# Installation

Both crates build on Rust 1.88 or newer.

## The library

`ferrosys` is a Rust library. Add it to a project with:

```sh
cargo add ferrosys
```

or by editing `Cargo.toml`:

```toml
[dependencies]
ferrosys = "0.6"
```

The build is pure Rust. Features shape it, and the first four are the filesystem
families. The default build carries all four and the three decoders, so it reads what a
Linux kernel mounts, a compressed btrfs root included. It depends on `thiserror`,
`miniz_oxide`, and `ruzstd`. A build that names its own features takes only the families it
names. A consumer that wants an ext image alone compiles no FAT code:

| Feature | Default | What it adds | What it depends on |
|---|---|---|---|
| `ext` | on | The ext2/ext3/ext4 family, under the `ext` module: the formatter, the reader, the feature model, and the on-disk structures | — |
| `fat` | on | The FAT12/FAT16/FAT32 family, under the `fat` module: the formatter, the reader, the geometry planner, the on-disk structures, and the classifier that recognizes a FAT volume | — |
| `exfat` | on | The exFAT family, under the `exfat` module: the formatter, the reader, the planner, the on-disk structures, and the classifier | — |
| `btrfs` | on | The btrfs family, under the `btrfs` module: the reader over its two layers, the formatter, the B-tree engine, the chunk map, and the on-disk structures | — |
| `zlib` | on | Reading a file whose extents are stored as DEFLATE | `miniz_oxide` |
| `lzo` | on | Reading a file whose extents are stored as LZO1X | — |
| `zstd` | on | Reading a file whose extents are stored as Zstandard | `ruzstd` |
| `tar` | off | `ArchiveSource` and `ArchiveSink`: a filesystem built from a tar stream, and one written back out as one, with PAX times, `SCHILY.xattr.*` attributes, and `SCHILY.acl.*` records | `tar` |
| `dir` | off | `DirectorySource` and `DirectorySink`: a filesystem built from a directory tree on this machine, and one written back out as a tree, with modes, ownership, times, hard links, special files, and extended attributes. Built on Linux, whose metadata and extended attributes both ends read and write | `rustix` |
| `serde` | off | `Serialize` on the findings taxonomy, each family's planned geometry, and the ext feature model, for embedding them in a document of your own | `serde` |

Granularity is per family rather than per format. `ext` is ext2, ext3, and ext4 together,
and `fat` is FAT12, FAT16, and FAT32 together. Each set is one lineage that shares its
on-disk structures.

The three decoders are named for the algorithm, not for a family. An encoding is a
property of a run of bytes, not of the format around it. Of the families here, btrfs is the
one that stores runs that way. A build that names its own features and wants to read them
names a decoder beside it: `--features btrfs,zstd`.

Each decoder decides what a *file* does when it is read. A build lacking the decoder for
the algorithm a file was stored with declines that file by name. A build lacking a decoder
for an algorithm the filesystem *advertises in its feature word* declines the filesystem
itself.

Verification is a separate question and needs none of them. The checksums a filesystem
records cover the bytes it stored, so ferrosys checks them whether or not those bytes can
be expanded.

`default-features = false` is a real build, not a smaller version of the same one. It
leaves the family-agnostic substrate the crate root carries. That is the `crc32c`
primitive, the source and extraction vocabulary, and `detect`, which says which filesystem
an image holds. It leaves no family code at all, so `detect` then recognizes nothing, and
it depends on `thiserror` alone. It is the build a consumer starts from when it wants some
families and not the others:

```toml
[dependencies]
ferrosys = { version = "0.6", default-features = false, features = ["ext", "tar"] }
```

None of `tar`, `dir`, or `serde` names a family. A source feeds whichever family the writer
makes, and a sink takes whichever one the reader opened. So `--no-default-features
--features fat,dir` builds a FAT volume from a directory tree on this machine and extracts
one back, with no ext code compiled.

Cargo unifies features across a dependency graph. Naming a subset is therefore a property
of a leaf application, not of a library deep in someone's tree. Anything in the build that
pulls this crate with a family turns that family on for everyone in it. That includes the
answers `detect` then gives. A library depending on this crate therefore turns the default
off and names what it reads. Otherwise it turns all four families on for every build it
joins.

```toml
[dependencies]
ferrosys = { version = "0.6", features = ["tar", "dir"] }
```

The [API reference](./api-reference.md) documents the public surface.

## The command line

The `ferrosys` binary writes, inspects, and reads back filesystems from a shell prompt.
Install it from the registry:

```sh
cargo install ferrosys-cli
```

or from a checkout of the workspace:

```sh
cargo install --path crates/ferrosys-cli
```

It writes to a regular file, takes its identifiers and timestamps as inputs, and
exits as `e2fsck` does. The [command-line chapter](./cli.md) covers it.
