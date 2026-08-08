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
ferrosys = "0.4"
```

The build is pure Rust and depends only on `thiserror`. Five features shape it, and the
first two are the filesystem families — a build takes the families it names, so a consumer
that wants an ext image compiles no FAT code:

| Feature | Default | What it adds | What it depends on |
|---|---|---|---|
| `ext` | on | The ext2/ext3/ext4 family, under the `ext` module: the formatter, the reader, the feature model, and the on-disk structures | — |
| `fat` | off | The FAT12/FAT16/FAT32 family, under the `fat` module: the formatter, the reader, the geometry planner, the on-disk structures, and the classifier that recognizes a FAT volume | — |
| `tar` | off | `ArchiveSource` and `ArchiveSink`: a filesystem built from a tar stream, and one written back out as one, with PAX times, `SCHILY.xattr.*` attributes, and `SCHILY.acl.*` records | `tar` |
| `dir` | off | `DirectorySource` and `DirectorySink`: a filesystem built from a directory tree on this machine, and one written back out as a tree, with modes, ownership, times, hard links, special files, and extended attributes. Built on Linux, whose metadata and extended attributes both ends read and write | `rustix` |
| `serde` | off | `Serialize` on the findings taxonomy, each family's planned geometry, and the ext feature model, for embedding them in a document of your own | `serde` |

Granularity is per family rather than per format: `ext` is ext2, ext3, and ext4 together,
and `fat` is FAT12, FAT16, and FAT32 together, since each set is one lineage sharing its
on-disk structures.

`default-features = false` is a real build, not a smaller version of the same one: it
leaves the family-agnostic substrate the crate root carries — the `crc32c` primitive, the
source and extraction vocabulary, and `detect`, which says which filesystem an image holds
— and no family code at all, so `detect` then recognizes nothing. It is the build a
consumer starts from when it wants one family and not the other. None of `tar`, `dir`, or
`serde` names a family: a source feeds whichever family is being written and a sink drains
whichever one was opened, so `--features fat,dir` builds a FAT volume from a directory tree
on this machine and extracts one back, with no ext code compiled.

Cargo unifies features across a dependency graph, so naming a subset is a property of a
leaf application rather than of a library deep in someone's tree: anything else in the
build that pulls this crate with a family turns that family on for everyone in it —
including the answers `detect` then gives.

```toml
[dependencies]
ferrosys = { version = "0.4", features = ["tar", "dir"] }
```

The [API reference](./api-reference.md) documents the public surface.

## The command line

The `ferrosys` binary writes, inspects, and reads back filesystems without
writing any Rust. Install it from the registry:

```sh
cargo install ferrosys-cli
```

or from a checkout of the workspace:

```sh
cargo install --path crates/ferrosys-cli
```

It writes to a regular file, takes its identifiers and timestamps as inputs, and
exits as `e2fsck` does. The [command-line chapter](./cli.md) covers it.
