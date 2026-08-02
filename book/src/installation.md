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
ferrosys = "0.3"
```

The build is pure Rust and depends only on `thiserror`. Four features shape it:

| Feature | Default | What it adds | What it depends on |
|---|---|---|---|
| `ext` | on | The whole filesystem surface, under the `ext` module: the formatter, the reader, the feature model, and the on-disk structures | — |
| `tar` | off | `ArchiveSource` and `ArchiveSink`: a filesystem built from a tar stream, and one written back out as one, with PAX times, `SCHILY.xattr.*` attributes, and `SCHILY.acl.*` records | `tar` |
| `dir` | off | `DirectorySource`: a filesystem built from a directory tree on this machine, with its modes, ownership, times, hard links, special files, and extended attributes. Built on Linux, whose metadata and extended attributes the walk reads | `rustix` |
| `serde` | off | `Serialize` on the scan taxonomy, the planned geometry, and the feature model, for embedding them in a document of your own | `serde` |

`default-features = false` is a real build, not a smaller version of the same one: it
leaves the family-agnostic substrate the crate root carries — the `crc32c` primitive and
`detect`, which says which filesystem an image holds — and no formatter, reader, or
`FeatureSet`. It is the build for a consumer that classifies images without reading them.
Each of the three optional features enables `ext`, since each is a way of describing or
emitting an ext filesystem.

```toml
[dependencies]
ferrosys = { version = "0.3", features = ["tar", "dir"] }
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
