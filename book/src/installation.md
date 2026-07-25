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
ferrosys = "0.2"
```

The default build is pure Rust and depends only on `thiserror`. Three features
add to it, each off by default:

| Feature | What it adds | What it depends on |
|---|---|---|
| `tar` | `ArchiveSource` and `ArchiveSink`: a filesystem built from a tar stream, and one written back out as one, with PAX times, `SCHILY.xattr.*` attributes, and `SCHILY.acl.*` records | `tar` |
| `dir` | `DirectorySource`: a filesystem built from a directory tree on this machine, with its modes, ownership, times, hard links, special files, and extended attributes | `rustix` |
| `serde` | `Serialize` on the scan taxonomy, the planned geometry, and the feature model, for embedding them in a document of your own | `serde` |

```toml
[dependencies]
ferrosys = { version = "0.2", features = ["tar", "dir"] }
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
