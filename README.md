# ferrosys

Pure-Rust filesystem tooling: it builds and reads filesystem images in userspace, over
ordinary byte streams, in safe Rust. Four families — ext2/ext3/ext4, FAT12/FAT16/FAT32,
exFAT, and btrfs — and a build takes the ones it names.

This Cargo workspace holds two crates:

- [`ferrosys`](crates/ferrosys) — the library: a reader and a writer per family, each behind
  a feature of its own, with byte-reproducible on-disk geometry.
- [`ferrosys-cli`](crates/ferrosys-cli) — the `ferrosys` binary, which puts the library
  on the command line and carries all four families.

Both build on Rust 1.88 or newer.

> **Status:** under active development. Following Cargo's
> `0.x` semantics, a breaking change bumps the minor version, and a `0.x` requirement
> resolves only within that minor — so a breaking release reaches no one unasked.

## Highlights

- **Four families, one at a time or all of them** — ext2, ext3, and ext4 across one
  lineage, from the classic direct/indirect block map to extent trees of any depth; FAT12,
  FAT16, and FAT32 across another, where the type is derived from the cluster count rather
  than chosen; exFAT, which shares a name with FAT and no bytes, with an allocation bitmap
  of its own and names folded through the up-case table each volume carries; and btrfs, a
  copy-on-write filesystem of B-trees over a logical address space, where a chunk tree maps
  that space onto the device and every metadata block carries its own checksum — read in
  full, and written whole from a source tree, subvolumes included. Each is a feature, so a
  consumer wanting one filesystem compiles one.
- **Resize-safe ext geometry** — descriptor backups and reserved GDT blocks, sized by a
  grow reservation, let the image grow in place without relocating its descriptor table.
- **Byte-reproducible** — the identifiers and timestamps an image carries are inputs, so
  the same inputs write the same image every time and nothing about the machine that wrote
  one reaches it.
- **Full fidelity, and a report where a format cannot hold it** — ext records every file
  type, ownership and mode bits, nanosecond timestamps, extended attributes, POSIX ACLs,
  metadata checksums, a jbd2 journal, and an orphan file. Where a format holds less than
  the tree it is given, what it could not keep is named rather than dropped in silence.
- **A robust reader per family** — bounds-checks every field into typed errors, reads
  foreign images other tools wrote, and scans a whole image into typed findings rendered as
  JSON, SARIF, or a table, allocating in proportion to the bytes an image holds rather than
  to what it claims.
- **Built for scale** — streaming in both directions: a format writes only the blocks the
  filesystem uses, so an image stays sparse and may be larger than memory, and a read
  windows its way through a file rather than holding it, so pulling a multi-gigabyte file
  out of an image costs a working set. ext's 64-bit block addressing reaches past 16 TiB.
- **Sources and sinks, belonging to no family** — a programmatic tree, a tar archive, or a
  directory on this machine feeds whichever family is being written, and an archive or a
  directory drains whichever one was opened. Each hands a file's bytes over as a handle, so
  a format's peak memory is the largest single file rather than the sum of them all.

The [crate README](crates/ferrosys/README.md) and the
[guide](https://gregordinary.github.io/ferrosys/) carry the complete feature list.

## The command line

```console
$ cargo install --path crates/ferrosys-cli

$ ferrosys format --size 512M --uuid "$(uuidgen)" --time 1700000000 \
      --from-tar rootfs.tar rootfs.img
$ ferrosys inspect rootfs.img
$ ferrosys extract rootfs.img --to-tar - | tar -tv

$ ferrosys format --type fat32 --size auto --volume-id 1a2b3c4d --time 1700000000 \
      --owner 0:0 --accept-loss all --from-dir seed/ seed.img
```

`format` writes a filesystem — of the type `--type` names, from a tar archive, a directory
tree, or empty, at a size you name or, for the ext and FAT families, one `--size auto`
finds from the contents — `inspect` reports on one and says whether it is sound, `extract`
reads the contents back out as a tar archive, a directory tree, one file's bytes, one
path's metadata, or a listing, `detect` says which filesystem an image holds, and
`identity` re-stamps an existing ext filesystem with a new UUID, label, or checksum seed.
Every command that reads an image takes any family the binary carries; `identity` writes to
one family and says so. The identifiers and timestamps are inputs, so
the same inputs write the same image every time. The exit codes mirror `e2fsck`'s. See the
guide's
[command-line chapter](https://gregordinary.github.io/ferrosys/cli.html).

## Build and test

```sh
cargo build
cargo test
cargo doc --no-deps            # clean under RUSTDOCFLAGS="-D warnings"
ci/lint-features.sh            # and clean in every feature configuration on offer
```

## Documentation

The guide and the API reference are published together to GitHub Pages:

- **[The guide](https://gregordinary.github.io/ferrosys/)** — a narrative introduction,
  built with [mdbook](https://rust-lang.github.io/mdBook/) from [`book/`](book). Build it
  locally with `mdbook serve book` (or `mdbook build book`).
- **[The API reference](https://gregordinary.github.io/ferrosys/api/)** — rustdoc for the
  crate, generated by `cargo doc --no-deps`. The guide's code examples compile against the
  crate with `mdbook test book -L target/debug/deps`, so they stay in step with the API.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
