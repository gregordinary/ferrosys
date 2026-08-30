# ferrosys

ferrosys is pure-Rust filesystem tooling. It builds and reads filesystem images in
userspace, over ordinary byte streams, in safe Rust. It has four filesystem families:

- ext2, ext3, and ext4
- FAT12, FAT16, and FAT32
- exFAT
- btrfs

Each family is a Cargo feature, so a build takes only the families you name.

This Cargo workspace has two crates:

- [`ferrosys`](crates/ferrosys) is the library. It has a reader and a writer per family,
  each behind a feature of its own, with byte-reproducible on-disk geometry.
- [`ferrosys-cli`](crates/ferrosys-cli) is the `ferrosys` binary. It puts the library on
  the command line and carries all four families.

Both crates build on Rust 1.88 or newer.

> **Status:** ferrosys is under active development. The version numbers follow the `0.x`
> semantics of Cargo. A breaking change increases the minor version, and a `0.x`
> requirement resolves only within that minor. A breaking release reaches only the users
> who ask for it.

## Capabilities

### Filesystem families

Each family is a separate on-disk format with a reader and a writer of its own:

- **ext2, ext3, ext4.** One lineage, from the classic direct/indirect block map to
  extent trees of any depth.
- **FAT12, FAT16, FAT32.** One lineage, where the cluster count derives the type.
- **exFAT.** A separate format that shares only the name. It carries an allocation
  bitmap of its own, and each volume carries an up-case table that the reader folds
  names through.
- **btrfs.** A copy-on-write filesystem of B-trees over a logical address space. A chunk
  tree maps that space onto the device, and every metadata block carries its own
  checksum. ferrosys reads a btrfs volume in full, and writes one whole from a source
  tree with its subvolumes.

### Resize-safe ext geometry

The ext writer places descriptor backups and reserved GDT blocks, sized by a grow
reservation. The image grows in place, and its descriptor table stays where it is.

### Byte-reproducible images

The identifiers and timestamps an image carries are inputs. The writer produces the same
image from the same inputs, every time, and puts only those inputs into it.

The guarantee holds for one ferrosys version. Across versions it holds where the on-disk
feature set is pinned. `ext::FeatureSet::DEFAULT` is frozen, and `ext::FeatureSet::LATEST`
tracks current `mke2fs` and moves between releases by design.

### Fidelity and accepted loss

ext records the whole of a source tree:

- Every file type, with ownership and mode bits
- Nanosecond timestamps
- Extended attributes and POSIX ACLs
- Metadata checksums, a jbd2 journal, and an orphan file

If a format holds less than the tree you give it, ferrosys names each property it cannot
keep.

### Reader robustness

The reader bounds-checks every field into a typed error, and reads foreign images other
tools wrote. It also scans a whole image into typed findings, rendered as JSON, SARIF, or
a table.

A scan allocates in proportion to the bytes an image holds, not to the count the image
declares.

### Streaming and sparse images

ferrosys streams in both directions. A format writes only the blocks the filesystem uses,
so an image stays sparse and can be larger than memory. The reader moves a window through
a file rather than holding it, so a multi-gigabyte extraction costs one working set.

The 64-bit block addressing of ext reaches past 16 TiB.

### Sources and sinks

A source and a sink belong to no family. A programmatic tree, a tar archive, or a
directory on this machine feeds any family the writer makes. An archive or a directory
receives any family the reader opens.

Each passes a file's bytes as a handle. The peak memory of a format is the largest
single file, not the sum of them all.

The [crate README](crates/ferrosys/README.md) and the
[guide](https://gregordinary.github.io/ferrosys/) carry the complete feature list.

## The command line

Install the binary:

```sh
cargo install --path crates/ferrosys-cli
```

Write an ext4 image from a tar archive, inspect it, and read it back:

```sh
ferrosys format --size 512M --uuid "$(uuidgen)" --time 1700000000 \
    --from-tar rootfs.tar rootfs.img
ferrosys inspect rootfs.img
ferrosys extract rootfs.img --to-tar - | tar -tv
```

Write a FAT32 image and an exFAT image:

```sh
ferrosys format --type fat32 --size auto --volume-id 1a2b3c4d --time 1700000000 \
    --owner 0:0 --accept-loss all --from-dir seed/ seed.img
ferrosys format --type exfat --volume-serial 1234abcd --size 4G card.img
```

Write a btrfs image with a subvolume, and read one file out of it:

```sh
ferrosys format --type btrfs --size 2G --fsid "$(uuidgen)" --time 1700000000 \
    --subvol "$(uuidgen)":/@root --default-subvol /@root --from-dir staged/ root.img
ferrosys extract root.img --cat /@root/etc/hostname
```

| Command | What it does |
|---|---|
| `format` | Writes a filesystem of the type `--type` names, from a tar archive, a directory tree, or empty. |
| `inspect` | Reports on a filesystem and says whether it is sound. |
| `extract` | Reads the contents back as a tar archive, a directory tree, one file's bytes, one path's metadata, or a listing. |
| `detect` | Says which filesystem an image holds. |
| `identity` | Re-stamps an ext filesystem with a new UUID, label, or checksum seed. |

You name the size with `--size`. For the ext and FAT families, `--size auto` finds it
from the contents. Every command that reads an image takes any family the binary carries.
`identity` writes to one family and says so. The exit codes mirror the exit codes of
`e2fsck`.

The [command-line chapter](https://gregordinary.github.io/ferrosys/cli.html) of the guide
covers every option.

## Build and test

```sh
cargo build
cargo test
cargo doc --no-deps            # clean under RUSTDOCFLAGS="-D warnings"
ci/lint-features.sh            # and in every feature configuration
```

## Documentation

The guide and the API reference go to GitHub Pages together:

- **[The guide](https://gregordinary.github.io/ferrosys/)** is a narrative introduction,
  built with [mdbook](https://rust-lang.github.io/mdBook/) from [`book/`](book). Build it
  locally with `mdbook serve book` or `mdbook build book`.
- **[The API reference](https://gregordinary.github.io/ferrosys/api/)** is rustdoc for
  the crate. `cargo doc --no-deps` generates it. The command
  `mdbook test book -L target/debug/deps` compiles the guide's code examples against the
  crate, so the examples and the API agree.

## License

<!-- prose-lint: off -- Rule 23 exempts legal boilerplate. -->

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
