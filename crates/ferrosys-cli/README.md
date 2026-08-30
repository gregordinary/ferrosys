# ferrosys-cli

The `ferrosys` command line: create a filesystem, report on one, and read one back. One
binary carries four families:

- ext2, ext3, and ext4
- FAT12, FAT16, and FAT32
- exFAT
- btrfs

It creates and reads all four, subvolumes included. It runs in userspace as a single
self-contained binary, in safe Rust, over
[`ferrosys`](https://crates.io/crates/ferrosys). It builds on Rust 1.88 or newer.

> **Status:** ferrosys is under active development. The version numbers follow the `0.x`
> semantics of Cargo, so a breaking change increases the minor version.

```sh
cargo install ferrosys-cli

ferrosys format --size 512M --uuid "$(uuidgen)" --time 1700000000 \
    --from-tar rootfs.tar rootfs.img
ferrosys inspect rootfs.img
ferrosys extract rootfs.img --to-tar - | tar -tv
ferrosys detect rootfs.img          # prints: ext4

ferrosys format --type fat32 --size auto --volume-id 1a2b3c4d --time 1700000000 \
    --owner 0:0 --accept-loss all --from-dir seed/ seed.img
ferrosys format --type exfat --volume-serial 1234abcd --size 4G card.img
ferrosys format --type btrfs --size 2G --fsid "$(uuidgen)" --time 1700000000 \
    --subvol "$(uuidgen)":/@root --default-subvol /@root --from-dir staged/ root.img
ferrosys extract root.img --cat /@root/etc/hostname

ferrosys inspect fedora-root.img
ferrosys extract fedora-root.img --cat /etc/os-release
```

## The five subcommands

### `format`

`format` writes a filesystem of the type `--type` names: `ext2`, `ext3`, `ext4`, `fat12`,
`fat16`, `fat32`, `exfat`, or `btrfs`. The default is `ext4`. The source is a tar archive
(`--from-tar`), a directory tree on this machine (`--from-dir`, with `--owner UID:GID` to
override the host's ownership), or empty. You name the size, or for the ext and FAT
families you give `--size auto`, which finds it from the contents.

The size, the timestamps, and the family's own identity are inputs. The identity option is
`--uuid` for ext, `--volume-id` for a FAT volume, `--volume-serial` for an exFAT one, and
`--fsid` for a btrfs. The tool reads only what you give it, so the same inputs write the
same image every time.

Each family's geometry has its own options. ferrosys refuses an option that belongs to
another family, and names it. `--dry-run` reports the geometry without opening the
destination, and `--atomic` publishes the image only once it is whole.

Walking a tree records Linux inode metadata and Linux extended attributes, so
`--from-dir` runs on Linux. `--from-tar` reads an archive on any platform the binary
builds for.

### `inspect`

`inspect` reports what a filesystem says about itself and whether it is sound. The output
is a table a person reads, JSON, or SARIF for a pipeline that ingests findings.

A full scan walks every structure the family has, and collects each deviation as a typed
anomaly:

| Family | What a scan walks |
|---|---|
| ext | Group descriptors, bitmaps, inodes, and extent trees |
| FAT | Both allocation tables and every chain |
| exFAT | The allocation bitmap, the up-case table, and every entry set |
| btrfs | The chunk map, every tree, and every metadata block's checksum |

A btrfs report also lists the subvolumes and which of them is the default. `--fail-on`
sets the severity at which the run fails.

### `extract`

`extract` reads the contents back, in one of five forms:

- A tar archive
- A directory tree on this machine (`--to-dir`, the inverse of `--from-dir`)
- One file's bytes
- One path's full metadata (`--stat`, extended attributes and decoded ACLs included)
- A listing

A btrfs is read the same way, subvolumes included. A path crosses a subvolume boundary the
way it crosses a directory.

### `detect`

`detect` says which filesystem an image holds: one word, at an offset if asked.

### `identity`

`identity` changes what an existing ext filesystem is known by: its UUID, its volume
label, and the seed its metadata checksums derive from. It writes every superblock copy,
and the journal's own record of the UUID. It writes nothing until every check has passed.

## Streams and exit codes

The standard output carries exactly one artifact per run: a report, a listing, a tar
stream, or one file's bytes. Everything else goes to the standard error, so a pipe never
receives a summary line in place of an artifact.

The exit codes mirror the exit codes of `e2fsck`. The line between 4 and 8 is whether an
opinion about a filesystem could be formed at all:

| Code | Meaning |
| ---- | ------- |
| `0`  | The command did what it was asked, and any filesystem it read is sound. |
| `4`  | A filesystem was read, and it is bad. |
| `8`  | The command could not be carried out: the host got in the way, or the bytes are not a filesystem at all. |
| `16` | The command line could not be understood. |

## Documentation

The guide's [command-line chapter](https://gregordinary.github.io/ferrosys/cli.html) covers
every subcommand and option.

## License

<!-- prose-lint: off -- Rule 23 exempts legal boilerplate. -->

Licensed under either of Apache License, Version 2.0 or the MIT license, at your option.
