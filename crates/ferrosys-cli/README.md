# ferrosys-cli

The `ferrosys` command line: create a filesystem, report on one, and read one back. Four
families — ext2/ext3/ext4, FAT12/FAT16/FAT32, exFAT, and btrfs — and one binary that carries
all of them. It creates and reads all four, subvolumes included. It runs in userspace as a
single self-contained binary, in safe Rust, over
[`ferrosys`](https://crates.io/crates/ferrosys), and builds on Rust 1.88 or newer.

> **Status:** under active development. Following Cargo's `0.x` semantics, a breaking
> change bumps the minor version.

```console
$ cargo install ferrosys-cli

$ ferrosys format --size 512M --uuid "$(uuidgen)" --time 1700000000 \
      --from-tar rootfs.tar rootfs.img
$ ferrosys inspect rootfs.img
$ ferrosys extract rootfs.img --to-tar - | tar -tv
$ ferrosys detect rootfs.img
ext4

$ ferrosys format --type fat32 --size auto --volume-id 1a2b3c4d --time 1700000000 \
      --owner 0:0 --accept-loss all --from-dir seed/ seed.img
$ ferrosys format --type exfat --volume-serial 1234abcd --size 4G card.img
$ ferrosys format --type btrfs --size 2G --fsid "$(uuidgen)" --time 1700000000 \
      --subvol "$(uuidgen)":/@root --default-subvol /@root --from-dir staged/ root.img
$ ferrosys extract root.img --cat /@root/etc/hostname

$ ferrosys inspect fedora-root.img
$ ferrosys extract fedora-root.img --cat /etc/os-release
```

## The five subcommands

- **`format`** writes a filesystem of the type `--type` names — `ext2`, `ext3`, `ext4`,
  `fat12`, `fat16`, `fat32`, `exfat`, or `btrfs`, defaulting to `ext4` — from a tar archive
  (`--from-tar`), from a directory tree on this machine (`--from-dir`, with `--owner
  UID:GID` to override the host's ownership), or empty, at a size you name or, for the ext
  and FAT families, one `--size auto` finds from the contents. The size, the timestamps, and
  the family's own identity are inputs — `--uuid` for ext, `--volume-id` for a FAT volume,
  `--volume-serial` for an exFAT one, `--fsid` for a btrfs — and the tool reads neither the
  clock nor a random source, so the same inputs write the same image every time. Each family's geometry has its own options, and
  an option belonging to another family is refused by name rather than ignored. `--dry-run`
  reports the geometry without opening the destination, and `--atomic` publishes the image
  only once it is whole. Walking a tree records Linux inode metadata and Linux extended
  attributes, so `--from-dir` is carried out on Linux; `--from-tar` reads an archive on any
  platform the binary builds for.
- **`inspect`** reports what a filesystem says about itself and whether it is sound —
  as a table a person reads, as JSON, or as SARIF for a pipeline that ingests findings.
  A full scan walks every structure the family has, collecting each deviation as a typed
  anomaly: group descriptors, bitmaps, inodes, and extent trees for ext; both allocation
  tables and every chain for FAT; the allocation bitmap, the up-case table, and every entry
  set for exFAT; the chunk map, every tree, and every metadata block's checksum for btrfs,
  whose report also lists the subvolumes and which of them is the default. `--fail-on` sets
  the severity at which the run fails.
- **`extract`** reads the contents back out: as a tar archive, as a directory tree on this
  machine (`--to-dir`, the inverse of `--from-dir`), as one file's bytes, as one path's
  full metadata (`--stat`, extended attributes and decoded ACLs included), or as a
  listing. A btrfs is read the same way, subvolumes included: a path crosses a subvolume
  boundary the way it crosses a directory.
- **`detect`** says which filesystem an image holds — one word, at an offset if asked.
- **`identity`** changes what an existing ext filesystem is known by: its UUID, its volume
  label, and the seed its metadata checksums derive from. Every superblock copy is written,
  along with the journal's own record of the UUID, and nothing at all is until every check
  has passed.

## Streams and exit codes

The standard output carries exactly one artifact per run — a report, a listing, a tar
stream, or one file's bytes. Everything else goes to the standard error, so a pipe never
receives a summary line where an artifact should have been.

The exit codes mirror `e2fsck`'s, and the line between 4 and 8 is whether an opinion
about a filesystem could be formed at all:

| Code | Meaning                                                                    |
| ---- | -------------------------------------------------------------------------- |
| `0`  | The command did what it was asked, and any filesystem it read is sound.     |
| `4`  | A filesystem was read, and it is bad.                                       |
| `8`  | The command could not be carried out: the host got in the way, or the bytes are not a filesystem at all. |
| `16` | The command line could not be understood.                                   |

## Documentation

The guide's [command-line chapter](https://gregordinary.github.io/ferrosys/cli.html) covers
every subcommand and option.

## License

Licensed under either of Apache License, Version 2.0 or the MIT license, at your option.
