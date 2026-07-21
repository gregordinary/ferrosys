# ferrosys-cli

The `ferrosys` command line: create an ext2, ext3, or ext4 filesystem, report on one, and
read one back. It runs in userspace as a single self-contained binary, in safe Rust, over
[`ferrosys`](https://crates.io/crates/ferrosys), and builds on Rust 1.88 or newer.

> **Status:** under active development. The command-line interface is not yet stable.
> Following Cargo's `0.x` semantics, a breaking change bumps the minor version.

```console
$ cargo install ferrosys-cli

$ ferrosys format --size 512M --uuid "$(uuidgen)" --time 1700000000 \
      --from-tar rootfs.tar rootfs.img
$ ferrosys inspect rootfs.img
$ ferrosys extract rootfs.img --to-tar - | tar -tv
```

## The three subcommands

- **`format`** writes a filesystem, from a tar archive or empty. The size, UUID, and
  timestamps are inputs; the tool reads neither the clock nor a random source, so the
  same inputs write the same image every time. Grow reservation, block size, inode
  count, reserved percentage, volume label, journal size, feature set, and directory
  hash are all options.
- **`inspect`** reports what a filesystem says about itself and whether it is sound —
  as a table a person reads, as JSON, or as SARIF for a pipeline that ingests findings.
  A full scan walks every group descriptor, bitmap, inode, and extent tree, collecting
  each deviation as a typed anomaly; `--fail-on` sets the severity at which the run
  fails.
- **`extract`** reads the contents back out: as a tar archive, as one file's bytes, or
  as a listing.

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
| `8`  | The command could not be carried out: the host got in the way, or the bytes are not an ext filesystem at all. |
| `16` | The command line could not be understood.                                   |

## Documentation

The guide's [command-line chapter](https://gregordinary.github.io/ferrosys/cli.html) covers
every subcommand and option.

## License

Licensed under either of Apache License, Version 2.0 or the MIT license, at your option.
