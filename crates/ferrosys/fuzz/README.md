# Fuzzing

libFuzzer targets over the two surfaces that read input this crate did not produce: an
image handed to a family's reader, and an archive handed to the tar source. Both assert
the same contract — every malformed input is a returned error, never a crash, an
out-of-range read, or an allocation sized from a number the input claims.

## Run

Requires a nightly toolchain and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run reader_scan corpus/reader_scan seeds/reader_scan
cargo +nightly fuzz run fat_reader corpus/fat_reader seeds/fat_reader
cargo +nightly fuzz run archive_parse corpus/archive_parse seeds/archive_parse
```

The first corpus directory is where libFuzzer writes what it learns, and it must be
`corpus/<target>`: libFuzzer treats the first directory it is given as its working
corpus and adds every interesting input it discovers there. The committed seeds come
second, so they are read as starting points and stay untouched — a run starts from real
filesystems and real archives rather than from random bytes.

Seeding matters for every target and is close to load-bearing for two of them. A tar
header carries a checksum over its own bytes, so random input almost never frames a single
member. A FAT volume carries no magic at all and is recognized by its whole parameter block
agreeing with itself — a sector size, a cluster size, a table size, and a sector count that
are jointly possible — which random bytes reach about as often. Without a real filesystem or
archive to mutate, either run would exercise the header check and nothing past it.

## Seeds

`seeds/<target>/` holds the starting inputs, one filesystem per file for the reader targets
and one tar archive per file for the archive target. Every one is small on purpose, so the
fuzzer mutates them quickly: the images are 2 to 16 MiB at a 1 KiB block size, and the
archive is a few members with short bodies. The images are almost entirely zeros, so the
repository stores them in on the order of a hundred kilobytes however many megabytes they
occupy once checked out.

- `ext4-min` — the smallest default filesystem, `metadata_csum` and `64bit` on.
- `ext4-nocsum` — the same without `metadata_csum`, which is a separate read path:
  no checksum tails, and directory blocks with no tail slot.
- `ext4-32bit` — neither `metadata_csum` nor `64bit`, so group descriptors are the
  32-byte form.
- `ext4-populated` — a tree with nested directories, a symlink, a hard link, an
  extended attribute, and a file large enough to need several blocks, so the walk,
  extent, and attribute parsers are all reachable.
- `ext4-multigroup` — two block groups, so descriptor iteration and the per-group
  bitmap and inode-table paths are exercised.
- `ext2-populated` — an ext2 tree (no journal, no extents, no checksums) with a nested
  directory, a symlink, and a file large enough to reach the single-indirect block, so
  the classic direct/indirect block map and its walk are represented rather than only
  the extent path. This is the block-mapped family's counterpart to `ext4-populated`.
- `fat12-populated`, `fat16-populated` — one tree at each of the two narrow entry widths.
  FAT12 packs three bytes to two entries, so an entry may straddle a sector boundary and
  the packing is a read path of its own. Each holds a name that is already its own short
  name, a lower-case one, two that shorten alike so the second takes a numeric tail, a file
  spanning several clusters, and one owning no cluster at all.
- `fat12-4k-sectors` — the same tree at a 4096-byte sector with one table rather than two,
  so the sector-size arithmetic and the single-table volume are both represented.
- `fat32-undersized` — the 32-bit entry width, on a volume below the cluster minimum FAT32
  defines. Every mainstream driver reads such a volume as FAT32 because a zero 16-bit table
  size is what they test before counting anything, so it reaches the whole FAT32 path — the
  information sector, the backup boot sector, the root as a cluster chain — at a fraction of
  the 33 MiB a conformant FAT32 needs.
- `inspect-huge-group-count` — `ext4-min` with `s_blocks_count` set to `2^64 - 1`,
  the crafted superblock the `reader_inspect` target exists to guard: the group count
  it implies must not size an allocation.
- `rootfs-pax.tar` — the archive seed: a PAX tarball carrying one of each shape the parser
  resolves, so a mutation lands somewhere that matters. A `g` global header, PAX timestamps
  and ownership, a binary `SCHILY.xattr.*` value whose NUL bytes are why records are
  length-delimited, a text `SCHILY.acl.*` record, a symlink, a hard link, a character
  device, a name past the header's 100-byte field, and a body spanning several blocks. It
  parses into a source that formats into an image `e2fsck` accepts, so a mutation starts
  from an archive that is sound end to end.

To regenerate the archive seed, run its generator; every field it writes is fixed, so the
result is byte-reproducible and a change in the file is a deliberate one.

```sh
python3 make-archive-seed.py seeds/archive_parse/rootfs-pax.tar
```

The generator lives beside this file rather than in `seeds/archive_parse/`, because
libFuzzer reads every file in a seed directory as an input.

To regenerate the images, format with the CLI and then craft the last one. `^has_journal`
keeps the images small; `orphan_file` and `metadata_csum_seed` depend on the features
being cleared, so they come off together.

```sh
u=f0e17055-0000-4000-8000-000000000000
off='^has_journal,^orphan_file'
common="--block-size 1024 --uuid $u --time 1700000000"
ferrosys format --size  2M $common -O "$off"                                 ext4-min.img
ferrosys format --size  2M $common -O "$off,^metadata_csum,^metadata_csum_seed"      ext4-nocsum.img
ferrosys format --size  2M $common -O "$off,^metadata_csum,^metadata_csum_seed,^64bit" ext4-32bit.img
ferrosys format --size  4M $common -O "$off" --from-tar tree.tar             ext4-populated.img
ferrosys format --size 16M $common -O "$off"                                 ext4-multigroup.img
# The block-mapped family: `-t ext2` selects the ext2 feature words directly, so the
# tree maps through the classic direct/indirect block map instead of an extent tree.
ferrosys format --size  4M $common -t ext2 --from-tar tree.tar               ext2-populated.img
# s_blocks_count_lo is at superblock offset 0x04 and _hi at 0x150.
python3 - <<'PY'
import shutil
shutil.copy("ext4-min.img", "inspect-huge-group-count.img")
with open("inspect-huge-group-count.img", "r+b") as f:
    for off in (0x04, 0x150):
        f.seek(1024 + off)
        f.write((0xFFFFFFFF).to_bytes(4, "little"))
PY
```

## Targets

- `reader_scan` — `Reader::open` and `open_with`, then `walk`, `verify_checksums`,
  `scan`, and every per-inode read the walk reaches, over the fuzzer's bytes.
- `fat_reader` — `Reader::open` and `open_with` over the FAT family, then `walk`,
  `verify_tables`, `info_sector`, `volume_label`, `chain`, and every per-node read the walk
  reaches, plus a lenient `scan` and its three rendered projections. Driven strictly at the
  start of the source, leniently for the scan, and once more with a code page named and a
  nonzero base offset — three configurations because they take different branches: a strict
  read stops at the first deviation, a scan follows every chain and every directory entry,
  and a named code page is what turns a short name's bytes into characters.
- `reader_inspect` — the `inspect` command's sequence: list every group descriptor
  (grown from the descriptors that exist, never pre-sized from the claimed count),
  scan, and render the report as JSON, as a table, and as SARIF. Guards the
  inspection path against a superblock that claims billions of groups.
- `archive_parse` — both tar entry points: `ArchiveSource::from_reader`, which reads
  every body, and `ArchiveSource::from_path`, which locates each body and leaves it on
  disk. The seeking one computes an offset from a declared size, and a PAX `size`
  record carries a full `u64`, so this is where an unrepresentable length would land.
  The fuzzer's bytes are written to a scratch file so the by-path parser is driven as a
  caller reaches it.

A deterministic subset of this — degenerate geometry, truncations, and bit-flips of
a valid image — also runs on stable as the `reader_never_panics_on_mangled_images`
unit test, its FAT counterpart as `the_reader_never_panics_on_mangled_images`, and the
archive one as `a_mangled_archive_never_panics`, so the never-panic contract is guarded on
every `cargo test`.

This package sets its own `[workspace]`, so the crate's build never compiles it and a
target could otherwise rot unnoticed. CI type-checks it on every run, and checks the seeds
too — every image still opens, the archive still parses and formats, and its generator
still reproduces it byte for byte — since a seed is the one part of this setup with no
compiler to catch its drift. The image half of that check is
`every_committed_fuzz_seed_still_opens_and_walks_without_naming_a_family` in
`tests/seam.rs`, which opens each one through `ferrosys::open` and walks it: written in the
crate's family-agnostic vocabulary, so one case covers every family's seeds.
