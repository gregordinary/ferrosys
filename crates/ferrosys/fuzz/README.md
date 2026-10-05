# Fuzzing

libFuzzer targets over the two surfaces that read input this crate did not produce: an
image handed to a family's reader, and an archive handed to the tar source. Both assert
the same contract — every malformed input is a returned error, never a crash, an
out-of-range read, or an allocation sized from a number the input claims.

## Run

Requires a nightly toolchain and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz
limits='-malloc_limit_mb=2048 -rss_limit_mb=8192'
cargo +nightly fuzz run reader_scan corpus/reader_scan seeds/reader_scan \
    -- -max_len=16777216 $limits
cargo +nightly fuzz run fat_reader corpus/fat_reader seeds/fat_reader \
    -- -max_len=16777216 $limits
cargo +nightly fuzz run exfat_reader corpus/exfat_reader seeds/exfat_reader \
    -- -max_len=8388608 $limits
cargo +nightly fuzz run btrfs_reader corpus/btrfs_reader seeds/btrfs_reader \
    -- -max_len=83886080 -malloc_limit_mb=2048 -rss_limit_mb=24576
cargo +nightly fuzz run archive_parse corpus/archive_parse seeds/archive_parse
```

`-max_len` is the largest seed in the target's directory, and it is not optional. Without
it libFuzzer caps an input at 1 MiB and truncates every seed to that when it loads them, so
an exFAT seed loses its whole cluster heap — which begins past the first MiB — and a btrfs
seed loses every tree. The fuzzer then mutates boot sectors and superblocks and never
reaches a directory. A seed added larger than the figure here raises it.

The two memory limits answer different questions. libFuzzer holds its whole corpus in
memory, so with inputs of megabytes its resident size passes the default 2 GiB on its own
within minutes, and reports that as the input's fault. `-rss_limit_mb` is raised to hold
that corpus. `-malloc_limit_mb` stays at 2 GiB, so a single allocation sized from a number
the input claims, which is the bug these targets exist to find, still fails the run.

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
fuzzer mutates them quickly: the ext images are 2 to 16 MiB at a 1 KiB block size, the FAT
and exFAT ones 2 to 16 MiB, the btrfs ones 48 to 80 MiB, and the archive
a few members with short bodies. The images are almost entirely zeros, so the
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
- `ext4-needs-recovery` — a 4 MiB filesystem left needing recovery: its journal carries three
  checksummed transactions written by `debugfs`, the last revoking a block the first logged,
  so reading it replays the log before anything else. The journal superblock, the tags, the
  revoke records, and the commit checksums are all reachable from the first input.
- `ext4-kernel-htree` — a directory with a two-level hash index that a Linux kernel grew a
  name at a time: 600 names of 200 bytes linked into an 8 MiB ext4 at 1 KiB blocks, every
  fifth removed, a run of names sharing one hash split across leaves, and names at the end of
  the hash space. It is the test suite's `ext4-kernel-htree` fixture expanded, and the one
  seed from which a lookup descends an index rather than reading a directory whole.
- `ext4-meta-bg` — `meta_bg` with 256-block groups, so an 8 MiB filesystem has 33 groups
  across three meta-groups, each meta-group's descriptor block in its own first group. Made
  by the pinned `mke2fs` from a small tree, since this crate does not write `meta_bg`.
- `ext4-unclean` — a 4 MiB ext4 without a journal that a Linux kernel had mounted, written
  to, and not unmounted, so its state word records the unclean shutdown. It is the test
  suite's `ext4-kernel-unclean` fixture expanded.
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
- `fat16-dirty` — a 16 MiB FAT16 a Linux kernel had mounted, written to, and not unmounted,
  so its boot sector carries the mark a Linux driver records that in. The test suite's
  `fat16-kernel-unclean` fixture expanded.
- `fat12-long-dir` — 200 files with long names in one directory, which spans several
  clusters, so a lookup that stops at its name and a listing that reads to the end take
  different paths through it.
- `exfat-populated`, `exfat-chained`, `exfat-512b-clusters` — a tree on an 8 MiB exFAT at
  4 KiB clusters, the same with its streams chained through the allocation table rather
  than contiguous, and the tree again at 512-byte clusters.
- `exfat-empty` — a 4 MiB exFAT holding nothing but its root, bitmap, and up-case table.
- `exfat-dirty` — an 8 MiB exFAT a Linux kernel had mounted, written to, and not unmounted,
  with `VolumeDirty` set. The test suite's `exfat-kernel-unclean` fixture expanded.
- `exfat-long-dir` — the 200 long names of `fat12-long-dir` on an 8 MiB exFAT.
- `btrfs-min` — an empty btrfs, every tree present and none holding a file.
- `btrfs-populated` — a btrfs holding a tree, with a default subvolume.
- `btrfs-4k-node` — a tree on a btrfs whose tree blocks are 4 KiB rather than 16 KiB, so a
  leaf holds a quarter as much and the trees are deeper for the same items.
- `btrfs-damaged-copy` — a btrfs with `dup` metadata whose root tree's first copy has its
  checksum damaged: a lenient read takes the second copy and a scan names the block, so the
  read-through to a later copy is reachable from the first input. Made with
  `mkfs.btrfs -m dup -d single -r` over a small tree, the copy located with
  `btrfs-map-logical`. The pinned `mkfs.btrfs` makes such a filesystem no smaller than
  114 MiB, and the file ends at 80 MiB, past the last block the filesystem uses: every
  seed stays under the 100 MB a repository host accepts in one file, and the seed gate
  holds them to it.
- `inspect-huge-group-count` — `ext4-min` claiming as many block groups as its 32-bit
  inode total can count, sixteen million of them, with `s_blocks_count` and
  `s_inodes_count` both agreeing with that many: the crafted superblock the
  `reader_inspect` target exists to guard. It opens, and the group count it implies must
  not size an allocation.
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
# The most groups a 32-bit inode total counts, with the block and inode totals agreeing
# with them, since a superblock whose totals disagree with its group count is refused at
# open. s_inodes_count is at superblock offset 0x00, s_first_data_block at 0x14,
# s_blocks_per_group at 0x20, s_inodes_per_group at 0x28, s_blocks_count_lo at 0x04 and
# _hi at 0x150.
python3 - <<'PY'
import shutil, struct
shutil.copy("ext4-min.img", "inspect-huge-group-count.img")
with open("inspect-huge-group-count.img", "r+b") as f:
    f.seek(1024)
    sb = bytearray(f.read(1024))
    first, per_group, inodes = (struct.unpack_from("<I", sb, o)[0] for o in (0x14, 0x20, 0x28))
    groups = 0xFFFFFFFF // inodes
    blocks = groups * per_group + first
    struct.pack_into("<I", sb, 0x00, groups * inodes)
    struct.pack_into("<I", sb, 0x04, blocks & 0xFFFFFFFF)
    struct.pack_into("<I", sb, 0x150, blocks >> 32)
    f.seek(1024)
    f.write(sb)
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
- `exfat_reader` — the same over the exFAT family: a strict walk and a lookup of every path
  it reaches, a lenient scan and its projections, and a second open at a nonzero base offset.
- `btrfs_reader` — the address space and the trees through `Volume`, then the filesystem
  view through `Reader`: a walk, a lookup and a read of every file it reaches, a
  verification of each file's data checksums, and a scan.
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
