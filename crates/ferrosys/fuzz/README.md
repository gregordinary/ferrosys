# Reader fuzzing

A libFuzzer target that asserts the reader never panics on arbitrary input: every
malformed image is a returned error, never a crash or an out-of-range read.

## Run

Requires a nightly toolchain and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run reader_scan corpus/reader_scan seeds/reader_scan
```

The first corpus directory is where libFuzzer writes what it learns, and it must be
`corpus/<target>`: libFuzzer treats the first directory it is given as its working
corpus and adds every interesting input it discovers there. The committed seeds come
second, so they are read as starting points and stay untouched — a run starts from
real filesystems rather than from random bytes.

## Seeds

`seeds/<target>/` holds the starting inputs, one filesystem per file. They are small
on purpose — 2 to 16 MiB at a 1 KiB block size, almost entirely zeros — so the
repository carries a few tens of kilobytes and the fuzzer mutates them quickly.

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
- `inspect-huge-group-count` — `ext4-min` with `s_blocks_count` set to `2^64 - 1`,
  the crafted superblock the `reader_inspect` target exists to guard: the group count
  it implies must not size an allocation.

To regenerate them, format with the CLI and then craft the last one. `^has_journal`
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

- `reader_scan` — `Reader::open` and `open_at`, then `walk`, `verify_checksums`,
  and `scan` over the fuzzer's bytes.
- `reader_inspect` — the `inspect` command's sequence: list every group descriptor
  (grown from the descriptors that exist, never pre-sized from the claimed count),
  scan, and render the report as JSON, as a table, and as SARIF. Guards the
  inspection path against a superblock that claims billions of groups.

A deterministic subset of this — degenerate geometry, truncations, and bit-flips of
a valid image — also runs on stable as the `reader_never_panics_on_mangled_images`
unit test, so the never-panic contract is guarded on every `cargo test`.

This package sets its own `[workspace]`, so the crate's build never compiles it and a
target could otherwise rot unnoticed. CI type-checks it on every run.
