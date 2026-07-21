# ferrosys

`ferrosys` builds and reads ext2, ext3, and ext4 filesystem images entirely in userspace,
over ordinary byte streams, in safe Rust (`#![forbid(unsafe_code)]`). It is self-contained,
pure Rust and runs anywhere Rust runs.

A formatter writes an image from a description of its contents — directories,
files, symlinks, hard links, device / FIFO / socket nodes, extended attributes,
and POSIX ACLs, each with its ownership, modes, and access / change / modification
times — and a reader parses an image back. The contents come from a programmatic
builder or, with the `tar` feature, from a tar archive and its PAX metadata. The
image carries real superblock and descriptor backups and reserved descriptor
blocks sized to a grow target — a maximum the caller names, or every block the
format can reserve when the caller names none — so the filesystem grows in place
without relocating its descriptor table, and every metadata object carries a
crc32c (`metadata_csum`) so a checker detects corruption of the filesystem's own
structures. A format-time jbd2 journal (`has_journal`), sized from the filesystem,
is written into the journal inode so the kernel journals from the first mount, and
the inodes awaiting deletion are recorded in an orphan file (`orphan_file`). Files
map their blocks with extent trees of any depth, and a directory that outgrows one
block gains a hash index (`dir_index`).

It is at once:

- **a Rust library** you link and call in process;
- **rootless and kernel-free** — it works the image as ordinary data and runs
  unprivileged;
- **cross-platform** — pure Rust, so it builds and reads ext2/3/4 images on
  Linux, macOS, Windows, and the BSDs;
- **deterministic** — the default output is byte-reproducible: the filesystem
  UUID and timestamps are inputs the caller supplies, and names hash the same way
  whatever machine builds the image;
- **resize-safe** in the on-disk geometry it writes;
- **unbounded by memory** — `format_to` streams an image to a seekable
  destination, writing only the blocks the filesystem uses.

## This guide

- [Safe by construction](./design/safety.md), [Deterministic
  output](./design/determinism.md), [Rootless and
  cross-platform](./design/rootless.md), and [Resize-safe
  geometry](./design/resize-safe.md) describe the guarantees the crate is built
  around.
- [Installation](./installation.md) shows how to add the crate to a project, and
  [Formatting and reading images](./formatting.md) walks through the API.
- The [API reference](./api-reference.md) documents every public item.
