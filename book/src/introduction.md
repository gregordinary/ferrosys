# ferrosys

`ferrosys` builds and reads ext2, ext3, and ext4 filesystem images entirely in userspace,
over ordinary byte streams, in safe Rust (`#![forbid(unsafe_code)]`). It is self-contained,
pure Rust and runs anywhere Rust runs.

It also writes and reads FAT12, FAT16, and FAT32 volumes, behind the off-by-default `fat`
feature — the family the EFI System Partition is, and the one the rest of this page's
guarantees read differently against, since it has no field for a permission bit, an owner,
or a link. Which of the three a volume is follows from its cluster count and from nothing
else, so the geometry is the format's real contract; the output is byte-reproducible on
the same terms as the ext writer's, and the reader is held to the same never-panic contract
on any input.

It also writes and reads exFAT volumes, behind the off-by-default `exfat` feature — the
interchange format for large removable media, the one SDXC cards specify, and the one every
current desktop operating system reads as it ships. exFAT shares a name with FAT and no
bytes: a different boot region, a different directory entry format, a different name
encoding, and an allocation bitmap FAT has no concept of, so it is a family of its own
behind a feature of its own. Its output is byte-reproducible on the same terms as the other
two writers', and it costs one input to be so — the volume serial number, since an empty
exFAT volume records no time at all. Its reader is held to the same never-panic contract on
any input, and it folds names through the up-case table the *volume* carries rather than
through one of its own, so a lookup resolves what a driver reading the same volume
resolves.

It also writes and reads btrfs, behind the off-by-default `btrfs` feature — the default root
filesystem on Fedora and openSUSE, and the one image-based Linux tooling increasingly assumes.
Reading covers both layers the format has: the superblock and every copy of it the device holds,
the chunk tree that maps a logical address onto the device, any of the filesystem's B-trees
searched by the key tuple with every block's checksum verified as it is read — and, on top of
those, the filesystem itself. Paths resolve across subvolume boundaries, a file's bytes come
back whatever shape its extents take, and `verify_data` holds those bytes against the checksums
the filesystem recorded for them, which is a check no other family here can make. Every address
in a btrfs is logical and one map translates all of them, which is the structural difference
from the three families above and the reason this one has a layer they do not.

Writing puts a source tree into a complete btrfs: ten trees and one more per subvolume, every
block checksummed, a crc32c beside every sector of file data, every allocated block recorded in
the extent tree with the tree that owns it, and every superblock copy the device has room for.
A caller names which of the source's directories become subvolumes, and which subvolume a mount
that names none lands in. It goes down in one transaction and nothing is ever rewritten, which
is what lets the whole layout be decided before a byte is placed — and it is byte-reproducible
on the same terms as the other three writers', costing five inputs to be so. btrfs has a field
for every property a source states, so this is the one family here whose fidelity report is
empty in both directions. [Reading a btrfs](./formatting.md#reading-a-btrfs) and
[writing one](./formatting.md#writing-one) are the two halves.

The rest of this page is the ext family.

A formatter writes an image from a description of its contents — directories,
files, symlinks, hard links, device / FIFO / socket nodes, extended attributes,
and POSIX ACLs, each with its ownership, modes, and access / change / modification
times — and a reader parses an image back. The contents come from a programmatic
builder, from a tar archive and its PAX metadata (the `tar` feature), or from a
directory tree on the machine doing the building (the `dir` feature). The
image carries real superblock and descriptor backups and reserved descriptor
blocks sized to a grow target — a maximum the caller names, or as much headroom
as a sixty-fourth of the filesystem buys when the caller names none — so the
filesystem grows in place
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
  UUID, the directory-hash seed, and timestamps are inputs the caller supplies, so
  names hash the same way whatever machine builds the image. Each family names its
  own such inputs, and [Deterministic output](./design/determinism.md) lists all
  three sets;
- **resize-safe** in the on-disk geometry it writes;
- **unbounded by memory** — `format_to` streams an image to a seekable
  destination, writing only the blocks the filesystem uses, and a read windows its
  way through a file rather than holding it.

## This guide

- [Safe by construction](./design/safety.md), [Deterministic
  output](./design/determinism.md), [Rootless and
  cross-platform](./design/rootless.md), and [Resize-safe
  geometry](./design/resize-safe.md) describe the guarantees the crate is built
  around.
- [Installation](./installation.md) shows how to add the crate to a project, and
  [Formatting and reading images](./formatting.md) walks through the API.
- The [API reference](./api-reference.md) documents every public item.
