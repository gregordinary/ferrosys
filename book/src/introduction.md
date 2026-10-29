# ferrosys

`ferrosys` builds and reads filesystem images entirely in userspace, over ordinary byte
streams, in safe Rust (`#![forbid(unsafe_code)]`). It is self-contained, pure Rust, and
runs anywhere Rust runs. It carries five families:

- ext2, ext3, and ext4, behind the `ext` feature
- FAT12, FAT16, and FAT32, behind the `fat` feature
- exFAT, behind the `exfat` feature
- btrfs, behind the `btrfs` feature
- APFS, behind the `apfs` feature

A default build carries all five. Every reader is held to a never-panic contract on any
input. The families it writes share two more properties: the output is byte-reproducible,
and the whole layout is decided before a byte is written.

## What the crate is

- **A Rust library** you link and call in process.
- **Rootless.** It works the image as ordinary data and runs unprivileged.
- **Cross-platform.** Pure Rust, so it builds and reads images on Linux, macOS, Windows,
  and the BSDs.
- **Deterministic.** The default output is byte-reproducible, because the values a
  filesystem would draw from its environment are inputs the caller supplies.
  [Deterministic output](./design/determinism.md) lists all four sets.
- **Resize-safe** in the on-disk geometry it writes for ext.
- **Unbounded by memory.** `format_to` streams an image to a seekable destination and
  writes only the blocks the filesystem uses. A read moves a window through a file rather
  than holding it.

## The ext family

A formatter writes an image from a description of its contents, and a reader parses an
image back. The description covers directories, files, symlinks, hard links, device, FIFO
and socket nodes, extended attributes, and POSIX ACLs. Each carries its ownership, its
modes, and its access, change, and modification times.

The contents come from a programmatic builder, from a tar archive and its PAX metadata
(the `tar` feature), or from a directory tree on this machine (the `dir` feature).

The image carries real superblock and descriptor backups, and reserved descriptor blocks
sized to a grow target. That target is a maximum the caller names, or as much headroom as
a sixty-fourth of the filesystem buys when the caller names none. The filesystem therefore
grows in place without relocating its descriptor table.

Every metadata object carries a crc32c (`metadata_csum`), so a checker detects corruption
of the filesystem's own structures. ferrosys writes a format-time jbd2 journal
(`has_journal`), sized from the filesystem, into the journal inode, so the kernel journals
from the first mount. The inodes awaiting deletion are recorded in an orphan file
(`orphan_file`).

Files map their blocks with extent trees of any depth. A directory that outgrows one block
gains a hash index (`dir_index`). The filesystem UUID, the directory-hash seed, and the
timestamps are inputs, so names hash the same way whatever machine builds the image.

## The FAT family

`ferrosys` writes and reads FAT12, FAT16, and FAT32 volumes behind the `fat` feature. This
is the family the EFI System Partition is.

The ext guarantees read differently here, because FAT has no field for a permission bit,
an owner, or a link. Which of the three a volume is follows from its cluster count alone,
so the geometry is the format's real contract.

The output is byte-reproducible on the same terms as the ext writer's. The reader is held
to the same never-panic contract on any input.

## exFAT

`ferrosys` writes and reads exFAT volumes behind the `exfat` feature. This is the
interchange format for large removable media, and the one SDXC cards specify. Every
current desktop operating system reads it as it ships.

exFAT is a family of its own behind a feature of its own. It has a different boot region,
a different directory entry format, a different name encoding, and an allocation bitmap
FAT has no concept of.

Its output is byte-reproducible on the same terms as the other two writers', and it costs
one input to be so. That input is the volume serial number, because an empty exFAT volume
records no time at all. Its reader is held to the same never-panic contract on any input.

It folds names through the up-case table the *volume* carries, rather than one of its own.
A lookup therefore resolves what a driver reading the same volume resolves.

## btrfs

`ferrosys` writes and reads btrfs behind the `btrfs` feature. This is the default root
filesystem on Fedora and openSUSE, and the one image-based Linux tooling increasingly
assumes.

Every address in a btrfs is logical, and one map translates all of them. That is the
structural difference from the three families here, and the reason this one has a layer
they do not.

Reading covers both layers the format has. The lower layer is three things:

- The superblock, and every copy of it the device holds
- The chunk tree that maps a logical address onto the device
- Any of the filesystem's B-trees, searched by the key tuple

ferrosys verifies every block's checksum as it reads it. The upper layer is the filesystem
itself. Paths resolve across subvolume boundaries, and a file's bytes come back whatever
shape its extents take. `verify_data` holds those bytes against the checksums the
filesystem recorded for them, which is a check no other family here can make.

Writing puts a source tree into a complete btrfs:

- Ten trees, and one more per subvolume
- Every block checksummed, and a crc32c beside every sector of file data
- Every allocated block recorded in the extent tree with the tree that owns it
- Every superblock copy the device has room for

A caller names which of the source's directories become subvolumes, and which subvolume a
mount that names none lands in. It goes down in one transaction, and nothing is ever
rewritten. The whole layout is therefore decided before a byte is placed.

The output is byte-reproducible on the same terms as the other three writers', and costs
five inputs to be so. btrfs has a field for every property a source states, so this is the
one family here whose fidelity report is empty in both directions.
[Reading a btrfs](./formatting.md#reading-a-btrfs) and
[writing one](./formatting.md#writing-one) are the two halves.

## APFS

`ferrosys` reads APFS behind the `apfs` feature: the format of every Mac, of the disk images
macOS makes, and of the drives a Mac formats.

An APFS partition holds one container, a pool of blocks under a checkpoint, and the
container lists its volumes. Each volume is a filesystem of its own, with its own tree of
records found through its own object map. So a read is a read of one volume: the one in the
container's first slot, or the one a caller names.

Reading covers both layers. The container is the newest whole checkpoint, its object map,
and every volume it lists, each with its role and the features it carries. A volume is read
as files: paths, attributes embedded and in streams of their own, hard links, and sparse
files. A file whose content macOS compressed with zlib, LZVN, LZFSE or LZBITMAP reads as
its content. So does one stored whole behind its compression header. Every object's
checksum is verified, and every object is held to the identifier, type, and transaction of
the reference that reached it.

A volume's snapshots are views of it. Each is listed with the transaction it keeps the
volume at and the identifier it carries, and any one opens as the volume it keeps.

An encrypted volume, a sealed one, a Fusion container, and a feature bit this crate does not
read are each refused by name.

`ferrosys` also writes a container, each volume holding a source tree of its own. Two of them
can be joined as a System and Data volume group. Empty, one
volume is block for block what `newfs_apfs` writes into a file on macOS 14, 15, 26 and 27. The identifiers and the
one instant it records are inputs, and so is how each volume compares names. [Formatting an APFS container](./formatting.md#formatting-an-apfs-container) shows
the call.

## This guide

- [Safe by construction](./design/safety.md), [Deterministic
  output](./design/determinism.md), [Rootless and
  cross-platform](./design/rootless.md), and [Resize-safe
  geometry](./design/resize-safe.md) describe the guarantees the crate is built
  around.
- [Installation](./installation.md) shows how to add the crate to a project, and
  [Formatting and reading images](./formatting.md) walks through the API.
- The [API reference](./api-reference.md) documents every public item.
