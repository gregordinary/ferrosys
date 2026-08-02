# Formatting and reading images

`ferrosys` has two halves: a formatter that writes an ext2, ext3, or ext4 image
from a description of its contents, and a reader that parses an image back into
inodes, directories, and file data.

## Describing the contents

A `TreeBuilder` collects the entries to place in the filesystem — directories,
files, symlinks, hard links, device / FIFO / socket nodes, and their extended
attributes — each with its ownership, mode, and times. The root directory and
`/lost+found` always exist and are not added:

```rust
# extern crate ferrosys;
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::{Metadata, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
    .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), Metadata::new(0o644, time))
    .symlink(b"/etc/mtab".to_vec(), b"/proc/self/mounts".to_vec(), Metadata::new(0o777, time))
    .directory(b"/bin".to_vec(), Metadata::new(0o755, time))
    .file(b"/bin/busybox".to_vec(), vec![0x7f, b'E', b'L', b'F'], Metadata::new(0o755, time))
    .hardlink(b"/bin/sh".to_vec(), b"/bin/busybox".to_vec(), Metadata::new(0o755, time));
# let _ = source;
```

Order of addition does not matter — inode numbers are assigned in sorted path
order — but every parent directory must be present somewhere in the source. An
input the format cannot represent, such as a name over 255 bytes or a hard link
to a directory, is a typed error rather than a silently dropped entry.

The builder also places device, FIFO, and socket nodes and attaches extended
attributes and POSIX ACLs. `xattr` applies to the entry added just before it, and
an ACL is encoded and attached under its `system.posix_acl_*` name:

```rust
# extern crate ferrosys;
use ferrosys::ext::acl::{EXEC, READ, WRITE};
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::{Acl, AclEntry, AclQualifier, Metadata, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let acl = Acl::new(vec![
    AclEntry { who: AclQualifier::UserObj, perm: READ | WRITE | EXEC },
    AclEntry { who: AclQualifier::GroupObj, perm: READ | EXEC },
    AclEntry { who: AclQualifier::Other, perm: READ },
])
.unwrap();
let source = TreeBuilder::new()
    .directory(b"/dev".to_vec(), Metadata::new(0o755, time))
    .char_device(b"/dev/null".to_vec(), 1, 3, Metadata::new(0o666, time))
    .file(b"/ping".to_vec(), b"ELF".to_vec(), Metadata::new(0o755, time))
    .xattr(b"security.capability".to_vec(), vec![0u8; 20])
    .directory(b"/srv".to_vec(), Metadata::new(0o755, time))
    .xattr(Acl::ACCESS_NAME.to_vec(), acl.encode());
# let _ = source;
```

Each entry's access, change, and modification times default to the one timestamp
passed to `Metadata::new`; `Metadata::with_times` sets them independently. A
fixed-time option on the format call overrides every entry's times for
byte-reproducible output regardless of the source.

With the `tar` feature enabled, an `ArchiveSource` parses a tar archive — its PAX
timestamps, `SCHILY.xattr.*` attributes, and `SCHILY.acl.*` ACL records — into the
same entries a `TreeBuilder` produces, so the rest of the pipeline is identical.

It has two constructors, and they differ only in where a regular file's *contents*
live. `ArchiveSource::from_reader` takes any stream and reads every body into memory.
`ArchiveSource::from_path` opens the archive itself, records where each body lies, and
reads it only when that file is placed — so a format needs the largest single member
rather than the sum of them all. Both write byte-identical images. The handles keep the
archive open, so it must not be modified in place until the format finishes; replacing
it by writing a new file and renaming it over the old one is safe, because the original
inode stays readable.

With the `dir` feature enabled, a `DirectorySource` walks a directory tree on this machine
into the same entries. The directory it is pointed at becomes the filesystem root, and
everything under it keeps its path relative to that: modes, ownership, all three times to
the nanosecond, symlinks (recorded, never followed), hard links, device, FIFO and socket
nodes, and extended attributes with their POSIX ACLs, which are translated from the
version-2 form the syscall boundary speaks into the compact form ext stores.

The metadata and the extended attributes the walk reads are Linux's, so `DirectorySource`
is built on Linux; on another platform the feature compiles and the type is absent, and
`ArchiveSource` is the portable way to describe a tree. Everything else the crate
does — planning, writing, reading, and scanning — is the same everywhere.

```rust,ignore
# extern crate ferrosys;
use ferrosys::ext::{DirectorySource, FormatOptions, format_to};

// A build that does not run as root records its own uid on every file it walks, so the
// override is what makes the image root-owned.
let source = DirectorySource::from_path("staging/rootfs")?.owner(0, 0);
let out = std::fs::File::create("rootfs.img")?;
format_to(source, 512 << 20, options, out)?;
```

The walk sorts its entries by path and its attributes by name, and where several names
share an inode the first in that sorted order carries the file while the rest become hard
links to it — so the same tree walks to the same entry list whatever order the host listed
its directories in. Each file's bytes are read as that file is placed and no descriptor is
held in between, so a tree may hold any number of files and the peak memory is the largest
single one.

The times on those entries are the host's, and two of the three move under the host's feet.
A walk reads every directory and every symlink to learn what it holds, and a host that
maintains access times records that read — so reading a tree is itself enough to change
what the next walk of it records. The change time moves whenever anything sets a mode, an
owner, or a link count, which is what staging a tree does. Only the modification time
tracks the file's contents.

`times_from_modification` is what makes those times the walk's rather than the host's:

```rust,ignore
# extern crate ferrosys;
use ferrosys::ext::DirectorySource;

let source = DirectorySource::from_path("staging/rootfs")?
    .owner(0, 0)
    .times_from_modification();
```

Each entry's modification time then stands in for its access and change times, so one tree
walks to one image however many times it has been read or restaged, while every file keeps
the modification time that describes it. That is the clamp for a build that wants both
reproducible bytes and per-file times; `FormatOptions::fixed_time` is the clamp for one
that forces every inode to a single time instead, and gives up per-file times to do it.

### Composing sources

A `LayeredSource` puts one source over another, so a later layer's entry replaces an
earlier layer's at the same path. This is the shape an image build takes when a base tree
is customized — a root filesystem from an archive, configuration over it, computed files
over that — and the layers need not be of the same kind:

```rust,ignore
# extern crate ferrosys;
use ferrosys::ext::{ArchiveSource, DirectorySource, LayeredSource};

let source = LayeredSource::new()
    .layer(ArchiveSource::from_path("rootfs.tar")?)
    .layer(DirectorySource::from_path("overlay/etc")?)
    .layer(computed_files);
```

A path in more than one layer takes the last layer's entry whole — its kind, metadata, and
extended attributes, which replace the earlier set rather than merging with it name by
name. A directory is the case worth knowing: naming it again sets its mode, ownership, and
times, but its *contents* are separate entries at their own paths, so the layers' contents
merge and a configuration layer is additive. Replacing a directory with something that is
not one is different — the entries beneath it would have nowhere to live, so they are
dropped with it.

Paths are compared as the model compares them, so `/etc/hostname` and `//etc//hostname` are
one path and the second does replace the first. There is no deletion marker: a layer states
what is present, so the result always holds the union of the layers' paths.

A file's contents are a `FileContent`: either `Owned` bytes or a `Range` of a host file.
Both coexist in one entry list, which is what lets a caller take an archive-backed list
and replace one entry's contents with bytes it computed while every other entry stays on
disk. `TreeBuilder::file` takes anything that converts into one — a `Vec<u8>`, a `String`,
a borrowed `&[u8]`, `&[u8; N]`, or `&str`, each copied into the entry, or a `FileRange`,
which names host bytes and reads them when the file is placed. `FileContent::read` hands
back a `Cow`, so owned bytes are borrowed rather than copied and a format never holds two
copies of one file.

A `FileRange` comes in two forms. `FileRange::new` carries an open descriptor, shared, so
a hundred ranges into one archive cost one descriptor; `FileRange::at_path` carries the
path alone and opens it for each read, which is what lets a source name a range in each of
a hundred thousand separate files. Either way the bytes are read when the file is placed,
so the file must not be modified in place before the format finishes.

## Formatting

`format` takes the source, the image size, and the identity and grow inputs in
`FormatOptions`. The **maximum grow target** sizes the reserved
group-descriptor-table blocks; it is the largest size the image may later occupy:

```rust
# extern crate ferrosys;
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::{format, FormatOptions, GrowReservation, Metadata, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), Metadata::new(0o644, time))
    .directory(b"/etc".to_vec(), Metadata::new(0o755, time));

let uuid = [0x11; 16];
let hash_seed = [0u8; 16];
let mut options = FormatOptions::new(uuid, time, hash_seed);
// Reserve descriptor blocks to grow online up to 32 GiB.
options.grow = GrowReservation::UpTo(32 << 30);

let image = format(source, 64 << 20, options).expect("format a 64 MiB image");
assert_eq!(image.as_bytes().len(), 64 << 20);
```

The returned `Image` exposes the bytes directly (`as_bytes`, `into_bytes`) or
streams them to any writer (`write_to`) — for instance
`image.write_to(std::fs::File::create("rootfs.img")?)`.

`FormatOptions` also carries the block size (through its feature set: 1024, 2048,
or 4096 bytes), the journal size, and how directory names hash — the algorithm and
whether their bytes are read as signed or unsigned. The image records both, so a
reader reproduces a name's hash from the image rather than from its own host.

The feature set is the source of truth for which family an image is, and a
`Profile` is the two-way lens over it. `FormatOptions::profile(Profile::Ext2)`
seeds the whole set from the ext2, ext3, or ext4 baseline — the words `mke2fs -t`
writes — and is chainable from `new`; set individual features on `feature`
afterward to depart from it. `Profile::of(feature)` names the family a set
classifies to, which is what `Reader::profile` reports for an image on the way
back in.

A feature word is a promise about the structures the filesystem carries, so the words and
the bytes written under them have to agree. `FeatureSet::validate` refuses a set that
contradicts itself before any planning happens — `metadata_csum_seed` without the
checksums it seeds, `orphan_file` without the journal its entries are written through,
`resize_inode` at a 4096-byte block without `large_file`, since the resize inode is itself
a file of 4 GiB. A source the set cannot describe is refused the same way and names the
entry: extended attributes without `ext_attr`, a regular file of `LARGE_FILE_MIN_SIZE` or
more without `large_file`. Nothing is silently dropped and no feature is silently added.

### Pinning the bytes across versions

Images are byte-reproducible: the UUID, the timestamps, and the hash seed are inputs, so
the same source and the same options write the same bytes, always. That holds across
versions of this crate too — but only for a feature set that is itself fixed.

`FeatureSet::DEFAULT`, `EXT2`, and `EXT3` are fixed and stay fixed, so pinning to one of
them pins the layout. `FeatureSet::LATEST` deliberately does not: it tracks what a
current `mke2fs` writes for ext4, so it may gain a feature in any release and the bytes
under it may change with it. Name `LATEST` when parity with the current tool is what you
want, and `DEFAULT` when reproducible bytes are.

To record exactly what a build resolved to, `FeatureSet::pin` emits the whole set as one
canonical document — every feature word twice over, as exact bits and as readable names,
plus the block and inode sizes that a feature-name list would omit:

```text
ferrosys-feature-pin 1
compat 0x0000103c has_journal ext_attr resize_inode dir_index orphan_file
incompat 0x000022c2 filetype extent 64bit flex_bg metadata_csum_seed
ro_compat 0x0000046b sparse_super large_file huge_file dir_nlink extra_isize metadata_csum
block_size 4096
inode_size 256
```

Record it verbatim and compare it string for string on the next build: a difference is
drift in the on-disk layout, surfaced as a diff a person reads rather than as changed
image bytes nobody notices. `FeatureSet::EMPTY` is the base to replay a recorded list of
feature names back through `with_feature`, which is how the readable half of a pin is
checked against the exact half.

The feature set is five of the decisions that move bytes, and not the only five. The grow
reservation, inode count, reserved share, error behaviour, journal size, and the two hash
choices each move them too, and none of them appears above — so a build that changed one
would produce a different image under an identical feature pin. `errors` is the least
visible of them: it reaches neither the feature words nor the geometry, so nothing else
records it at all.

Three documents cover the whole format, split by *why each one changes*:

| Document | What it holds | When it changes |
| --- | --- | --- |
| `FormatOptions::policy_pin` | feature set, grow, inodes, reserved, errors, journal, hash choices, whether times are clamped | only when the contract changes |
| `FormatOptions::identity_pin` | uuid, time, hash seed, label, the clamped time | every image, by design |
| `FormatPlan::geometry_pin` | block and inode counts, group table, reserved GDT, journal length | with the filesystem's size |

Each is a self-contained document with its own version line, so a builder records the ones
it wants and never has to slice a section out of a larger one.

**The policy pin is the one to record and compare.** Nothing in it varies with the image, so
a builder writing many images from one set of constants gets one policy pin for all of them
— which means an empty diff between two images' recorded pins says they were built to the
same contract, and a non-empty diff always means something changed:

```rust
# extern crate ferrosys;
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::FormatOptions;

let options = FormatOptions::new([0x11; 16], Timestamp::from_secs(1_700_000_000), [0; 16]);
assert!(options.policy_pin().starts_with("ferrosys-policy-pin 1\n"));
```

```text
ferrosys-policy-pin 1
compat 0x0000103c has_journal ext_attr resize_inode dir_index orphan_file
incompat 0x000022c2 filetype extent 64bit flex_bg metadata_csum_seed
ro_compat 0x0000046b sparse_super large_file huge_file dir_nlink extra_isize metadata_csum
block_size 4096
inode_size 256
grow max
inodes auto
reserved 500
errors continue
journal auto
hash_version half_md4
hash_signedness unsigned
timestamp_clamp none
```

No UUID, no timestamp, no label, no block count. Those change for reasons that are not
drift — an image is *meant* to have its own identity, and a filesystem sized to its
partition is *meant* to have its own geometry — so recording them beside the contract would
make every comparison non-empty and worthless. The identity pin exists for a caller that
wants them anyway; every field in it is also a superblock field, so a caller that can open
the image it built need not record it at all.

### Pinning what a name means, not just the name

A policy pin records the options *by name*. It moves when an option is renamed or its
default changes — and not when the formula behind one changes underneath an unchanged name.
`grow max` reads the same before and after a change to how much `Max` reserves, while every
block after the descriptor table moves.

Planning at a **fixed reference size** and pinning the result is what closes that:

```rust
# extern crate ferrosys;
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::{FormatOptions, FormatPlan, TreeBuilder};

// The size is the test's constant, not the build's, so this pin is the same for every
// image built to these options however large each one is.
const REFERENCE_SIZE: u64 = 512 << 20;

let options = FormatOptions::new([0x11; 16], Timestamp::from_secs(1_700_000_000), [0; 16]);
let reference = FormatPlan::new(TreeBuilder::new(), REFERENCE_SIZE, options)?;
let pinned = reference.geometry_pin();
assert!(pinned.starts_with("ferrosys-geometry-pin 1\n"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

```text
ferrosys-geometry-pin 1
block_size 4096
total_blocks 16384
blocks_per_group 32768
first_data_block 0
group_count 1
inodes_per_group 16384
inode_table_blocks 1024
total_inodes 16384
gdt_blocks 1
reserved_gdt_blocks 256
flex_bg_size 16
max_grow_blocks 538968064
reserved_blocks 819
groups 1 crc32c 0x8a137015
journal_blocks 1024
```

`reserved_gdt_blocks` is the line to notice: it is the descriptor headroom the grow
reservation sized, and every block after the descriptor table sits where it does because of
it. Pinning the two documents together — the policy for the contract, one reference geometry
for what the contract resolves to — catches both a renamed option and a re-computed one.

The per-group placements are one line rather than one per group: the count, and a `crc32c`
over every field of every group. A filesystem has as many groups as it has room for and a
large one has millions, so the document stays a fixed size while a placement that moves
still changes it.

Each document's first line carries its version, and that version moves whenever the shape
of the document moves. Two documents that both say `1` always mean the same thing, so a
recorded pin that stops matching is a change in what was pinned and never a change in how it
was rendered.

### Deciding everything before the destination is touched

A format writes only the blocks the filesystem uses, so every byte of the destination it
does not write must already read as zero — which means creating the file, or truncating one
that is already there, is part of formatting rather than something done beforehand. A run
that then failed would have destroyed what was at that path for nothing.

`FormatPlan` is the fallible half of a format as a value, and it is what makes that
impossible. `FormatPlan::new` takes the source, the size, and the options and does every
piece of work that can fail — parsing the source, planning the geometry, building the
inode model and checking it against that geometry, sizing the journal. What it returns can
only be written:

```rust,ignore
# extern crate ferrosys;
use ferrosys::ext::FormatPlan;

// Nothing has been opened yet; a failure here leaves whatever is at the path untouched.
let plan = FormatPlan::new(source, 512 << 20, options)?;
println!("{} blocks, {} inodes used", plan.layout().total_blocks, plan.used_inodes());

let out = std::fs::File::create("rootfs.img")?;
let layout = plan.write_to(out)?;
```

`format` and `format_to` both route through it, so there is one derivation of a layout
rather than two. `layout()` and `used_inodes()` report what the write will realize before
a byte is written, which is what a caller reporting a geometry, or deciding whether to
write at all, needs.

Three more fields tune what the size alone would decide, each defaulting to what the
size implies. `volume_name` labels the filesystem, up to sixteen bytes NUL-padded into
`s_volume_name`. `inodes` (an `InodeCount`) sets how many inodes it holds — a
bytes-per-inode density or an exact count — overriding the size-driven default; a
density past what a group's bitmap indexes is refused rather than reduced. `reserved`
(a `ReservedRatio`) sets the share of blocks held back for the super-user, in exact
hundredths of a percent, defaulting to 5%.

### Sizing the filesystem to what goes in it

`FormatPlan::new` is told how large the filesystem is. `FormatPlan::fit` works it out
instead, from the source:

```rust,ignore
# extern crate ferrosys;
use ferrosys::ext::{FormatPlan, Slack};

// The smallest filesystem that holds the source, with a fifth of it still free.
let plan = FormatPlan::fit(source, options, Slack::Share(2000))?;
println!("{} bytes", plan.size_bytes());
plan.write_to(std::fs::File::create("rootfs.img")?)?;
```

There is no formula behind it. How much room a filesystem has left depends on how many
block groups it has, how large its inode tables are, how many descriptor blocks it reserves
to grow into, and how large a journal its size earns — and every one of those follows from
the size, so the answer is a fixed point. `fit` finds it by planning candidate sizes and
*placing* the source into each one, using the format's own placement pass over a sink that
keeps nothing. Nothing is estimated beside the writer; the part of the writer that decides
is what runs.

That is what backs the guarantee: **the size `fit` returns formats, and one block less does
not.** The search closes a bracket whose ends are both established by placing, so it ends
holding a size that was placed successfully and the size one block below it that was not.
Fit is not monotone in size — a filesystem one block larger can need another block group,
and so have less room than the one below it — so that is *a* smallest size rather than
provably *the* smallest.

`Slack` says how much must be left free once the source is written, since the smallest
filesystem holding a source is one with nothing left in it:

| | |
|---|---|
| `Slack::None` | the floor: `plan.size_bytes()` is then the minimum size for this source |
| `Slack::Bytes(64 << 20)` | at least 64 MiB free, rounded up to whole blocks |
| `Slack::Share(2000)` | at least a fifth of the filesystem free, in hundredths of one percent |

The measure is free blocks — the same count `s_free_blocks_count` carries. The super-user
reservation is separate accounting over the same blocks, so a filesystem left a fifth free
under the default 5% reservation leaves an unprivileged writer 15% of it.

The source is consumed once and the model built from it is kept, so a fitted plan writes
with no second walk of the source. That is also why there is no `minimum_size` function
taking a source of its own: `FormatPlan::fit(source, options, Slack::None)?.size_bytes()`
is that number, and it hands back the plan that produces it rather than throwing the work
away.

## Streaming a large image

`format` builds the whole image in memory. `format_to` instead writes it to any
seekable destination, touching only the blocks the filesystem uses, so the
destination stays sparse and the image never exists in memory at once. It returns
the `Layout` the bytes realize:

```rust,no_run
# extern crate ferrosys;
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::{format_to, FormatOptions, GrowReservation, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let size = 512u64 << 30; // 512 GiB
let mut options = FormatOptions::new([0x11; 16], time, [0u8; 16]);
options.grow = GrowReservation::UpTo(size);

let file = std::fs::File::create("big.img").unwrap();
let layout = format_to(TreeBuilder::new(), size, options, file).unwrap();
assert_eq!(layout.total_blocks, size / u64::from(layout.block_size));
```

Every byte of the destination that is not written must read back as zero, which a
freshly created file satisfies. Block numbers past 2^32 are written where the size
needs them, so a filesystem beyond 16 TiB addresses its blocks correctly.

Three things are held while the bytes stream out, and none of them is the image:

- **The entry list**, and the inode model built from it, for the whole run. This grows
  with the number of entries, not with their size.
- **A file's contents, while it is placed.** How long that is depends on the source: an
  entry holding `FileContent::Owned` bytes holds them from the moment the source was
  built, so a list of them costs the sum of every file, while a `FileContent::Range` is
  read at placement and dropped after, so a list of them costs the largest single file.
  `ArchiveSource::from_path` is what makes that difference for a tar source.
- **The allocator's used-block bitmap**, for the whole run, at one bit per filesystem
  block: `total_blocks / 8` bytes, 128 MiB for a 4 TiB image at a 4 KiB block.

So peak memory grows with the entry count, the largest file, and the block count — never
with the image's size in bytes.

## Reading

The `Reader` opens over an image's bytes and parses it back. It walks the directory
tree from the root (inode 2) and returns file and symlink contents:

```rust
# extern crate ferrosys;
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::{format, FormatOptions, GrowReservation, Metadata, Reader, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .file(b"/greeting".to_vec(), b"hello\n".to_vec(), Metadata::new(0o644, time));
let mut options = FormatOptions::new([0x11; 16], time, [0u8; 16]);
options.grow = GrowReservation::UpTo(32 << 30);
let image = format(source, 64 << 20, options).unwrap();

// The reader reads over any `Read + Seek` source; wrap the bytes in a cursor.
let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).unwrap();
let (_, file) = reader.lookup(b"/greeting").unwrap();
assert_eq!(reader.read_data(&file).unwrap(), b"hello\n");
```

### Reading without holding the file

`read_data` returns a whole file, which is right for a configuration file and wrong for a
kernel image. Three methods read without ever holding one:

- **`read_into(&inode, offset, buf)`** fills `buf` from `offset` and returns how many bytes
  it read, short only at the end of the file. It maps a window of the file at a time, so
  reading the last megabyte of a large file does not build the whole mapping first.
- **`read_data_to(&inode, writer)`** streams the whole file to any `Write`, a window at a
  time, and returns the byte count. Peak memory is the window, whatever the file's size.
- **`walk_with(|reader, entry| …)`** walks the tree lazily, handing each entry to the
  callback as it is reached rather than collecting the whole listing first. The callback
  receives the reader, so it may read each file as it walks. It is generic over the
  callback's error type, so a consumer's own failure comes straight back out.

```rust,ignore
# extern crate ferrosys;
// Copy every regular file out of the image without holding any of them.
reader.walk_with(|reader, entry| -> Result<(), MyError> {
    if entry.inode.mode & 0o170000 == 0o100000 {   // a regular file
        let mut out = std::fs::File::create(destination(&entry.path))?;
        reader.read_data_to(&entry.inode, &mut out)?;
    }
    Ok(())
})?;
```

`walk` collects the whole listing into a `Vec` and is what to reach for when the tree,
rather than its contents, is the subject.

With the `tar` feature enabled, `ArchiveSink` is that loop already written:
`ArchiveSink::new(writer).write_tree(&mut reader)` streams the whole filesystem out as a
tar archive — ownership, modes, times to the nanosecond, symlinks, hard links, device and
FIFO nodes, extended attributes, and POSIX ACLs, all carried in PAX records — with each
member's body streamed rather than buffered. An archive that makes the round trip through
`ArchiveSource` describes the same filesystem at both ends. A socket has no tar entry type
at all, so a filesystem holding one is a typed error rather than an archive quietly missing
a file.

### Writing the tree back out

With the `dir` feature enabled, on Linux, `DirectorySink` is the same thing as a tree on
this host rather than as an archive — the inverse of `DirectorySource`:

```rust,ignore
# extern crate ferrosys;
use ferrosys::ext::{DirectorySink, Reader};

let mut reader = Reader::open(std::fs::File::open("rootfs.img")?)?;
std::fs::create_dir("unpacked")?;
let report = DirectorySink::new("unpacked")?.write_tree(&mut reader)?;
println!("{} names written", report.written);
```

The destination must exist and be empty; it takes the filesystem root's own mode,
ownership, times, and extended attributes, and everything the filesystem holds appears
beneath it. `/lost+found` is omitted, so the tree is one `DirectorySource` reads straight
back. A file's bytes are streamed a window at a time, so a tree far larger than memory
costs a working set.

**The image is untrusted, and a name in it is not a path to resolve.** Every directory is
created and then opened, and everything beneath it is created through that open handle by
its single-component name — checked to be one a directory can hold, so a name carrying a
separator, a `..`, or a NUL is `HostError::HostileName` rather than a write somewhere
else. Symbolic links are written exactly as recorded, absolute targets included, which is
safe because nothing here ever follows one: every handle is opened `O_NOFOLLOW` and every
attribute is set on the link itself.

Two parts of a tree take privileges — a device node needs `CAP_MKNOD`, and setting a
recorded owner needs `CAP_CHOWN` — and by default a host that refuses either is
`HostError::Unprivileged`, naming the entry. `skip_privileged` is the opt-in for an
unprivileged extraction: what it left out comes back in the `ExtractReport` rather than in
silence.

Two times no extraction can carry, because no host lets a caller set them: an inode's
**change time** and its **creation time**. Access and modification times are set exactly,
to the nanosecond.

### Filesystems other tools made

The reader reads any conformant ext image, whatever tool wrote it. It follows the
on-disk format, so an image `mke2fs` or the kernel produced reads the same as one
this crate wrote:

- **Any inode size.** The 128-byte inode has no extended area, so it carries no
  creation time, no sub-second timestamps, and no `i_checksum_hi`; every field past
  the classic inode is read only when the inode actually holds it. That is the same
  condition the kernel applies, and it is why the reserved inodes of a filesystem
  another formatter wrote — which declare no extended area — verify against the low
  half of their checksum alone.
- **Either mapping.** An inode flagged for extents roots an extent tree; every other
  inode uses the classic direct/indirect block map, with a zero pointer standing for a
  hole at any level. ext2 and ext3 map every file that way.
- **Checksums verified against the object's own bytes**, so a field the filesystem
  carries and this crate does not model — `l_i_version`, which the kernel bumps on
  every inode update, or the superblock's error record — is part of the checksum it
  was part of when it was computed.

### Resolving a path

`lookup` resolves a path to its inode, following symbolic links. Targets resolve
against the image's own root, never the host's, and resolution stops at a bounded
number of links, so a cycle terminates:

```rust,ignore
# extern crate ferrosys;
// A merged-`/usr` root filesystem, where `/lib` is a link into `/usr/lib`.
let (_, modules) = reader.lookup(b"/lib/modules")?;   // follows the link
let (_, link) = reader.lookup_no_follow(b"/lib")?;    // the link itself
assert_eq!(reader.read_symlink(&link)?, b"usr/lib");
```

`walk` yields the literal tree and does not descend through links, so on a
merged-`/usr` layout the paths under `/lib` appear only under `/usr/lib`. `lookup` is
what reaches them by the name a system actually uses.

### Checking an image

`scan` walks the whole image and reports every deviation it finds as a structured
`Anomaly` rather than stopping at the first — a checksum that does not match, a
reference out of range, a structure that does not parse, an inode carrying a structure
its superblock's feature words deny. It reports what is wrong; it does not refuse the
image. `verify_checksums` is the strict counterpart, failing on the first object whose
stored checksum does not match its recomputed value.

`scan` is the path to point at an image you have no reason to trust. Every allocation it
makes is bounded by the bytes the source holds rather than by a count the image claims:
the groups and inodes it walks are capped at what the source can physically hold, each
metadata block is read once however many references name it, and the findings stop at
`Limits::max_anomalies` — `ScanReport::MAX_ANOMALIES` unless you set another — with
`ScanReport::is_truncated` recording that they did. A truncated report is a floor: the
image holds at least these findings, `worst_severity` and `has_fatal` are floors too, and
`is_clean` is false whatever the report holds, since a scan that stopped short never saw
enough to call an image clean.

`walk` is bounded the same way — a well-formed filesystem spends at least a directory
record's worth of its own blocks per name, so the source's length bounds how many names
it can describe. Reaching that bound is an error rather than a short list: a caller
extracting a tree from a truncated walk would write an incomplete one and see success.

A report projects to JSON, to a fixed-column table, and to a SARIF log. The JSON document
opens with a `schema` field holding `ext::read::SCAN_SCHEMA_VERSION`: a downstream parser depends on
the emitted shape, and no Rust signature describes it, so the shape names its own version.

### Opening options

`Reader::open` reads from the start of a source, strictly, with the default limits.
`Reader::open_with` takes an `OpenOptions` carrying everything else: where the filesystem
begins within the source (a partition offset), the `ReadPolicy` to hold it to, a `Limits`
capping what one read may allocate, and a `metadata_csum` seed to verify against when the
image's stored seed and UUID no longer agree.

```rust,ignore
# extern crate ferrosys;
use ferrosys::ext::{Limits, OpenOptions, ReadPolicy, Reader};

// A filesystem one mebibyte into a disk image, read leniently so a scan can describe
// what is wrong with it, and held to a gigabyte per file read.
let options = OpenOptions::new()
    .base(1 << 20)
    .policy(ReadPolicy::Lenient)
    .limits(Limits::new().max_file_bytes(1 << 30));
let mut reader = Reader::open_with(file, &options)?;
```

The limits default to imposing nothing, so an image of any size this crate wrote reads
back whole at the default settings. `max_file_bytes` bounds the logical-to-physical
mapping a read builds as well as the buffer it returns: the mapping costs eight bytes per
logical block against one byte per byte returned, so on the crafted `i_size` the cap
exists for it is the larger of the two.

A file past the cap is a `ReadError::FileTooLarge` naming the size and the bound — not a
short read. A truncated file that looked like a whole one would be the worse outcome by
far: a caller extracting a tree would write it out, see success, and carry a silently
incomplete file forward. Where a large file is legitimate, `read_data_to` streams it
without the cap applying to a buffer that is never allocated.

## Saying what an image is

`detect` reads a source and reports the `Filesystem` family it holds — the crate root's
own vocabulary, independent of which families are compiled in. `detect_with` does the same
at an offset within the source, for a partition inside a whole-disk image or a region a
carver located:

```rust,ignore
# extern crate ferrosys;
use ferrosys::{DetectOptions, Filesystem, detect_with};

let what = detect_with(disk, &DetectOptions::new().base(1 << 20))?;
assert!(matches!(what, Filesystem::Ext4));
```

Detection asks what an image *is*, not whether it is sound: it classifies leniently, so an
image with a quirk a strict read would refuse still answers here. `Reader` and `scan` are
what say whether a filesystem is well-formed.
