# Formatting and reading images

`ferrosys` has two halves: a formatter that writes a filesystem image, and a reader
that parses one back. Each filesystem family lives in a module of its own. `ext` writes and
reads ext2, ext3, and ext4, and `fat` writes FAT12, FAT16, and FAT32.

A third vocabulary belongs to neither half and lives at the crate root. It describes a
directory tree, reports what a format could not hold, and says what an image is.

Most of this page is the ext family, which is the one with the fullest surface.
[Formatting a FAT volume](#formatting-a-fat-volume) is what differs.

## Describing the contents

A `TreeBuilder` collects the entries to place in the filesystem, each with its ownership,
mode, and times. Those entries are directories, files, symlinks, hard links, device, FIFO
and socket nodes, and their extended attributes. The root directory and `/lost+found`
always exist and are not added:

```rust
# extern crate ferrosys;
use ferrosys::ext::{Metadata, Timestamp, TreeBuilder};

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

Order of addition does not matter, because inode numbers are assigned in sorted path
order. Every parent directory must be present somewhere in the source. An input the format
cannot represent is a typed error rather than a silently dropped entry. A name over 255
bytes and a hard link to a directory are two such inputs.

The builder also places device, FIFO, and socket nodes and attaches extended
attributes and POSIX ACLs. `xattr` applies to the entry added just before it, and
an ACL is encoded and attached under its `system.posix_acl_*` name:

```rust
# extern crate ferrosys;
use ferrosys::ext::ondisk::encode_acl;
use ferrosys::{Acl, AclEntry, AclQualifier, Metadata, Timestamp, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let acl = Acl::new(vec![
    AclEntry { who: AclQualifier::UserObj, perm: Acl::READ | Acl::WRITE | Acl::EXEC },
    AclEntry { who: AclQualifier::GroupObj, perm: Acl::READ | Acl::EXEC },
    AclEntry { who: AclQualifier::Other, perm: Acl::READ },
])
.unwrap();
let source = TreeBuilder::new()
    .directory(b"/dev".to_vec(), Metadata::new(0o755, time))
    .char_device(b"/dev/null".to_vec(), 1, 3, Metadata::new(0o666, time))
    .file(b"/ping".to_vec(), b"ELF".to_vec(), Metadata::new(0o755, time))
    .xattr(b"security.capability".to_vec(), vec![0u8; 20])
    .directory(b"/srv".to_vec(), Metadata::new(0o755, time))
    .xattr(Acl::ACCESS_NAME.to_vec(), encode_acl(&acl));
# let _ = source;
```

Each entry's access, change, and modification times default to the one timestamp
passed to `Metadata::new`. `Metadata::with_times` sets them independently. A
fixed-time option on the format call overrides every entry's times for
byte-reproducible output regardless of the source.

With the `tar` feature enabled, an `ArchiveSource` parses a tar archive into the same
entries a `TreeBuilder` produces. The rest of the pipeline is therefore identical. It reads
the archive's PAX timestamps, `SCHILY.xattr.*` attributes, and `SCHILY.acl.*` ACL records.

It has two constructors, and they differ only in where a regular file's *contents*
live. `ArchiveSource::from_reader` takes any stream and reads every body into memory.
`ArchiveSource::from_path` opens the archive itself, records where each body lies, and
reads it only when that file is placed. A format then needs the largest single member
rather than the sum of them all. Both write byte-identical images.

The handles keep the archive open, so it must not be modified in place until the format
finishes. Replacing it by writing a new file and renaming it over the old one is safe,
because the original inode stays readable.

With the `dir` feature enabled, a `DirectorySource` walks a directory tree on this machine
into the same entries. The directory it is pointed at becomes the filesystem root, and
everything under it keeps its path relative to that. What comes across is:

- Modes, ownership, and all three times to the nanosecond.
- Symlinks, recorded and never followed.
- Hard links, and device, FIFO and socket nodes.
- Extended attributes with their POSIX ACLs.

Those ACLs are carried in the version-2 form the syscall boundary speaks, and narrowed by
whichever family the tree is written to.

The metadata and the extended attributes the walk reads are Linux's, so `DirectorySource`
is built on Linux. On another platform the feature compiles and the type is absent, and
`ArchiveSource` is the portable way to describe a tree. Everything else the crate does is
the same everywhere: planning, writing, reading, and scanning.

```rust,ignore
# extern crate ferrosys;
use ferrosys::DirectorySource;
use ferrosys::ext::{FormatOptions, format_to};

// A build that does not run as root records its own uid on every file it walks, so the
// override is what makes the image root-owned.
let source = DirectorySource::from_path("staging/rootfs")?.owner(0, 0);
let out = std::fs::File::create("rootfs.img")?;
format_to(source, 512 << 20, options, out)?;
```

The walk sorts its entries by path and its attributes by name. Where several names share an
inode, the first in that sorted order carries the file and the rest become hard links to
it. The same tree therefore walks to the same entry list, whatever order the host listed
its directories in.

Each file's bytes are read as that file is placed, and no descriptor is held in between. A
tree can hold any number of files, and the peak memory is the largest single one.

The times on those entries are the host's, and two of the three move under the host's feet.
A walk reads every directory and every symlink to learn what it holds, and a host that
maintains access times records that read. Reading a tree is therefore itself enough to
change what the next walk of it records. The change time moves whenever anything sets a
mode, an owner, or a link count, which is what staging a tree does. Only the modification
time tracks the file's contents.

`times_from_modification` is what makes those times the walk's rather than the host's:

```rust,ignore
# extern crate ferrosys;
use ferrosys::DirectorySource;

let source = DirectorySource::from_path("staging/rootfs")?
    .owner(0, 0)
    .times_from_modification();
```

Each entry's modification time then stands in for its access and change times. One tree
therefore walks to one image however many times it has been read or restaged. Every file
keeps the modification time that describes it. That is the clamp for a build that
wants both reproducible bytes and per-file times. `FormatOptions::fixed_time` is the clamp
for one that forces every inode to a single time instead, and gives up per-file times to do
it.

### Composing sources

A `LayeredSource` puts one source over another, so a later layer's entry replaces an
earlier layer's at the same path. This is the shape an image build takes when a base tree
is customized. A root filesystem comes from an archive, configuration goes over it, and
computed files go over that. The layers need not be of the same kind:

```rust,ignore
# extern crate ferrosys;
use ferrosys::{ArchiveSource, DirectorySource};
use ferrosys::LayeredSource;

let source = LayeredSource::new()
    .layer(ArchiveSource::from_path("rootfs.tar")?)
    .layer(DirectorySource::from_path("overlay/etc")?)
    .layer(computed_files);
```

A path in more than one layer takes the last layer's entry whole. Its kind, metadata, and
extended attributes replace the earlier set rather than merging with it name by name.

A directory is the case worth knowing. Naming it again sets its mode, ownership, and times.
Its *contents* are separate entries at their own paths, so the layers' contents merge and a
configuration layer is additive. Replacing a directory with something that is not one is
different. The entries beneath it would have nowhere to live, so they are dropped with it.

Paths are compared as the model compares them, so `/etc/hostname` and `//etc//hostname` are
one path and the second does replace the first. There is no deletion marker. A layer states
what is present, so the result always holds the union of the layers' paths.

A file's contents are a `FileContent`, which is either `Owned` bytes or a `Range` of a host
file. Both coexist in one entry list. That is what lets a caller take an archive-backed
list and replace one entry's contents with bytes it computed. Every other entry stays on
disk.

`TreeBuilder::file` takes anything that converts into one. A `Vec<u8>`, a `String`, a
borrowed `&[u8]`, `&[u8; N]`, or `&str` is copied into the entry. A `FileRange` names host
bytes and reads them when the file is placed. `FileContent::read` hands back a `Cow`. Owned
bytes are therefore borrowed rather than copied, and a format never holds two copies of one
file.

A `FileRange` comes in two forms. `FileRange::new` carries an open descriptor, shared, so
a hundred ranges into one archive cost one descriptor. `FileRange::at_path` carries the
path alone and opens it for each read. That is what lets a source name a range in each of
a hundred thousand separate files. Either way the bytes are read when the file is placed,
so the file must not be modified in place before the format finishes.

## Formatting

`format` takes the source, the image size, and the identity and grow inputs in
`FormatOptions`. The **maximum grow target** sizes the reserved
group-descriptor-table blocks. It is the largest size the image can later occupy:

```rust
# extern crate ferrosys;
use ferrosys::ext::{FormatOptions, GrowReservation, Metadata, Timestamp, TreeBuilder, format};

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
or 4096 bytes), the journal size, and how directory names hash. The hash is an algorithm
and a signedness, which decides whether a name's bytes are read as signed or unsigned. The
image records both, so a reader reproduces a name's hash from the image rather than from
its own host.

The feature set is the source of truth for which family an image is, and a
`Profile` is the two-way lens over it. `FormatOptions::profile(Profile::Ext2)`
seeds the whole set from the ext2, ext3, or ext4 baseline, which is the words `mke2fs -t`
writes, and is chainable from `new`. Set individual features on `feature`
afterward to depart from it. `Profile::of(feature)` names the family a set
classifies to, which is what `Reader::profile` reports for an image on the way
back in.

A feature word is a promise about the structures the filesystem carries. The words and the
bytes written under them therefore have to agree. `FeatureSet::validate` refuses a set that
contradicts itself before any planning happens. Three such sets are these:

- `metadata_csum_seed` without the checksums it seeds.
- `orphan_file` without the journal its entries are written through.
- `resize_inode` at a 4096-byte block without `large_file`, since the resize inode is
  itself a file of 4 GiB.

A source the set cannot describe is refused the same way, and names the entry. Two such
sources are extended attributes without `ext_attr`, and a regular file of
`LARGE_FILE_MIN_SIZE` or more without `large_file`. Nothing is silently dropped and no
feature is silently added.

### Pinning the bytes across versions

Images are byte-reproducible. The UUID, the timestamps, and the hash seed are inputs, so
the same source and the same options write the same bytes, always. That holds across
versions of this crate too, for a feature set that is itself fixed.

`FeatureSet::DEFAULT`, `EXT2`, and `EXT3` are fixed and stay fixed, so pinning to one of
them pins the layout. `FeatureSet::LATEST` deliberately does not. It tracks what a
current `mke2fs` writes for ext4, so it can gain a feature in any release. The bytes
under it change with it. Name `LATEST` when parity with the current tool is what you
want, and `DEFAULT` when reproducible bytes are.

To record exactly what a build resolved to, `FeatureSet::pin` emits the whole set as one
canonical document. It carries every feature word twice over, as exact bits and as readable
names. It also carries the block and inode sizes that a feature-name list would omit:

```text
ferrosys-feature-pin 1
compat 0x0000103c has_journal ext_attr resize_inode dir_index orphan_file
incompat 0x000022c2 filetype extent 64bit flex_bg metadata_csum_seed
ro_compat 0x0000046b sparse_super large_file huge_file dir_nlink extra_isize metadata_csum
block_size 4096
inode_size 256
```

Record it verbatim and compare it string for string on the next build. A difference is
drift in the on-disk layout, surfaced as a diff a person reads rather than as changed
image bytes nobody notices. `FeatureSet::EMPTY` is the base to replay a recorded list of
feature names back through `with_feature`. That is how the readable half of a pin is
checked against the exact half.

The feature set is five of the decisions that move bytes, and not the only five. These move
them too, and none of them appears above:

- The grow reservation.
- The inode count.
- The reserved share.
- The error behavior.
- The journal size.
- The two hash choices.

A build that changed one would therefore produce a different image under an identical
feature pin.

`errors` is the least visible of them. It reaches neither the feature words nor the
geometry, so nothing else records it at all.

Three documents cover the whole format, split by *why each one changes*:

| Document | What it holds | When it changes |
| --- | --- | --- |
| `FormatOptions::policy_pin` | feature set, grow, inodes, reserved, errors, journal, hash choices, whether times are clamped | only when the contract changes |
| `FormatOptions::identity_pin` | uuid, time, hash seed, label, the clamped time | every image, by design |
| `FormatPlan::geometry_pin` | block and inode counts, group table, reserved GDT, journal length | with the filesystem's size |

Each is a self-contained document with its own version line. A builder therefore records
the ones it wants, and never has to slice a section out of a larger one.

**The policy pin is the one to record and compare**. Nothing in it varies with the image.
A builder writing many images from one set of constants therefore gets one policy pin for
all of them. An empty diff between two images' recorded pins therefore says they were built to the
same contract. A non-empty diff always means something changed:

```rust
# extern crate ferrosys;
use ferrosys::ext::Timestamp;
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
drift. An image is *meant* to have its own identity, and a filesystem sized to its
partition is *meant* to have its own geometry. Recording them beside the contract would
therefore make every comparison non-empty and worthless.

The identity pin exists for a caller that wants them anyway. Every field in it is also a
superblock field, so a caller that can open the image it built need not record it at all.

### Pinning what a name means, not just the name

A policy pin records the options *by name*. It moves when an option is renamed or its
default changes. It does not move when the formula behind one changes underneath an
unchanged name. `grow max` reads the same before and after a change to how much `Max`
reserves, while every block after the descriptor table moves.

Planning at a **fixed reference size** and pinning the result is what closes that:

```rust
# extern crate ferrosys;
use ferrosys::ext::{FormatOptions, FormatPlan, Timestamp, TreeBuilder};

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

`reserved_gdt_blocks` is the line to notice. It is the descriptor headroom the grow
reservation sized, and every block after the descriptor table sits where it does because of
it. Pin the two documents together, the policy for the contract and one reference geometry
for what the contract resolves to. That catches both a renamed option and a re-computed one.

The per-group placements are one line rather than one per group. That line is the count,
and a `crc32c` over every field of every group. A filesystem has as many groups as it has
room for, and a large one has millions. The document therefore stays a fixed size, while a
placement that moves still changes it.

Each document's first line carries its version, and that version moves whenever the shape
of the document moves. Two documents that both say `1` always mean the same thing. A
recorded pin that stops matching is therefore a change in what was pinned, and never a
change in how it was rendered.

### Deciding everything before the destination is touched

A format writes only the blocks the filesystem uses, so every byte of the destination it
does not write must already read as zero. Creating the file, or truncating one that is
already there, is therefore part of formatting rather than something done beforehand. A run
that then failed would have destroyed what was at that path for nothing.

`FormatPlan` is the fallible half of a format as a value, and it is what makes that
impossible. `FormatPlan::new` takes the source, the size, and the options, and does every
piece of work that can fail. That is parsing the source, planning the geometry, building the
inode model and checking it against that geometry, and sizing the journal. What it returns
can only be written:

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
a byte is written. That is what a caller reporting a geometry, or deciding whether to
write at all, needs.

Three more fields tune what the size alone would decide, each defaulting to what the
size implies. `volume_name` labels the filesystem, up to sixteen bytes NUL-padded into
`s_volume_name`. `inodes` (an `InodeCount`) sets how many inodes it holds, as a
bytes-per-inode density or an exact count, overriding the size-driven default. A
density past what a group's bitmap indexes is refused rather than reduced. `reserved`
(a `ReservedRatio`) sets the share of blocks held back for the super-user, in exact
hundredths of a percent, defaulting to 5%.

### Sizing the filesystem to what goes in it

`FormatPlan::new` is told how large the filesystem is. `FormatPlan::fit` works it out
instead, from the source:

```rust,ignore
# extern crate ferrosys;
use ferrosys::Slack;
use ferrosys::ext::FormatPlan;

// The smallest filesystem that holds the source, with a fifth of it still free.
let plan = FormatPlan::fit(source, options, Slack::Share(2000))?;
println!("{} bytes", plan.size_bytes());
plan.write_to(std::fs::File::create("rootfs.img")?)?;
```

There is no formula behind it. How much room a filesystem has left depends on four things:

- How many block groups it has.
- How large its inode tables are.
- How many descriptor blocks it reserves to grow into.
- How large a journal its size earns.

Every one of those follows from the size, so the answer is a fixed point. `fit` finds it by
planning candidate sizes and *placing* the source into each one. It uses the format's own
placement pass over a sink that keeps nothing. Nothing is estimated beside the writer. The
part of the writer that decides is what runs.

That is what backs the guarantee: **the size `fit` returns formats, and one block less does
not**. The search closes a bracket whose ends are both established by placing. It ends
holding a size that was placed successfully. It also holds the size one block below that,
which was not.

Fit is not monotone in size. A filesystem one block larger can need another block group,
and so have less room than the one below it. That is therefore *a* smallest size rather
than provably *the* smallest.

`Slack` says how much must be left free once the source is written. The smallest
filesystem holding a source is one with nothing left in it:

| | |
|---|---|
| `Slack::None` | the floor: `plan.size_bytes()` is then the minimum size for this source |
| `Slack::Bytes(64 << 20)` | at least 64 MiB free, rounded up to whole blocks |
| `Slack::Share(2000)` | at least a fifth of the filesystem free, in hundredths of one percent |

The measure is free blocks, the same count `s_free_blocks_count` carries. The super-user
reservation is separate accounting over the same blocks. A filesystem left a fifth free
under the default 5% reservation therefore leaves an unprivileged writer 15% of it.

The source is consumed once and the model built from it is kept, so a fitted plan writes
with no second walk of the source. That is also why there is no `minimum_size` function
taking a source of its own. `FormatPlan::fit(source, options, Slack::None)?.size_bytes()`
is that number, and it hands back the plan that produces it rather than throwing the work
away.

## Streaming a large image

`format` builds the whole image in memory. `format_to` instead writes it to any
seekable destination, touching only the blocks the filesystem uses. The destination
therefore stays sparse, and the image never exists in memory at once. It returns
the `Layout` the bytes realize:

```rust,no_run
# extern crate ferrosys;
use ferrosys::ext::{FormatOptions, GrowReservation, Timestamp, TreeBuilder, format_to};

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
- **A file's contents, while it is placed**. How long that is depends on the source. An
  entry holding `FileContent::Owned` bytes holds them from the moment the source was built,
  so a list of them costs the sum of every file. A `FileContent::Range` is read at
  placement and dropped after, so a list of them costs the largest single file.
  `ArchiveSource::from_path` is what makes that difference for a tar source.
- **The allocator's used-block bitmap**, for the whole run, at one bit per filesystem
  block: `total_blocks / 8` bytes, 128 MiB for a 4 TiB image at a 4 KiB block.

So peak memory grows with the entry count, the largest file, and the block count. It never
grows with the image's size in bytes.

## Formatting a FAT volume

The `fat` module writes FAT12, FAT16, and FAT32. That is the family the EFI System
Partition is, and the one with no POSIX fidelity at all. It is behind the `fat` feature,
which is off by default.

**Which of the three a volume is follows from its cluster count and from nothing else.**
No FAT image records its type. Every driver counts the clusters and compares against two
thresholds. A formatter that computed the count differently from a driver would not
produce a mislabeled filesystem. It would produce one whose every chain resolved somewhere
else. `plan_layout` is therefore where the real work is, and `FatTypeRequest`
states what the derivation must *arrive at* rather than what to write down:

```rust
# extern crate ferrosys;
use ferrosys::fat::{FatType, FatTypeRequest, PlanRequest, plan_layout};

// A 512 MiB volume, laid out the way convention lays one out.
let layout = plan_layout(&PlanRequest::new(512 << 20))?;
assert_eq!(layout.fat_type, FatType::Fat32);

// Every field is a decision a materializer obeys, and they agree with each other:
// the cluster count is exactly what a driver derives from the rest.
let derived = (layout.total_sectors - layout.first_data_sector) / layout.sectors_per_cluster;
assert_eq!(derived, layout.clusters);

// A type the geometry cannot reach is a typed error rather than a near miss.
let too_small = PlanRequest::new(8 << 20).fat_type(FatTypeRequest::Exactly(FatType::Fat32));
assert!(plan_layout(&too_small).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

`format` and `format_to` write the volume. They take the same `Source` the ext writer does,
so one tree feeds either family unchanged:

```rust
# extern crate ferrosys;
use ferrosys::fat::{
    ClusterSize, FatType, FormatOptions, PlanRequest, Timestamp, VolumeLabel, format,
};
use ferrosys::{Metadata, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .directory(b"/EFI".to_vec(), Metadata::new(0o755, time))
    .directory(b"/EFI/BOOT".to_vec(), Metadata::new(0o755, time))
    .file(b"/EFI/BOOT/BOOTX64.EFI".to_vec(), b"MZ...", Metadata::new(0o644, time));

let options = FormatOptions::new(0x1234_abcd, time)
    .label(VolumeLabel::new("ESP")?)
    // A 2 KiB allocation unit. The request's own size is ignored — the size `format`
    // is asked for is the size it plans against.
    .plan(PlanRequest::new(0).cluster_size(ClusterSize::Sectors(4)));

let image = format(source.clone(), 64 << 20, options)?;
assert_eq!(image.layout().fat_type, FatType::Fat16);
assert_eq!(image.as_bytes().len(), 64 << 20);

// Root-owned with conventional modes and no links: nothing was lost putting it here.
assert!(image.fidelity().is_faithful());

// Two formats of the same tree are the same bytes: the serial number and the times
// are inputs, never read from the clock, and entries are placed in sorted order.
assert_eq!(image.as_bytes(), format(source, 64 << 20, options)?.as_bytes());
# Ok::<(), Box<dyn std::error::Error>>(())
```

An empty volume is `TreeBuilder::new()`, which places nothing.

`format_to` streams to any seekable destination on the same terms as the ext writer,
writing only the sectors the filesystem occupies. It hands back the `FormatPlan`, which
carries both the geometry and the account of what the format could not hold:

```rust,no_run
# extern crate ferrosys;
use ferrosys::fat::{FormatOptions, Timestamp, format_to};
use ferrosys::TreeBuilder;

let file = std::fs::File::create("esp.img")?;
let options = FormatOptions::new(0x1234_abcd, Timestamp::from_secs(0));
let plan = format_to(TreeBuilder::new(), 512 << 20, options, file)?;
assert_eq!(plan.layout().total_bytes(), 512 << 20);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`FormatPlan::new` is the same work without the write. It is for a caller that wants to know
whether a build will succeed, and what it will cost, before touching the destination.

Six things about the format are worth knowing before choosing parameters.

### The volume label is a value, not a string

It is stored twice, in the boot sector and as an entry in the root directory. It lives in a
directory entry's name field, so it is eleven bytes, upper-cased, and cannot contain the
separators DOS reserved. `VolumeLabel` holds those rules in one place.

A volume with no label carries the `NO NAME` placeholder in its boot sector, and no entry
at all. That is how a driver reports it as unnamed.

### Times are 1980 to 2107, at a two-second granularity

A FAT directory entry stores a date and a time in two sixteen-bit words, counting years
from 1980, and the seconds field counts two-second units. An instant outside that range is
a typed error rather than a value truncated into a plausible-looking one. The conversion is
UTC, so an image's bytes do not depend on where the machine that wrote it thinks it is.

### The allocation unit stops at 32 KiB

The format's own guidance is that a cluster of 64 KiB or more misbehaves. More than one
widely deployed driver holds a cluster's byte count in sixteen bits. A pinned cluster past
that is refused, and `ClusterSize::Auto`'s search stops there. A volume that no type fits
below the cap is therefore an error, rather than a cluster a driver will truncate. Reading
has no such limit.

### Two cluster counts cannot be written unambiguously

A volume of 4085 or 4086 clusters is FAT16 to the specification and to Linux, and FAT12 to
Windows. A file allocation table is a packed array whose entry width differs between the
two. One of those readers therefore resolves every chain past the second cluster to
nonsense. Nothing written into an image settles it, because no driver reads a type from an
image.

So the planner never emits one. It declares the largest count no driver disputes, and
leaves the few clusters between unused. A request for FAT16 at such a count is a typed
error naming the range. Stepping down would produce a FAT12, and there is nothing else to
move.

### Names, and why an unrepresentable one is refused

Names are what a file is found by, so an unrepresentable one is refused rather than
substituted. Every name is stored as a long name unless it is already exactly its own 8.3
short name. What a driver shows is therefore what was asked for.

The two case bits Windows NT put in byte 12 of a directory entry are left zero. The
format's own specification says that byte is reserved and must never be read. A name
carried only there reads back upper-cased on a driver that takes it at its word.

A name is a typed error in four cases:

- It is not valid UTF-8.
- It is longer than 255 code units.
- It contains a path or wildcard separator.
- It ends in a dot or a space.

Two names in one directory that differ only in case are refused as well. A FAT lookup
ignores case, so they are one name to every driver that reads the volume.

### What a FAT volume cannot represent

Everything a FAT volume cannot represent is refused until the caller says otherwise.
Ownership, permission bits, the set-user-id bits, symbolic links, second names for a file,
device nodes, and extended attributes have no field at all. A build that would lose one of
those fails, naming the entry and the property, until it is named in an `AcceptedLoss`. The
`FidelityReport` then says exactly what went, entry by entry.

A property counts as lost when the value a read gets back is not the value that was stated.
That is narrower than "the format has no field for it". A tree owned by root with `0644`
files and `0755` directories goes in and comes back out unchanged. Those are the values
`Synthesis` fills in for a filesystem that records none.

```rust
# extern crate ferrosys;
use ferrosys::fat::{FormatOptions, Timestamp, format};
use ferrosys::{Direction, Metadata, Property, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .file(b"/plain".to_vec(), b"x", Metadata::new(0o644, time))
    .file(b"/run.sh".to_vec(), b"#!/bin/sh\n", Metadata::new(0o755, time));

// The executable bit has nowhere to go, so the build refuses and names it.
let options = FormatOptions::new(0x1234_abcd, time);
assert!(format(source.clone(), 8 << 20, options).is_err());

// Accepted, it goes through and the report accounts for it.
let options = options.accept_loss(Property::Permissions);
let image = format(source, 8 << 20, options)?;
assert_eq!(image.fidelity().count(Direction::Dropped, Property::Permissions), 1);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Two shapes of entry behave differently from each other, and the asymmetry is deliberate.

**A hard link is written as a second copy of its file**. Its target is named inside the
`Source`, so resolving it reads nothing the crate was not given. `FormatPlan` is where the
size that costs is a number to read, rather than one to discover.

**A symbolic link is never followed**. Its target is an arbitrary path. Resolving one would
copy whatever it happens to point at into the image. It leaves no entry behind, and
neither do device nodes, named pipes, and sockets.

## Reading

The `Reader` opens over an image's bytes and parses it back. It walks the directory
tree from the root (inode 2), and returns file and symlink contents:

```rust
# extern crate ferrosys;
use ferrosys::ext::Timestamp;
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
  it read, short only at the end of the file. It maps a window of the file at a time.
  Reading the last megabyte of a large file therefore builds no whole mapping first.
- **`read_data_to(&inode, writer)`** streams the whole file to any `Write`, a window at a
  time, and returns the byte count. Peak memory is the window, whatever the file's size.
- **`walk_with(|reader, entry| …)`** walks the tree lazily, handing each entry to the
  callback as it is reached rather than collecting the whole listing first. The callback
  receives the reader, so it can read each file as it walks. It is generic over the
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

`walk` collects the whole listing into a `Vec`. It is what to reach for when the tree,
rather than its contents, is the subject. `walk_with` holds only the *frontier*, which is
the names reached and not yet visited, each a path and an inode number. What it costs
therefore follows the shape of the tree rather than its size.

It is a frontier and not a fixed set, so a directory holding a million names puts a million
paths on it. Those names answer to the same bound the visited ones do. `Limits::max_walk_entries`
and the image's own storage therefore bound what a walk finds as well as what it yields.

With the `tar` feature enabled, `ArchiveSink` is that loop already written.
`ArchiveSink::new(writer).write_tree(&mut reader)` streams the whole filesystem out as a
tar archive, with each member's body streamed rather than buffered. Ownership, modes, times
to the nanosecond, symlinks, hard links, device and FIFO nodes, extended attributes, and
POSIX ACLs are all carried in PAX records.

An archive that makes the round trip through `ArchiveSource` describes the same filesystem
at both ends. A socket has no tar entry type at all. A filesystem holding one is therefore
a typed error, rather than an archive quietly missing a file.

### Writing the tree back out

With the `dir` feature enabled, on Linux, `DirectorySink` is the same thing as a tree on
this host rather than as an archive. It is the inverse of `DirectorySource`:

```rust,ignore
# extern crate ferrosys;
use ferrosys::{DirectorySink};
use ferrosys::ext::{Reader};

let mut reader = Reader::open(std::fs::File::open("rootfs.img")?)?;
std::fs::create_dir("unpacked")?;
let report = DirectorySink::new("unpacked")?.write_tree(&mut reader)?;
println!("{} names written", report.written);
```

The destination must exist and be empty. It takes the filesystem root's own mode,
ownership, times, and extended attributes, and everything the filesystem holds appears
beneath it. `/lost+found` is omitted, so the tree is one `DirectorySource` reads straight
back. A file's bytes are streamed a window at a time, so a tree far larger than memory
costs a working set.

**The image is untrusted, and a name in it is not a path to resolve**. Every directory is
created and then opened. Everything beneath it is created through that open handle by its
single-component name. That name is checked to be one a directory can hold. A name carrying
a separator, a `..`, or a NUL is therefore `HostError::HostileName`, rather than a write
somewhere else.

It is the second of two checks. A reader refuses such a name where it resolves it, so no
walk hands one over in the first place. Symbolic links are written exactly as recorded,
absolute targets included. That is safe because nothing here ever follows one: every handle
is opened `O_NOFOLLOW` and every attribute is set on the link itself.

The destination is resolved once. The handle is taken first and both questions asked of it,
which are that it is a directory and that it holds nothing. What a sink accepted and what it
writes into are therefore one object.

A directory's mode, ownership, and times are applied once its children are in place. A
directory the image records as read-only is therefore still one its contents could be
written into. One the image records *without owner-search permission* waits until the whole
walk is done. A second name for a hard-linked node is created by traversing to the first,
and a directory that cannot be searched cannot be traversed. That is what makes an
unprivileged extraction of such a tree succeed rather than fail part-way with a bare
`EACCES`.

Four parts of a tree take privileges:

- A device node needs `CAP_MKNOD`.
- Setting a recorded owner needs `CAP_CHOWN`.
- An extended attribute in the `security` or `trusted` namespace is the host's to write.
- A destination filesystem with no notion of a second name for a node refuses a hard link.

By default a host that refuses any of them is `HostError::Unprivileged`, naming the entry.
`skip_privileged` is the opt-in for an unprivileged extraction. What it left out comes back
in the `ExtractReport` rather than in silence, as `skipped`, `ownership_dropped`, and
`xattrs_dropped`.

A file's contents are written as the filesystem reports them, and a hole reads as zeros. A
sparse file therefore lands in the destination fully allocated.

Two times no extraction can carry, because no host lets a caller set them. They are an
inode's **change time** and its **creation time**. Access and modification times are set
exactly, to the nanosecond.

### Filesystems other tools made

The reader reads any conformant ext image, whatever tool wrote it. It follows the
on-disk format, so an image `mke2fs` or the kernel produced reads the same as one
this crate wrote:

- **Any inode size**. The 128-byte inode has no extended area, so it carries no
  creation time, no sub-second timestamps, and no `i_checksum_hi`. Every field past
  the classic inode is read only when the inode actually holds it. That is the same
  condition the kernel applies. The reserved inodes of a filesystem another formatter
  wrote declare no extended area. They therefore verify against the low half of their
  checksum alone.
- **Either mapping**. An inode flagged for extents roots an extent tree. Every other
  inode uses the classic direct/indirect block map, with a zero pointer standing for a
  hole at any level. ext2 and ext3 map every file that way.
- **Checksums verified against the object's own bytes**. A field the filesystem carries
  and this crate does not model is part of the checksum it was part of when it was
  computed. `l_i_version`, which the kernel bumps on every inode update, is one such
  field, and the superblock's error record is another.

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

A `..` component ascends to the directory the resolution came from, whether a caller
wrote it or a symbolic link in the image stores it. `/usr/lib64 -> ../lib` is the shape
a multiarch root filesystem has, and reaching what it names means leaving `/usr` and
coming back down. At the root there is nothing to ascend to, so a run of them stays there.

**Every path names something inside the image, and no resolution reaches the host that is
reading it.**

```rust,ignore
# extern crate ferrosys;
let (_, direct) = reader.lookup(b"/usr/lib/modules")?;
// The same directory, reached by ascending out of `/usr/bin` and back down.
let (_, ascended) = reader.lookup(b"/usr/bin/../lib/modules")?;
assert_eq!(direct, ascended);
// And a run of them at the root stays at the root.
assert_eq!(reader.lookup(b"/../..")?.0, reader.lookup(b"/")?.0);
```

`walk` yields the literal tree and does not descend through links. On a merged-`/usr`
layout the paths under `/lib` therefore appear only under `/usr/lib`. `lookup` is
what reaches them by the name a system actually uses.

### Checking an image

`scan` walks the whole image and reports every deviation it finds as a structured
`Anomaly`, rather than stopping at the first. Five such deviations are these:

- A checksum that does not match.
- A reference out of range.
- A structure that does not parse, or whose counts contradict each other.
- An inode carrying a structure its superblock's feature words deny.
- A directory entry naming an inode the filesystem does not have.

It reports what is wrong, and does not refuse the image. `verify_checksums` is the strict
counterpart, failing on the first object whose stored checksum does not match its
recomputed value.

`scan` is the path to point at an image you have no reason to trust. Every allocation it
makes is bounded by the bytes the source holds, rather than by a count the image claims.
The groups and inodes it walks are capped at what the source can physically hold. Each
metadata block is read once, however many references name it. The findings stop at
`Limits::max_findings`, which is `FindingReport::MAX_FINDINGS` unless you set another, and
`ScanReport::is_truncated` records that they did.

A truncated report is a floor. The image holds at least these findings, and
`worst_severity` and `has_fatal` are floors too. `is_clean` is false whatever the report
holds, since a scan that stopped short never saw enough to call an image clean.

`walk` is bounded the same way. A well-formed filesystem spends at least a directory
record's worth of its own blocks per name. The source's length therefore bounds how many
names it can describe. Reaching that bound is an error rather than a short list. A caller
extracting a tree from a truncated walk would write an incomplete one and see success.

An `ext::ScanReport` is the crate's `ScanReport` over ext's own taxonomy, kept typed. An
`Anomaly` names the subsystem as a `Category` value, and its place as a `Location` of group,
inode, and block. That is what a consumer reasoning about ext4 acts on.

`to_report` projects it into the crate's `FindingReport`, which is the frame every family
shares. That frame is a `Severity`, the `Family` that found it, and that family's own word
for the subsystem. It is also the byte offset and that family's own named coordinates. It
is what renders, to JSON, to a fixed-column table, and to a SARIF log. There is one
document shape and one severity scale however many families a build carries.

The JSON document opens with a `schema` field holding `FINDINGS_SCHEMA_VERSION`. A
downstream parser depends on the emitted shape, and no Rust signature describes it, so the
shape names its own version.

Every name a finding or an error carries came off the image. A filesystem name can hold
anything a terminal acts on: an escape sequence, a carriage return, a direction override. A
directory named `\x1b[2J\x1b[1;1Hno findings\x1b[0m` would otherwise put a forged clean
report on the screen of whoever read the report.

So a name is escaped where it is interpolated, which is the last point anything can tell it
from the words around it. Both renderings are public for a caller whose own output names
the same bytes. `printable` is for text a person reads, and `push_json_string` for a JSON
string literal.

### The filesystem's own boundary

An ext filesystem usually occupies a partition, or the region of a larger file that `base`
names. The bytes after its final block belong to something else.

**Every reference the reader follows is bounded by the filesystem's own block count before
any of it is read**. That covers these:

- A group descriptor's bitmaps and inode table.
- An external extent node.
- An attribute block.
- Every pointer in a classic block map.
- The table bytes an inode is read from, bounded through the block the inode's *last* byte
  falls in.

A reference past the end is a `ReadError::OutOfRange`, and a scan's structural finding
under the subsystem that named it.

That is a different bound from the source's length, and both are kept. The block count says
which bytes are the filesystem's, and the source's length is what a truncated image runs
out of. Bounding by the source alone would let a crafted image read whatever follows it
back as its own metadata. Nothing in the image would say otherwise. What follows it is a
neighboring partition, or the rest of a disk. That is the read the block count rules out.

The source's length here is the length from `base` on, measured once when the filesystem is
opened. That is the filesystem's share of the source. A 16 MiB partition at the end of a
2 TiB disk image is bounded by the 16 MiB that could hold it. It is not bounded by
everything in front of it. A source that cannot report its own end fails the open.
Answering zero would leave every bound built on it satisfied by a filesystem with nothing
in it.

The references an image makes to its own inodes are bounded the same way. A directory entry
naming an inode past `s_inodes_count` is `ReadError::DirEntryNoSuchInode` where the entry is
read. A listing therefore never carries a name that resolves to nothing, and a scan reports
the directory holding it.

### Opening options

`Reader::open` reads from the start of a source, strictly, with the default limits.
`Reader::open_with` takes an `OpenOptions` carrying everything else:

- Where the filesystem begins within the source, which is a partition offset.
- The `ReadPolicy` to hold it to.
- A `Limits` capping what one read can allocate.
- A `metadata_csum` seed to verify against, where the image's stored seed and UUID no
  longer agree.

The first three are the crate's own `OpenOptions`, held in a `common` field rather than
restated. An input every family takes is therefore named in one place, and reaches every
family at once. The builders below set through it, so a caller writes the same thing either
way.

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
mapping a read builds as well as the buffer it returns. The mapping costs eight bytes per
logical block against one byte per byte returned. On the crafted `i_size` the cap exists
for, it is therefore the larger of the two.

A file past the cap is a `ReadError::FileTooLarge` naming the size and the bound, rather
than a short read. A truncated file that looked like a whole one would be the worse outcome
by far. A caller extracting a tree would write it out, see success, and carry a silently
incomplete file forward.

The cap governs every whole-file form, in every family. `read_data` returns a buffer, and
`read_data_to` streams into a writer of yours and allocates nothing. That second one needs
the cap most, not least. What it *writes* follows the length the image declares. A region an
image says is allocated and unwritten reads back as zeros, without a block or a cluster being
touched. A length nobody bounded is therefore bytes nobody bounded, however small the working
buffer producing them.

To read part of a large file deliberately, read into a buffer of your own. `read_into` is
bounded by the buffer and reports how much of it was filled, so a partial read is
representable rather than silent.

## Reading a FAT volume

`fat::Reader` is the FAT family's counterpart to `ext::Reader`. It reads any conformant
FAT volume with one or two allocation tables, whatever wrote it. That is the count
`fsck.fat` supports, and the one a mirror comparison is defined against.

It derives the type from the geometry the way every driver does. It follows cluster chains,
reassembles long names from the entries that carry them, and streams file contents:

```rust
# extern crate ferrosys;
use ferrosys::fat::{FormatOptions, Reader, Timestamp, format};
use ferrosys::{Metadata, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .directory(b"/EFI".to_vec(), Metadata::new(0o755, time))
    .directory(b"/EFI/BOOT".to_vec(), Metadata::new(0o755, time))
    .file(b"/EFI/BOOT/BOOTX64.EFI".to_vec(), b"MZ\x90\x00".to_vec(), Metadata::new(0o644, time));
let image = format(source, 512 << 20, FormatOptions::new(0x1234_abcd, time))?;

let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes()))?;
let node = reader.lookup(b"/EFI/BOOT/BOOTX64.EFI")?;
assert_eq!(reader.read_data(&node)?, b"MZ\x90\x00");

// The geometry comes back as the same value the planner produces, so a format and a read
// of the result describe one filesystem rather than two that happen to agree.
assert_eq!(reader.layout(), image.layout());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The vocabulary differs from ext's, because the formats do. A `Node` is a handle to what a
directory entry describes, and carries no number. FAT has no inodes, so nothing would
distinguish a file from a second name for it. The format has no second names.

A `Node`'s `Storage` is a cluster chain, or the fixed region a FAT12 or FAT16 volume
reserves for its root, or nothing at all. That last is what an empty file owns. Its `times`
are an `Option`, because the root directory has no entry on any type and so no times to
read.

`read_dir` hands back an `Entry` carrying both the name and the short name, and
`has_long_name` saying which the volume actually stored. A name that is already its own
8.3 short name needs no long-name entries and gets none. Anything else is stored in
long-name entries and pairs with a generated short name, whether it is lower case, longer,
or punctuated differently.

**Every name it hands back is one a directory can hold**. A name resolving to `.` or `..`
is `ReadError::HostileName` rather than an entry in the list. So is one carrying a path
separator or a NUL. That is an error under `ReadPolicy::Strict`, and a `Severity::Structural`
finding a scan collects under `Lenient`.

The refusal is at the one place an entry's bytes become a name, so it holds for everything
downstream at once. That is the entry list, the paths a walk builds, and an archive or a
tree written from them. The dot entries the format requires are a separate matter. They are
recognized by their eleven-byte name field, which is where the format defines them, and are
simply not entries in the tree.

This is a rule about untrusted input rather than about damage. Neither field a name arrives
in rules such a name out. A long name is UTF-16 and can spell anything, and a short name is
eleven bytes the image chooses. A crafted volume controls every byte of a long-name run,
the ordinal and the checksum included. A run can therefore be perfectly well formed and
still spell `..`. A reader that built a path from one would be the component that produced
the traversal.

**A path resolves however its letters are cased**. `lookup` matches a component exactly
first. Failing that, it matches without regard to the case of its ASCII letters, which is
how every FAT driver finds a name. Bytes above ASCII are compared as they stand, for the
reason below.

### Short names above ASCII

An eleven-byte short name is bytes in whatever code page the machine that created the entry
was running under.

**Nothing in a FAT volume records which one**. `BS_OEMName` names the formatter rather than
a code page. The format's own specification says never to interpret it. The page was a
property of the machine and the moment each name was created. One directory therefore
legitimately holds names written under two of them.

So the page is an input and is never guessed. `ShortNameCharset::Verbatim`, the default,
hands the bytes back exactly as they sit on disk. Naming a page interprets them:

```rust
# extern crate ferrosys;
use ferrosys::fat::ShortNameCharset;

// A disk from the DOS era, read as the IBM PC character set. `decode` is what a name
// goes through, so what a page does to a byte is checkable without an image.
assert_eq!(ShortNameCharset::Cp437.decode(b"CAF\x82.TXT"), "CAFé.TXT".as_bytes());
assert_eq!(ShortNameCharset::Cp866.decode(b"CAF\x82.TXT"), "CAFВ.TXT".as_bytes());

// The default interprets nothing, so the same byte comes back as itself.
assert_eq!(ShortNameCharset::Verbatim.decode(b"CAF\x82.TXT"), b"CAF\x82.TXT");

// And `Reader::open_with` is where one is named:
// OpenOptions::new().charset(ShortNameCharset::Cp437)
```

Five single-byte pages are built in:

- `Cp437`, the original IBM PC set, and the OEM default in the United States.
- `Cp850`, Western Europe.
- `Cp852`, Central Europe.
- `Cp865`, Nordic.
- `Cp866`, Cyrillic.

`Custom(&'static [char; 128])` reaches any other single-byte page without waiting for a
release. The double-byte pages are not among them. A lead byte selects a second table for
the byte after it. Reading one is therefore a state machine over the name, rather than a
lookup per byte. Read such a volume under `Verbatim`, and transcode the bytes it hands
back.

Naming a page also changes what a strict read does. A byte above ASCII the reader cannot
interpret is a conformance deviation, and `ReadPolicy::Strict` stops at it. The same byte
with a page named is a cosmetic remark, and a strict read carries on. The severity tracks
whether the reader recognized what it saw, which is the only thing naming a page changes
about the bytes.

Long names take no such input. They are UTF-16, which is unambiguous, so there is nothing
for a caller to steer. A unit with no partner is replaced by U+FFFD and reported.

### Checking a FAT volume

`fat::Reader::scan` is the family's whole-volume pass, and what it audits is what a FAT
volume has to audit. There are no checksums anywhere in the format, so the file allocation
table's copies standing in for one is the closest thing. Two copies of one allocation record
that disagree mean at least one is wrong, and nothing in the volume says which. That is
reported at the same severity a failed ext checksum is. `verify_tables` is the strict
counterpart, failing at the first entry two copies disagree about.

Past that it checks the parameter block against itself, the backup boot sector against
sector 0, and the information sector's hints. It checks every directory entry for five
things:

- A long name whose checksum does not tie it to the entry it precedes.
- A run that is not whole.
- A name no directory could hold.
- A first cluster outside the volume.
- A `.` or `..` that is not what the format requires.

It checks every cluster chain for a loop, and for a cluster two chains both claim. It also
checks for clusters that are marked allocated and reached by nothing at all. That last one
needs the whole allocation rather than any single structure. A scan therefore carries one bit per
cluster, which is a thirty-second of one copy of the table on any volume. The count is held
at open to what the type addresses, so that is 32 MiB at the very largest FAT32 there is.

A `fat::ScanReport` is the same `ScanReport` an ext scan produces, over FAT's own anomaly.
The report itself, its cap, what truncation means, and the `to_report` projection into
`FindingReport` are therefore one implementation rather than two that agree.

What is FAT's own is the taxonomy inside it. Its `Category` is the boot sector, the
information sector, the allocation table, or a directory. ext's vocabulary means nothing
about a FAT and the reverse. Its `Location` is a cluster, a sector, and an entry.

The same is true of the walk underneath both readers. The frontier, the cycle check, and the
three bounds that keep a hostile tree from running a walk without end are one driver. Each
family supplies what sits on its frontier, what identifies one of its directories, and how a
name's children are read.

Four smaller rules are shared the same way, and each of them is one a second implementation
could drift on without ever failing.

**Which components a path has** is one rule. `/etc/hostname`, `//etc//hostname`, and
`etc/./hostname` are therefore one path to a resolution, to a model placing entries, and to
a caller keying them outside one.

**Which names a directory can hold** is one rule with two strengths. A name is never empty,
and never carries a separator or a NUL. A name about to become a *component of a path* is
never `.` or `..`. ext asks the first, because an ext directory genuinely holds those
two as entries and a listing without them would not be the directory. A FAT volume and a
directory extraction ask the second, because by the time either has a resolved name there is
no legitimate `.` left.

**Turning a block or a sector number into a byte offset** is one checked multiplication and
one checked addition. A number an image supplied therefore cannot wrap into a small offset
and read whatever sits there.

**An i/o failure records its kind beside its message** in every error type that carries one.
A caller therefore tells a truncated image from an environment failure without matching on
text.

**A strict read accepts every volume this crate's own writer produces**, at every parameter
set it accepts. That is the line the severities are drawn against. It is why an undersized
FAT32, which the writer emits on request, is a cosmetic remark rather than a refusal.

## Planning an exFAT volume

Behind the `exfat` feature, `ferrosys::exfat` supplies the formatter, the geometry planner,
the byte-exact on-disk structures, and the classifier that recognizes such a volume.
`plan_layout` derives every field the format records from three inputs. Those are how large
the volume is, how large a sector is, and how large an allocation unit is:

```rust
# extern crate ferrosys;
use ferrosys::exfat::{ClusterSize, PlanRequest, plan_layout};

// A 512 MiB volume, formatted the way convention formats one.
let layout = plan_layout(&PlanRequest::new(512 << 20))?;
assert_eq!(layout.bytes_per_cluster, 32 << 10);

// Every field agrees with the others: the heap's clusters end within the volume, and the
// allocation table has an entry for each of them and for the two reserved numbers.
let heap = u64::from(layout.cluster_heap_offset) * u64::from(layout.bytes_per_sector);
let used = heap + u64::from(layout.cluster_count) * u64::from(layout.bytes_per_cluster);
assert!(used <= layout.total_bytes());
let entries = u64::from(layout.fat_length) * u64::from(layout.bytes_per_sector) / 4;
assert!(entries >= u64::from(layout.cluster_count) + 2);
# Ok::<(), ferrosys::exfat::GeometryError>(())
```

The layout also says where the three residents a format writes land in the cluster heap.
Those residents are the allocation bitmap, the up-case table, and the root directory. They
are not fields the boot sector records. A volume's root directory is what names them, and
where each sits is a function of the cluster size. That is why the root directory's own
cluster number moves between two volumes of different shapes.

Pinning the allocation unit moves everything behind it:

```rust
# extern crate ferrosys;
use ferrosys::exfat::{ClusterSize, PlanRequest, plan_layout};

let dense = plan_layout(&PlanRequest::new(512 << 20).cluster_size(ClusterSize::Bytes(512)))?;
assert_eq!(dense.cluster_count, 1_038_336);
// A bitmap of a million bits spans many clusters, so the up-case table starts well into
// the heap rather than immediately behind it.
assert_eq!(dense.upcase_cluster, 256);
assert_eq!(dense.first_cluster_of_root, 268);
# Ok::<(), ferrosys::exfat::GeometryError>(())
```

The other knob is `BoundaryAlign`, which is where the allocation table and the cluster heap
each begin. It is a placement decision rather than a recorded field, and it shows up in the
two offsets a boot sector *does* record. It defaults to one mebibyte, which is what aligns
the regions to the erase block of the medium removable storage usually is.

It is a byte quantity rather than a sector count. The table begins 2048 sectors into a
volume with 512-byte sectors, and 256 sectors into one with 4096-byte sectors. Both are the
same place.

### Writing an empty volume

`exfat::format` lays down a volume of the planned geometry and hands back the bytes.
`exfat::format_to` writes the same bytes to any seekable destination without ever holding
them all. A volume far larger than memory is therefore created into a file that stays
sparse.

Only the sectors the filesystem occupies are written, and nothing is read back from the
destination. Every byte the destination holds that the format does not write must therefore
already read as zero. A freshly created file, or one truncated to zero length, satisfies
that.

```rust
# extern crate ferrosys;
use ferrosys::exfat::{FormatOptions, VolumeLabel, format};
use ferrosys::TreeBuilder;

let options = FormatOptions::new(0x1234_abcd).label(VolumeLabel::new("CARD")?);
let image = format(TreeBuilder::new(), 64 << 20, options)?;

assert_eq!(image.as_bytes().len(), 64 << 20);
assert_eq!(image.layout().bytes_per_cluster, 4 << 10);

// Two formats of the same parameters are the same bytes.
assert_eq!(
    image.as_bytes(),
    format(TreeBuilder::new(), 64 << 20, options)?.as_bytes()
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`TreeBuilder::new()` places nothing, which is what makes this an empty volume. Anything that
implements `Source` goes in the same argument, and the next section is what that looks like.

What a volume records is what was laid down. Both boot regions go out, the main one at
sector 0 and its backup twelve sectors behind it, each with its own computed checksum
sector. The allocation table gets the two entries the format reserves, and a chain for each
of the three residents. The cluster heap gets the allocation bitmap, the up-case table, and
the root directory describing both.

The root directory's four slots are the volume label, a reserved slot, the allocation
bitmap's describing entry, and the up-case table's, in that order. Two of those are worth
knowing about:

- **A volume with no name still carries a label entry**, with a character count of zero.
  `VolumeLabel::UNNAMED` is that entry, and it is what `FormatOptions` defaults to. exFAT has
  no state in which the root directory lacks one.
- **The reserved slot is a volume GUID entry with its in-use bit cleared**, which every
  implementation writes and which is *not* the end of the directory. An exFAT directory ends
  at a zero type byte and nowhere else, and the allocation bitmap and the up-case table are
  behind that slot. A reader that treated a cleared in-use bit as a terminator would find
  neither, on a perfectly conformant volume.

Reproducibility costs this family one input. The volume serial number is the only value a
formatter would conventionally draw from the clock, and it is a `FormatOptions` field. An
empty exFAT volume records no time anywhere. A label, a reserved slot, a bitmap and an
up-case table have no time field between them.

A label is up to eleven UTF-16 *code units*. That is eleven characters only for characters
the Basic Multilingual Plane holds, since an emoji is a surrogate pair and costs two. A
label that does not fit is refused rather than cut short at a boundary that might fall
inside a pair.

### Writing a populated volume

The same call takes a tree. Every file becomes a *set* of directory entries covered by a
single checksum. A set that was half written is therefore detectable rather than merely odd.
That set is one file entry, one stream extension, and one name entry per fifteen UTF-16 code
units.

```rust
# extern crate ferrosys;
use ferrosys::exfat::{FormatOptions, VolumeLabel, format};
use ferrosys::{Metadata, Timestamp, TreeBuilder};

let time = Timestamp::from_secs(1_426_325_212);
let source = TreeBuilder::new()
    .directory(b"/DCIM".to_vec(), Metadata::new(0o755, time))
    .file(b"/DCIM/IMG_0001.JPG".to_vec(), b"\xFF\xD8\xFF", Metadata::new(0o644, time))
    .file(b"/README.TXT".to_vec(), b"hello\n", Metadata::new(0o644, time));

let options = FormatOptions::new(0x1234_abcd).label(VolumeLabel::new("CARD")?);
let image = format(source, 64 << 20, options)?;

// Root-owned, conventionally moded, and no links: nothing was lost putting it here.
assert!(image.fidelity().is_faithful());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Three things about that are worth stating, because each is a place exFAT differs from the
format it shares a name with.

#### A name is stored whole

A name is up to 255 UTF-16 code units, in the case it was given. There is no second
shortened name to derive, and no numeric tail to resolve a collision with. A name the format
cannot hold is a typed refusal naming the path, never a truncation. Such a name is too long,
or carries one of the nine characters a driver interprets rather than stores.

#### Every stream is contiguous, and says so

A formatter builds a fresh filesystem in one pass with nothing to allocate around, so each
stream sets `NoFatChain`. That flag tells a reader to follow its clusters in order and not
consult the allocation table at all. The table therefore holds chains for three things only:
the allocation bitmap, the up-case table, and the root directory. None of those has a flags
field to declare anything with.

The allocation *bitmap* is what records that a cluster is in use either way. Both come out
of one planned allocation, rather than being maintained separately.

#### A time survives to ten milliseconds

The creation and modification fields each carry a hundredths byte beside their packed date
and time. An odd second is therefore not what a modification time loses. The access field
has no such byte and is granular to two seconds. Each of the three carries a zone offset,
and a volume this crate writes records that its times are UTC. The alternative encoding
means "nobody said", and leaves a reader guessing a locality it has no way to know.

An instant outside 1980–2107 is refused rather than wrapped, for the reason the FAT family
refuses one. A year that overflowed the field's seven bits would land in the 1980s and look
entirely plausible.

#### Two names one directory cannot hold

exFAT compares names through the volume's own up-case table. A source carrying `README` and
`readme` in one directory therefore describes a directory a driver cannot resolve. A lookup
has two answers and returns whichever it met first, leaving the other file unreachable by
its own name. The pair is refused at the model boundary with both paths named.

The comparison is the *volume's* rather than an approximation of it. This crate's writer lays
down `RECOMMENDED_UPCASE_TABLE` and folds through that same table. The comparison a driver
will make is therefore one the writer computed rather than guessed. It matters in both
directions. `ß` and `ss` fold apart on the volume where a host locale would fold them
together. Refusing that pair would refuse a directory every driver reading it can
resolve.

#### What a volume cannot hold

An exFAT entry set records a name, five attribute bits, three times, and two lengths. It has
no field for an owner, a group, or permission bits. It has none for a symbolic link, a second
name for a file, a device node, or an extended attribute.

A tree carrying one of those therefore loses something on the way in. A build that would
lose anything is **refused** until the caller names what it accepts:

```rust
# extern crate ferrosys;
use ferrosys::exfat::{FormatError, FormatOptions, FormatPlan, ModelError};
use ferrosys::{AcceptedLoss, Direction, Metadata, Property, Timestamp, TreeBuilder};

let time = Timestamp::from_secs(1_426_325_212);
let source = TreeBuilder::new().file(
    b"/owned".to_vec(),
    b"x",
    Metadata::new(0o644, time).owned_by(1000, 1000),
);

// Refused by default, and the refusal names the path and the property.
let refused = FormatPlan::new(source.clone(), 64 << 20, FormatOptions::new(1));
assert!(matches!(
    refused,
    Err(FormatError::Model(ModelError::LossNotAccepted {
        property: Property::Ownership,
        ..
    }))
));

// Accepted, and what it cost comes back entry by entry.
let plan = FormatPlan::new(
    source,
    64 << 20,
    FormatOptions::new(1).accepted_loss(AcceptedLoss::NONE.and(Property::Ownership)),
)?;
assert_eq!(plan.fidelity().count(Direction::Dropped, Property::Ownership), 1);
# Ok::<(), Box<dyn std::error::Error>>(())
```

A property counts as lost when the value a read hands back is not the value that was stated.
That is narrower than "the format has no field for it". A root-owned tree with `0644` files
and `0755` directories goes in and comes back out unchanged. Those are exactly the values
`Synthesis` fills in for a filesystem recording none, so it loses nothing and the report says
so.

The one permission bit the format does carry is read-only. It clears the write bits of
whatever mode a driver hands back, so a `0444` file survives too.

A hard link is written as a *second copy* of its file rather than refused. The target is
named inside the same source, so resolving it reads nothing this crate was not already
given. What that costs is the file's size again, which is why `FormatPlan` exists. The
report is readable before the destination is touched, so a caller finds out what a build
will cost rather than discovering it.

### The up-case table

exFAT compares names case-insensitively, and what that means is not a property of Unicode on
the volume's behalf. It is a mapping the volume itself carries, in the cluster heap,
described by a directory entry advertising the mapping's checksum. Two implementations agree
about whether `README` and `readme` are one name exactly when they fold through the same
table.

`exfat::ondisk::RECOMMENDED_UPCASE_TABLE` is the mapping the format recommends, which is what
every current implementation writes and what this crate's formatter lays down. It is checked
against `RECOMMENDED_UPCASE_CHECKSUM`, a value written down rather than derived. A table
checked against arithmetic over its own bytes checks out however badly it was transcribed,
the way a self-signed certificate proves nothing.

### The checksums

Three structures in an exFAT volume carry a checksum and a fourth carries a hash.
`exfat::ondisk` holds all four as pure functions:

- `boot_checksum`, over a boot region's own first eleven sectors.
- `upcase_checksum`, over the case-folding table a volume carries.
- `entry_set_checksum`, over a whole directory entry set.
- `name_hash`, over an up-cased file name.

Every one is a rotate-right-and-add over bytes, at 32 bits for the first two and
16 for the last two.

Two bytes of the boot sector sit deliberately outside its checksum, which are the volume's
state flags and how full it is. A mounted driver rewrites them in place, and would otherwise
have to recompute a checksum over eleven sectors to do it. `BOOT_CHECKSUM_SKIPS` names those
offsets.

They are *stepped over* rather than summed as zero, which is a different answer on every
volume. The accumulator rotates once per byte consumed. Three bytes skipped and three zero
bytes summed therefore leave it in different states. That holds even where all three bytes
are zero, which they are on every volume a format produces.

## Reading an exFAT volume

`exfat::Reader` is this family's counterpart to the other two, and reads any conformant
exFAT volume whatever wrote it. It parses both boot regions and verifies each against its
own checksum. It finds the allocation bitmap and the up-case table by reading the root
directory, and verifies every directory entry set's checksum and every name's hash. It
follows both of the format's run shapes, and streams file contents:

```rust
# extern crate ferrosys;
use ferrosys::exfat::{FormatOptions, Reader, Timestamp, format};
use ferrosys::{Metadata, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .directory(b"/DCIM".to_vec(), Metadata::new(0o755, time))
    .file(b"/DCIM/IMG_0001.JPG".to_vec(), b"\xff\xd8\xff".to_vec(), Metadata::new(0o644, time));
let image = format(source, 64 << 20, FormatOptions::new(0x1234_abcd))?;

let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes()))?;
let node = reader.lookup(b"/DCIM/IMG_0001.JPG")?;
assert_eq!(reader.read_data(&node)?, b"\xff\xd8\xff");

// The geometry comes back as the same value the planner produces — including the four
// fields no boot sector records, which only a reading of the root directory recovers.
assert_eq!(reader.layout(), image.layout());
# Ok::<(), Box<dyn std::error::Error>>(())
```

A `Node` carries no number, for FAT's reason: exFAT has no inodes and no second name for a
file. Its `Storage` is the format's two run shapes and nothing else. That is a run of
consecutive clusters the allocation table says nothing about, a chain through that table, or
no allocation at all. Its `times` are an `Option`, the root directory having no entry and so
no times to read.

### The run shape is declared, and the declaration is binding

A stream's own entry says whether its clusters are consecutive. Where it does, the format
defines that stream's allocation table entries as meaningless. A reader must therefore
follow the clusters in order, and must not consult them. That is not a shortcut a reader
declines. A volume this crate writes leaves those entries free, so a reader that resolved
them anyway would follow zeroes.

Both shapes reach one answer. A walk, a `lookup` and a `read_data` never ask which shape a
file has. The two converge at the point an offset becomes a cluster. A file written
contiguously and the same file rewritten as a chain therefore read back identically.

### The two lengths

An entry records how long a file is and how much of it has been written, and the two differ
on volumes a driver wrote. A driver that extends a file allocates first and writes after.
This crate's formatter never produces the state, because a format writes every byte it
allocates. A card out of a camera routinely carries it, so it is reported at
`Severity::Cosmetic` and a strict read carries on.

What a read hands back between the two is zeros. That region is allocated and nothing ever
wrote it, so what is on the medium there is whatever it last held. Handing that back would
leak it, and every driver answers the same way. A written length *past* the declared one
is the pair contradicting itself rather than a state anything reaches, and that is
structural.

### What bounds a declared length

Both lengths are 64-bit fields an image supplies, and exFAT is the family where a bound on
them exists and costs nothing. The format has no holes, so a stream's bytes *are* its
allocation, and the cluster heap is what any of them could occupy.

A length past the heap is refused as `ReadError::StreamPastHeap`. Under a lenient read the
length the reader answers with is the heap's, so the bound narrows the number and not just
the report. Without it, a `ValidDataLength` of zero beside a declared length of eight
gibibytes is a volume that answers eight gibibytes of zeros. It answers them out of a
sixteen-mebibyte image, without touching a cluster.

A directory is bounded twice more. `exfat::MAX_DIRECTORY_BYTES` is the cap the format puts
on one, and the writer is held to the same number. The traversal also stops at the
end-of-directory marker, which is where the directory ends and where every driver stops. A
directory of two entries declaring the rest of the heap therefore costs one cluster to read
rather than a heap. A length is a number an image supplies. What it costs to believe one is
not.

The whole-file cap a caller sets applies here as everywhere. `read_data` and `read_data_to`
both refuse a file past `Limits::max_file_bytes` before a byte is produced.

### The ranges the format states

The reader checks the structure first: every cluster reference, every chain, every checksum,
and both run shapes. Beyond that it holds each recovered field to the range the format
states for it. It reports the ones outside that range rather than acting on them. A volume
is refused under `ReadPolicy::Strict`, and the deviation is collected under `Lenient`, at
the severity the fault deserves.

| Field | What the format states | What a volume outside it reads as |
|---|---|---|
| `FileSystemRevision` | major 1; a minor above 0 is to be honored | a major other than 1 is refused where the boot sector is judged, so the classifier and the reader answer together; a minor this reader does not know is `UnknownMinorRevision` |
| `DataLength` | at most the cluster heap; at most `MAX_DIRECTORY_BYTES` for a directory, and whole clusters | `StreamPastHeap`, `DirectoryTooLong`, `DirectoryLengthNotClusters` |
| `FirstCluster` with a `DataLength` | a first cluster of zero means a length of zero | `StreamWithoutAllocation` |
| `FileAttributes` | five bits defined, eleven reserved and zero | `ReservedAttributes` |
| `AllocationPossible` | set on every stream extension | `AllocationNotPossible` |
| The three times | a date the calendar has, and hundredths of 0 to 199 | `MalformedTimestamp`, naming which of the three |
| `CharacterCount` | 0 to 11, and a label carries no `U+0000` | `LabelTooLong`; a label holding a NUL is `LabelNulUnit` and `volume_label` answers `None` rather than a name that is not one |
| `NameLength` | the set carries exactly the name entries it needs | `IncompleteEntrySet` short of them, `ExcessNameEntries` past them |
| The root's own entries | one bitmap, one up-case table, one label | `DuplicateRootEntry` inside the root, `MisplacedRootEntry` outside it |
| `PercentInUse` | 0 to 100, or 255 for "not known" | a value between the two is its own remark, distinct from a percentage that is merely stale |
| The extended boot signature | `0xAA550000` ending each of the eight sectors | `BadExtendedBootSignature`, once per region |
| A table entry in a chain | never the bad-cluster mark | `BadClusterInChain`, named as that rather than as a cluster number that is too high |

### Names, and whose idea of case decides them

A name is up to 255 UTF-16 code units, carried fifteen at a time in the entries behind a
file's stream extension, and reassembled whole.

**Every name the reader hands back is one a directory can hold**. A `.`, a `..`, or an empty
name is `ReadError::HostileName` rather than an entry in the list. So is a path separator or
a NUL. Each is refused at the one place an entry's bytes become a name. Nothing about the
field rules any of them out. An exFAT name is UTF-16 and can spell anything, so a crafted volume
can spell `..` in a perfectly well-formed set.

Beside the name, the entry records a **hash of its up-cased form**. A driver compares that
hash to skip a set without reassembling the name in it. The reader recomputes it.

A wrong hash costs no data, and makes the file invisible to every driver that trusts the
field. That is worse than corruption for being silent. It is a failure no checksum covers,
since the set's own checksum is satisfied by a hash and a name that disagree.

The folding both of those go through is **the volume's own**. `Reader::open` reads the
up-case table out of the cluster heap and verifies it against the checksum its describing
entry advertises. It decodes the table's run compression, and folds every comparison and
every hash through it.

A reader that folded through a table of its own would resolve names a driver does not, and
miss names a driver finds. The difference is real rather than theoretical. A volume is free
to carry a table that folds nothing, and its lookups are then case-sensitive.

```rust
# extern crate ferrosys;
use ferrosys::exfat::{FormatOptions, Reader, format};
use ferrosys::{Metadata, Timestamp, TreeBuilder};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .file(b"/README.TXT".to_vec(), b"hello\n".to_vec(), Metadata::new(0o644, time));
let image = format(source, 64 << 20, FormatOptions::new(1))?;
let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes()))?;

// Found through the volume's table, which is the same rule that made `README.TXT` and
// `readme.txt` a pair no directory could have held.
assert!(reader.lookup(b"/readme.txt").is_ok());
assert!(reader.upcase().folded_units() > 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### What a volume must carry, and what is refused outright

The allocation bitmap and the up-case table are found by reading the root directory and
nowhere else. A volume describing neither is one nothing can allocate in, or look a name up
in. That is refused by name rather than answered with an empty tree, under either policy. A
reader that reported a working filesystem there would be wrong in the least visible way.

A volume recording **two allocation tables** is the transaction-safe variant, and is refused
by name too. Which of the two is live is a flag rather than a convention. Treating such a
volume as an ordinary one is therefore a coin toss dressed as an answer.

### Checking an exFAT volume

`scan` reads the whole volume under `ReadPolicy::Lenient` and collects every deviation
rather than stopping at the first. What it checks is this:

- Both boot regions against their checksums, and the backup against the main one.
- The allocation table's two reserved entries.
- Every entry set's checksum, and every name's hash.
- Every cluster the tree occupies, held against the allocation bitmap **in both
  directions**.

That last one is a cluster in use and reached by nothing, and a cluster a stream occupies
that the bitmap calls free. The second of those is worth stating, because no checker reaches
it. `fsck.exfat` objects only when a cluster a file *chains through* is marked free, and a
stream declaring consecutive clusters chains through nothing. A bitmap and a tree that
disagreed about an ordinary file would therefore pass a check on most of a volume.

```rust
# extern crate ferrosys;
use ferrosys::exfat::{FormatOptions, Reader, format};
use ferrosys::{OpenOptions, ReadPolicy, TreeBuilder};

let image = format(TreeBuilder::new(), 64 << 20, FormatOptions::new(1))?;
let mut reader = Reader::open_with(
    std::io::Cursor::new(image.as_bytes()),
    &OpenOptions::new().policy(ReadPolicy::Lenient),
)?;
let report = reader.scan();
assert!(report.is_clean());
assert!(!report.has_fatal(ReadPolicy::Strict));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Two states a driver leaves behind are reported and are not faults. They are a volume it had
open and did not put down, and a medium error it recorded. Both are the format correctly
recording something that happened. The volume is well-formed, and every field is what a
driver is supposed to have written. A strict read of a card somebody pulled out of a reader
therefore still succeeds.

Each message says what the bit means rather than which field held it. "This volume was not
cleanly unmounted" sends a caller somewhere useful, and "`VolumeFlags` is `0x0002`" does
not.

## Reading a btrfs

Behind the `btrfs` feature, `ferrosys::btrfs` reads the btrfs family. It is a different shape
of module from the three above, because btrfs is a different shape of format. The others
address storage directly, where **every address in a btrfs is logical** and something has to
translate it.

So this family has **two public entry points**, and they are the two layers the format has.
`Volume` is the address space and the trees on it: which trees are there, what the chunk map
says, and whether every block verifies. `Reader` is the filesystem view built on it: what is
at this path, what it holds, and whether it is what was written.

A caller extracting files wants the second. A caller looking at a damaged image wants the
first, and folding them into one would hide a layer the on-disk format actually draws.

```rust,ignore
# extern crate ferrosys;
use ferrosys::btrfs::{Volume, ondisk::objectid};

let mut volume = Volume::open(std::fs::File::open("root.img")?)?;
let sb = volume.superblock();
println!("{} bytes, {} KiB blocks", sb.total_bytes, sb.nodesize / 1024);

// Every tree the filesystem has, and how many records each holds.
for root in volume.tree_roots()? {
    let name = objectid::name(root.objectid).unwrap_or("subvolume");
    println!("{name}: {} items", volume.tree(root).count_items()?);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

### The bootstrap, and why there is one path and not two

Finding the chunk tree needs the map that reading the chunk tree would build. The format
breaks the circle in the superblock. The chunk items covering the chunk tree's own address
are copied into it, as an array of key-and-chunk pairs. So opening a volume loads that
array, translates the chunk root through it, reads the chunk tree, and has the whole map.
That map is what `ChunkMap` holds, and what every read above it goes through.

There is exactly one translation, and the reason is worth stating because the shortcut is
tempting. On a filesystem a formatter has just written, a chunk's logical start and its
physical start are often close. They are close enough that arithmetic would appear to work.
On a filesystem that has been balanced they are unrelated numbers.

A shortcut would be right on every image this crate could produce, and wrong on half the
images it is pointed at. The failure is not an error. It is a successful read of the wrong
bytes.

A chunk whose copies are *pieces* rather than whole copies needs more than the device in
hand, so a striped profile is refused by name. So is a profile word the format does not
define, because nothing says what its stripes are. Neither is treated as though the first
stripe were the chunk.

### The copies of the superblock

The format defines **three** locations, which are 64 KiB, 64 MiB, and 256 GiB. It writes a
copy at each one the device holds *all* of. `Volume::mirrors` says what was found at each.
Opening a volume chooses the copy at the highest generation, which is the filesystem's own
rule for which is live.

Every copy is judged whether or not it is the one used, and the states are not one state:

| What was found | What it means |
|---|---|
| `OutsideDevice` | the device is not long enough to hold this copy, so the format wrote none |
| `Truncated` | the device's own recorded length reaches it and the image in hand does not |
| `Absent` | the bytes are readable and are not a superblock |
| `Damaged` | a superblock whose checksum does not cover it |
| `Misplaced` | a superblock recording a different location as its own |
| `Present` | a superblock, at the transaction it records |

`Misplaced` is the one worth dwelling on. A superblock records where it lives, and that field
is *inside* what its checksum covers. A copy written somewhere other than where it belongs
therefore verifies perfectly, and still says the wrong thing about itself. That is what an
image carved out of a disk at the wrong offset looks like, and no checksum can catch it.

Under `ReadPolicy::Strict` a copy the device has room for that is anything but `Present` at
the live generation is a refusal. Under `ReadPolicy::Lenient` the volume opens through the
surviving copy and every state is reported. That is the reading a forensic look at a damaged
filesystem wants.

### Walking a tree

Every tree in a btrfs has the same shape, so there is one engine and every tree is read
through it. That shape is internal nodes of key-and-address pairs over leaves of key-and-data
items. They are sorted by a 17-byte key of an object id, a one-byte type, and an offset the
type decides the meaning of. A search goes straight to a key rather than scanning, which is
what makes "the entries of this directory" one descent:

```rust,ignore
# extern crate ferrosys;
use ferrosys::btrfs::{Volume, ondisk::{DiskKey, ItemType, objectid}};

let mut volume = Volume::open(std::fs::File::open("root.img")?)?;
let root = volume.root_tree();

// Every record of one tree, in key order, with the item's own bytes.
volume.tree(root).for_each_item(|key, data| {
    println!("{:?} {} bytes", key.kind.name(), data.len());
    true
})?;

// Or straight to one: the first record at or after a key.
let found = volume.tree(root).find_first(DiskKey::first_of(objectid::FS_TREE, ItemType::ROOT_ITEM))?;
# let _ = found;
# Ok::<(), Box<dyn std::error::Error>>(())
```

An item type the format has grown since this release keeps its byte and answers `None` to
`name`. That is deliberate, and it is the *opposite* of what an unknown feature bit gets. A
feature bit is the format telling a reader in advance that it will not understand what
follows. An unrecognized item is a record this reader has no opinion about, sitting beside
records it does. A reader that refused what it could not name would refuse every filesystem
that has been used.

### What bounds a walk

An image that was crafted rather than formatted can describe a tree that is not one. Each
way of doing so has its own guard:

- **A count larger than the block holds** — checked against the room the block has, in the
  units its own level says it holds.
- **An item whose data escapes its leaf** — a leaf fills from both ends, so the data must
  begin past the array describing it and end within the block. The arithmetic is 64-bit
  whatever the target's pointer width is. A crafted offset therefore behaves the same on a
  32-bit machine as on the one this was developed on.
- **A leaf whose data is not packed** — every item's data abuts its neighbor's. Bounding each
  item separately does not imply this, and the difference is a defect class. Data moved
  within a leaf, with the offsets moved to match, leaves every item inside the block. It
  also leaves every item pointing at bytes that are not its own.
- **A block reached twice** — every address a descent visits is remembered.
- **A child at the wrong height** — a child is exactly one level below its parent. A descent
  therefore has a decreasing measure independent of the visited set, and terminates whatever
  the addresses say.
- **Keys out of order** — a tree that is not sorted is not a tree, and a search over one
  silently misses items rather than failing.
- **A tree larger than the caller will hold** — `Limits::max_walk_entries` caps what one walk
  visits.

Beside those, every block carries a checksum over itself. This crate recomputes each one from
the bytes that came off the device, rather than from a value re-serialized through its own
types. A structure whose coverage of a format is partial cannot reproduce a foreign tool's
bytes. A verifier built on one would report every filesystem it did not write as damaged.

A block also records its own logical address and the filesystem it belongs to. Both are
held against what the reader believed when it went to fetch it. Those are checks no checksum
can make, for the same reason `Misplaced` is: the fields are inside what the checksum
covers.

### What it refuses to read at all

Some filesystems are entirely well-formed and beyond this reader. Each is refused by a
name saying what it would take, rather than by an unexpected value:

- An `incompat` feature bit outside `SUPPORTED_INCOMPAT`, named. One the format grew after
  this release is given as its bit position instead.
- A checksum algorithm this crate does not compute. Comparing bytes against a digest it did
  not produce would report every block of a healthy filesystem as damaged.
- A filesystem spanning more than one device. The image in hand is then a part of it rather
  than the whole.
- A chunk profile whose stripes are not copies.
- A file whose bytes are stored in an encoding this build has no decoder for, named by the
  algorithm.

### Compressed extents

The format stores a file's bytes as DEFLATE, LZO1X, or Zstandard where a mount was told to.
Each is a Cargo feature: `zlib`, `lzo`, `zstd`. What a build carries decides two different
things, and the difference is the format's rather than this crate's:

- **A file** stored with an algorithm this build cannot decode is refused by name
  (`ReadError::UnsupportedCompression`), and every other file on the filesystem reads.
- **A filesystem** advertising LZO or Zstandard in its `incompat` word cannot be opened at all
  without that decoder. The word is the format saying in advance that a reader without it will
  misread what follows. DEFLATE sets no such bit, because every reader of this format has
  always understood it, so a filesystem using it opens either way.

Verification needs none of them, and the reason is worth knowing. The checksums cover the
bytes **on the volume**, so `verify_data` checks a compressed extent without expanding it.

A record's declared expansion is a number the image supplied, and it is the size of a buffer.
It is held to what the format compresses in, which is 128 KiB, before a byte is allocated for
it. A record claiming more is refused, and so is a stream that expands to a different length
than its record declares.

### The filesystem view

`Reader` is the layer that reads those items as files. Opening one reads the volume and then
the root tree. The root tree is what says how many subvolumes there are, and where each one's
tree begins:

```rust,ignore
# extern crate ferrosys;
use ferrosys::btrfs::Reader;

let mut reader = Reader::open(std::fs::File::open("root.img")?)?;
for sub in reader.subvolumes() {
    println!("{}: {}", sub.id, String::from_utf8_lossy(&sub.name));
}

let node = reader.lookup(b"/etc/hostname")?;
println!("{} bytes, mode {:o}", node.item.size, node.item.mode & 0o7777);
print!("{}", String::from_utf8_lossy(&reader.read_data(&node)?));

// Held against the checksums the filesystem recorded for it.
reader.verify_data(&node)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

An inode is **a subvolume and a number together**, which is what `Node` carries. Inode 257
exists in every subvolume, and they are different files. A reader keyed on the number alone
would therefore hand back one for the other.

A directory holds every entry twice on purpose. One is a `DIR_ITEM` keyed by the hash of the
name, which is what `lookup` descends to. The other is a `DIR_INDEX` keyed by the entry's
sequence number, which is the order `read_dir` lists in. Each is used for what it is keyed
for. There is no `.` or `..` entry to filter out, because btrfs stores neither.

A directory entry whose location names a `ROOT_ITEM` rather than an inode is **where a
subvolume is mounted**. Stepping through it continues in another tree entirely. A walk
crosses those seams, so what it yields is every name in the filesystem rather than every name
in one tree.

A run of a file that was never written reads back as zeros, and the format spells that two
ways. With `no-holes` there is no extent record at all, and a reader has to notice the
absence. Without it there is a record whose extent address is zero. A preallocated extent
reads back as zeros too, because handing back what is on the volume there would be handing
back another file's deleted bytes.

### What data checksums buy

btrfs keeps a crc32c per sector of every data extent in a tree of its own.
`Reader::verify_data` is what holds a file's bytes against them.

**No other family in this crate can make this check**. ext4 checksums its metadata and not
its data, and neither FAT nor exFAT checksums anything. A file whose bytes decayed on the
medium sits under trees that are entirely well-formed, and verifies perfectly at every level
but this one.

Three kinds of run are skipped, each for a reason the format states. A hole and a
preallocated extent hold nothing to check, and a file whose inode carries `NODATASUM` has no
checksums recorded at all. A run with no checksum recorded is reported rather than passed.
Treating a missing record as a pass would make the whole check vacuous on the one image it
most matters for.

### Scanning a whole filesystem

`Reader::scan` walks every tree and reports rather than stopping, which is what a caller asking
"is anything wrong with this image" wants. Two of what it reports are this family's alone.

**A live log tree**. A filesystem that was not cleanly unmounted has a nonzero `log_root`, and
the committed trees are stale with respect to it. This crate never replays a log, so what it
reads is the last committed transaction and the finding says so. It is cosmetic, since the
image is conformant and every byte read is trustworthy. The message says what is *missing*
rather than which field held an unexpected value.

**An item type this reader has no opinion about**. Skipped, counted, and named, one finding per
type with the count. A used filesystem carries thousands of records of a handful of types
nothing here interprets. A report with one entry per record is a report nobody reads.

A finding from this family carries no byte offset, and that is deliberate. Every address it
reports is logical, and the byte one sits at is on the far side of the chunk map. A finding
with no offset is honest. One carrying a logical address multiplied by something would name a
byte that is nothing in particular.

### Planning a layout

`ferrosys::btrfs::plan_layout` answers, as a pure function, where every chunk of a btrfs of a
given shape sits. It takes a volume length, a sector and node size, and how each kind of
block group is replicated. It also takes the feature words, and how much content the
filesystem will be given.

It returns every chunk in ascending logical order with the device offset of each copy. It
returns which superblock locations the device has room for, and a bound on the metadata the
whole of it spends.

```rust
# extern crate ferrosys;
use ferrosys::btrfs::{PlanRequest, Profile, plan_layout, minimum_volume_bytes};
use ferrosys::btrfs::ondisk::BlockGroupFlags;

let layout = plan_layout(&PlanRequest::new(1 << 30))?;

// Two address spaces, advancing at different rates: a chunk covers its length of logical
// space and its length times its copy count of the device.
for chunk in &layout.chunks {
    println!(
        "{:#x}..{:#x} in {} cop{}",
        chunk.logical,
        chunk.logical_end(),
        chunk.copies.len(),
        if chunk.copies.len() == 1 { "y" } else { "ies" },
    );
}

// Metadata is replicated by default, so the device gives up twice the logical space for it.
let metadata: u64 = layout.chunks_of(BlockGroupFlags::METADATA).map(|c| c.length).sum();
assert!(layout.device_bytes_used() > metadata);

// Whether a device can hold a btrfs at all is a question with an answer before any of this.
assert!(minimum_volume_bytes(Profile::Dup, Profile::Single) > (100 << 20));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Two things it does that are worth knowing about.

**It refuses a feature whose prerequisites were not asked for**. Recording block groups in a
tree of their own is defined only for a filesystem that meets two conditions. That
filesystem also keeps free space in a tree, and records holes by their absence. Asking for
the first without the other two is a
`GeometryError::FeatureIncoherent` naming what is missing. It is not a layout quietly built
without the feature its caller named. A filesystem built without a feature it was described
as having is a filesystem other than the one that was asked for.

**The first mebibyte holds no chunk, and on a filesystem with replicated metadata neither does
the span after it**. The first is the format, since a superblock lives at 64 KiB. The second
is unallocated space a driver allocates from later. It allocates from it exactly as it
allocates from the space past the last chunk. The layout carries it so that a planned
filesystem and one the format's own tooling produces put the same chunk at the same
address.

### Writing one

`ferrosys::btrfs::format` turns a source tree and a plan into bytes. What comes out is a
complete btrfs:

- Ten trees, and one more per subvolume. The ten are the chunk, device, extent, root,
  filesystem, checksum, UUID, free-space, block-group, and data-relocation trees.
- Every block checksummed.
- Every allocated block recorded in the extent tree, with the tree that owns it.
- A crc32c beside every sector of file data.
- Every superblock copy the device has room for, written last.

```rust
# extern crate ferrosys;
use ferrosys::{Metadata, Timestamp, TreeBuilder};
use ferrosys::btrfs::{FormatOptions, GENERATION, Reader, Volume, format};

let time = Timestamp::from_secs(1_700_000_000);

// The five values a formatter would conventionally invent are inputs, so two formats of the
// same tree at the same parameters are the same bytes.
let options = FormatOptions::new([0x11; 16], time)
    .chunk_tree_uuid([0x22; 16])
    .device_uuid([0x33; 16])
    .subvolume_uuid([0x44; 16]);

let source = TreeBuilder::new()
    .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
    .file(b"/etc/hostname".to_vec(), "ferrosys\n", Metadata::new(0o644, time));

let image = format(source.clone(), 1 << 30, options.clone())?;
assert_eq!(image.as_bytes(), format(source, 1 << 30, options)?.as_bytes());

// btrfs has a field for every property a source states, so nothing was lost on the way in.
assert!(image.fidelity().is_faithful());

// Read it back. Ten trees: the eight a root item names, and the root tree and chunk tree the
// superblock points at directly.
let mut volume = Volume::open(std::io::Cursor::new(image.as_bytes()))?;
assert_eq!(volume.superblock().generation, GENERATION);
assert_eq!(volume.tree_roots()?.len(), 10);

// And as a filesystem.
let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes()))?;
let node = reader.lookup(b"/etc/hostname")?;
assert_eq!(reader.read_data(&node)?, b"ferrosys\n");
// Every byte of it against the checksum written beside it.
reader.verify_data(&node)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

An empty filesystem is `TreeBuilder::new()`, which is a source with no entries in it.

`format_to` streams the same bytes into any `Write + Seek` destination instead of collecting
them. Only the blocks the filesystem occupies are written and nothing is read back, so a file
destination stays sparse. An empty btrfs is a few hundred kibibytes of metadata whatever the
volume's length. What a format costs beyond the file data therefore does not grow with the
volume at all.

**One transaction, and nothing is ever rewritten**. A filesystem written here is at
`btrfs::GENERATION` and stops, which is what makes the whole of it decidable before the first
byte is placed. Two consequences are visible in the result, and are properties rather than
accidents. Every block group is filled from its start, and left with a single run of free
space. Every tree's leaves are packed full in key order.

### Subvolumes

A subvolume is a filesystem tree of its own inside the same address space. It is the layout
every distribution that defaults to btrfs expects. A caller names which of the source's
directories become one, by path:

```rust
# extern crate ferrosys;
use ferrosys::{Metadata, Timestamp, TreeBuilder};
use ferrosys::btrfs::{FormatOptions, Reader, SubvolumeRequest, format};

let time = Timestamp::from_secs(1_700_000_000);
let source = TreeBuilder::new()
    .directory(b"/@".to_vec(), Metadata::new(0o755, time))
    .file(b"/@/hostname".to_vec(), "ferrosys\n", Metadata::new(0o644, time))
    .directory(b"/@home".to_vec(), Metadata::new(0o755, time));

let image = format(
    source,
    1 << 30,
    FormatOptions::new([0x11; 16], time)
        .subvolume(SubvolumeRequest::new(b"/@".to_vec(), [0x55; 16]))
        .subvolume(SubvolumeRequest::new(b"/@home".to_vec(), [0x66; 16]))
        // Where a mount that names no subvolume lands.
        .default_subvolume(b"/@".to_vec()),
)?;

let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes()))?;
// Three: the one every btrfs has, and the two that were asked for.
assert_eq!(reader.subvolumes().len(), 3);
assert_eq!(reader.default_subvolume(), reader.subvolumes()[1].id);

// A walk crosses the seam rather than stopping at it, so what it yields is the filesystem.
let node = reader.lookup(b"/@/hostname")?;
assert_eq!(reader.read_data(&node)?, b"ferrosys\n");
# Ok::<(), Box<dyn std::error::Error>>(())
```

A subvolume root is still a directory. The source declares it as one, and the request says
which of those directories becomes the root of a tree of its own. A hard link cannot span two
of them, and no btrfs holds one. A source that names one is therefore refused rather than
written as a copy.

## Opening an image without knowing what it is

`open` classifies a source and hands back the reader for whichever family claimed it,
already open over the same bytes at the same offset. The result is an enum of concrete
family readers rather than a common trait, because the readers are genuinely not
interchangeable. Two of them have inodes, link counts, owners, modes, symbolic links, and
extended attributes. The other two have none of the six:

```rust,ignore
# extern crate ferrosys;
use ferrosys::{FsReader, open};

match open(file)? {
    FsReader::Ext(mut reader) => { let _ = reader.superblock(); }
    FsReader::Fat(mut reader) => { let _ = reader.layout(); }
    FsReader::ExFat(mut reader) => { let _ = reader.upcase(); }
    FsReader::Btrfs(mut reader) => { let _ = reader.subvolumes(); }
    // The enum is `#[non_exhaustive]`: a build compiles in the variants of the families it
    // compiles in, so a match carries a wildcard arm.
    _ => {}
}
```

What every variant does share is `FsTree`, which walks a directory, stats an entry, streams
a file's bytes, and resolves a link. An extraction therefore needs no `match` at all.
`ArchiveSink` and `DirectorySink` are written once against it, and drain whichever family
answered.

`open_with` takes the crate's own `OpenOptions`, which carries the three inputs every family
takes. Those are where the filesystem begins, how strictly it is read, and what one read
allocates.

A knob only one family has is on that family's own open, reached by opening its reader
directly. A checksum seed to verify against is one such knob, and a code page to read short
names under is another.

A family that has no such knob takes these options as they are, and mints nothing.
`exfat::Reader::open_with` is `OpenOptions` and no more, because a type identical to it would
be this family declaring a knob it does not have.

A family that does have one *holds* this value rather than copying its fields out. What is
handed across is therefore the value either way, and an input added here reaches every family
without a second edit.

## Saying what an image is

`detect` reads a source and reports the `Filesystem` family it holds, in the crate root's
own vocabulary. Each variant names one family and carries that family's own
sub-classification. `Filesystem::Ext` carries the `Profile` its feature words classify to,
and `Filesystem::Fat` carries the `FatType` its cluster count derives to.

`Filesystem::ExFat` carries nothing, because that family has nothing to sub-classify. The
format has one revision, and every volume records it. `detect_with` does the same at an
offset within the source, for a partition inside a whole-disk image or a region a carver
located:

```rust,ignore
# extern crate ferrosys;
use ferrosys::{DetectOptions, Filesystem, detect_with};
use ferrosys::ext::Profile;

let what = detect_with(disk, &DetectOptions::new().base(1 << 20))?;
assert!(matches!(what, Filesystem::Ext(Profile::Ext4)));
```

A build answers with the families it compiles in, so the enum is `#[non_exhaustive]` and a
`match` over it carries a wildcard arm.

Families are tried in a fixed order, and the rule behind the order is worth knowing because
it decides what detection can get wrong. A family whose images carry a distinctive
multi-byte magic at a fixed offset is tried first. Two such magics do not collide, so at
most one of those families claims any image.

A family whose marker is weak enough to collide, or that has none, is tried afterwards. It
is classified only by checking a whole header for internal consistency. FAT is the second
kind. Its only fixed marker is the boot signature at the end of sector 0, which is on every
bootable sector ever written. That includes the master boot record of a disk whose
partitions hold something else entirely. So a FAT volume is recognized by its whole BIOS
parameter block agreeing with itself, and never by that signature.

exFAT is the first kind, with a condition the rule has to name. `EXFAT   ` sits at offset 3
of sector 0. That is exactly where a FAT boot sector keeps eight bytes of arbitrary OEM
text. No FAT driver reads those bytes, and no formatter is constrained in them. A FAT
volume can therefore spell that magic exactly. Claiming it on the magic alone would mean
FAT is never tried.

An exFAT volume is therefore recognized by the magic **and** by the 53 bytes at offset 11
that the format requires to be zero. A FAT parameter block uses those bytes for its sector
size, its cluster size, and its media descriptor, and cannot leave them empty. Both, or the
claim is not made.

Generally, a family joins the first kind on a magic no other family could write at that
offset. Where the offset is shared, its condition is the magic plus whatever the format
requires that the collision cannot satisfy.

Detection answers with one family rather than every family that might match. It asks what an
image *is*, not whether it is sound. It classifies leniently, so an image with a quirk a
strict read would refuse still answers here. `Reader` and `scan` are what say whether a
filesystem is well-formed.

Recognizing a filesystem and reading one are separate capabilities, and a build carries
both for every family it compiles in. `open` reaches a reader for whatever `detect` names.
