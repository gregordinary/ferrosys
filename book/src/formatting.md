# Formatting and reading images

`ferrosys` has two halves: a formatter that writes a filesystem image, and a reader
that parses one back. Each filesystem family lives in a module of its own — `ext`
writes and reads ext2, ext3, and ext4; `fat` writes FAT12, FAT16, and FAT32 — and the
vocabulary for describing a directory tree, reporting what a format could not hold,
and saying what an image is belongs to neither and lives at the crate root.

Most of this page is the ext family, which is the one with the fullest surface.
[Formatting a FAT volume](#formatting-a-fat-volume) is what differs.

## Describing the contents

A `TreeBuilder` collects the entries to place in the filesystem — directories,
files, symlinks, hard links, device / FIFO / socket nodes, and their extended
attributes — each with its ownership, mode, and times. The root directory and
`/lost+found` always exist and are not added:

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

Order of addition does not matter — inode numbers are assigned in sorted path
order — but every parent directory must be present somewhere in the source. An
input the format cannot represent, such as a name over 255 bytes or a hard link
to a directory, is a typed error rather than a silently dropped entry.

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
nodes, and extended attributes with their POSIX ACLs, which are carried in the version-2
form the syscall boundary speaks and narrowed by whichever family the tree is written to.

The metadata and the extended attributes the walk reads are Linux's, so `DirectorySource`
is built on Linux; on another platform the feature compiles and the type is absent, and
`ArchiveSource` is the portable way to describe a tree. Everything else the crate
does — planning, writing, reading, and scanning — is the same everywhere.

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
use ferrosys::DirectorySource;

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
use ferrosys::{ArchiveSource, DirectorySource};
use ferrosys::LayeredSource;

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
use ferrosys::Slack;
use ferrosys::ext::FormatPlan;

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
- **A file's contents, while it is placed.** How long that is depends on the source: an
  entry holding `FileContent::Owned` bytes holds them from the moment the source was
  built, so a list of them costs the sum of every file, while a `FileContent::Range` is
  read at placement and dropped after, so a list of them costs the largest single file.
  `ArchiveSource::from_path` is what makes that difference for a tar source.
- **The allocator's used-block bitmap**, for the whole run, at one bit per filesystem
  block: `total_blocks / 8` bytes, 128 MiB for a 4 TiB image at a 4 KiB block.

So peak memory grows with the entry count, the largest file, and the block count — never
with the image's size in bytes.

## Formatting a FAT volume

The `fat` module writes FAT12, FAT16, and FAT32 — the family the EFI System Partition
is, and the one with no POSIX fidelity at all. It is behind the `fat` feature, which is
off by default.

**Which of the three a volume is follows from its cluster count and from nothing else.**
No FAT image records its type: every driver counts the clusters and compares against two
thresholds, so a formatter that computed the count differently from a driver would not
produce a mislabelled filesystem, it would produce one whose every chain resolved
somewhere else. `plan_layout` is therefore where the real work is, and `FatTypeRequest`
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

`FormatPlan::new` is the same work without the write, for a caller that wants to know
whether a build will succeed — and what it will cost — before touching the destination.

Six things about the format are worth knowing before choosing parameters.

**The volume label is a value, not a string.** It is stored twice — in the boot sector and
as an entry in the root directory — and lives in a directory entry's name field, so it is
eleven bytes, upper-cased, and cannot contain the separators DOS reserved. `VolumeLabel`
holds those rules in one place; a volume with no label carries the `NO NAME` placeholder in
its boot sector and no entry at all, which is how a driver reports it as unnamed.

**Times are 1980 to 2107, at a two-second granularity.** A FAT directory entry stores a date
and a time in two sixteen-bit words, counting years from 1980, and the seconds field counts
two-second units. An instant outside that range is a typed error rather than a value
truncated into a plausible-looking one, and the conversion is UTC, so an image's bytes do
not depend on where the machine that wrote it thinks it is.

**The allocation unit stops at 32 KiB.** The format's own guidance is that a cluster of
64 KiB or more misbehaves, because more than one widely deployed driver holds a cluster's
byte count in sixteen bits. A pinned cluster past that is refused and `ClusterSize::Auto`'s
search stops there, so a volume that no type fits below the cap is an error rather than a
cluster a driver will truncate. Reading has no such limit.

**Two cluster counts cannot be written unambiguously.** A volume of 4085 or 4086 clusters is
FAT16 to the specification and to Linux, and FAT12 to Windows — and since a file allocation
table is a packed array whose entry width differs between the two, one of those readers
resolves every chain past the second cluster to nonsense. Nothing written into an image
settles it, because no driver reads a type from an image. So the planner never emits one: it
declares the largest count no driver disputes and leaves the few clusters between unused. A
request for FAT16 at such a count is a typed error naming the range, since stepping down
would produce a FAT12 and there is nothing else to move.

**Names are what a file is found by, so an unrepresentable one is refused rather than
substituted.** Every name is stored as a long name unless it is already exactly its own 8.3
short name, so what a driver shows is what was asked for; the two case bits Windows NT put
in byte 12 of a directory entry are left zero, because the format's own specification says
that byte is reserved and must never be read, and a name carried only there reads back
upper-cased on a driver that takes it at its word. A name that is not valid UTF-8, is longer
than 255 code units, contains a path or wildcard separator, or ends in a dot or a space is a
typed error. Two names in one directory that differ only in case are refused as well: a FAT
lookup ignores case, so they are one name to every driver that reads the volume.

**Everything a FAT volume cannot represent is refused until the caller says otherwise.**
Ownership, permission bits, the set-user-id bits, symbolic links, second names for a file,
device nodes, and extended attributes have no field at all. A build that would lose one of
those fails, naming the entry and the property, until it is named in an `AcceptedLoss` — and
then the `FidelityReport` says exactly what went, entry by entry.

A property counts as lost when the value a read gets back is not the value that was stated,
which is narrower than "the format has no field for it": a tree owned by root with `0644`
files and `0755` directories goes in and comes back out unchanged, because those are the
values `Synthesis` fills in for a filesystem that records none.

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
**A hard link is written as a second copy of its file** — its target is named inside the
`Source`, so resolving it reads nothing the crate was not given, and `FormatPlan` is where
the size that costs is a number to read rather than to discover. **A symbolic link is never
followed**: its target is an arbitrary path, so resolving one would copy whatever it happens
to point at into the image. It leaves no entry behind, and neither do device nodes, named
pipes, and sockets.

## Reading

The `Reader` opens over an image's bytes and parses it back. It walks the directory
tree from the root (inode 2) and returns file and symlink contents:

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
rather than its contents, is the subject. `walk_with` holds only the *frontier* — the names
reached and not yet visited, each a path and an inode number — so what it costs follows the
shape of the tree rather than its size. It is a frontier and not a fixed set: a directory
holding a million names puts a million paths on it. Those names answer to the same bound the
visited ones do, so `Limits::max_walk_entries` and the image's own storage bound what a walk
finds as well as what it yields.

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
use ferrosys::{DirectorySink};
use ferrosys::ext::{Reader};

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
else. It is the second of two checks: a reader refuses such a name where it resolves it, so
no walk hands one over in the first place. Symbolic links are written exactly as recorded,
absolute targets included, which is safe because nothing here ever follows one: every handle
is opened `O_NOFOLLOW` and every attribute is set on the link itself.

The destination is resolved once. The handle is taken first and both questions asked of it —
that it is a directory, and that it holds nothing — so what a sink accepted and what it
writes into are one object.

A directory's mode, ownership, and times are applied once its children are in place, so a
directory the image records as read-only is still one its contents could be written into.
One the image records *without owner-search permission* waits until the whole walk is done,
because a second name for a hard-linked node is created by traversing to the first, and a
directory that cannot be searched cannot be traversed. That is what makes an unprivileged
extraction of such a tree succeed rather than fail part-way with a bare `EACCES`.

Parts of a tree take privileges — a device node needs `CAP_MKNOD`, setting a recorded owner
needs `CAP_CHOWN`, an extended attribute in the `security` or `trusted` namespace is the
host's to write, and a destination filesystem with no notion of a second name for a node
refuses a hard link — and by default a host that refuses any of them is
`HostError::Unprivileged`, naming the entry. `skip_privileged` is the opt-in for an
unprivileged extraction: what it left out comes back in the `ExtractReport` rather than in
silence, as `skipped`, `ownership_dropped`, and `xattrs_dropped`.

A file's contents are written as the filesystem reports them, and a hole reads as zeros, so
a sparse file lands in the destination fully allocated.

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
reference out of range, a structure that does not parse or whose counts contradict each
other, an inode carrying a structure its superblock's feature words deny, a directory
entry naming an inode the filesystem does not have. It reports what is wrong; it does not
refuse the image. `verify_checksums` is the strict counterpart, failing on the first
object whose stored checksum does not match its recomputed value.

`scan` is the path to point at an image you have no reason to trust. Every allocation it
makes is bounded by the bytes the source holds rather than by a count the image claims:
the groups and inodes it walks are capped at what the source can physically hold, each
metadata block is read once however many references name it, and the findings stop at
`Limits::max_findings` — `FindingReport::MAX_FINDINGS` unless you set another — with
`ScanReport::is_truncated` recording that they did. A truncated report is a floor: the
image holds at least these findings, `worst_severity` and `has_fatal` are floors too, and
`is_clean` is false whatever the report holds, since a scan that stopped short never saw
enough to call an image clean.

`walk` is bounded the same way — a well-formed filesystem spends at least a directory
record's worth of its own blocks per name, so the source's length bounds how many names
it can describe. Reaching that bound is an error rather than a short list: a caller
extracting a tree from a truncated walk would write an incomplete one and see success.

A `ScanReport` is ext's own taxonomy, kept typed: an `Anomaly` names the subsystem as a
`Category` value and its place as a `Location` of group, inode, and block, which is what a
consumer reasoning about ext4 acts on. `to_report` projects it into the crate's
`FindingReport`, which is the frame every family shares — a `Severity`, the `Family` that
found it, that family's own word for the subsystem, the byte offset, and that family's own
named coordinates — and that is what renders, to JSON, to a fixed-column table, and to a
SARIF log. There is one document shape and one severity scale however many families a build
carries.

The JSON document opens with a `schema` field holding `FINDINGS_SCHEMA_VERSION`: a
downstream parser depends on the emitted shape, and no Rust signature describes it, so the
shape names its own version.

Every name a finding or an error carries came off the image, and a filesystem name may hold
anything a terminal acts on — an escape sequence, a carriage return, a direction override. A
directory named `\x1b[2J\x1b[1;1Hno findings\x1b[0m` would otherwise put a forged clean
report on the screen of whoever read the report. So a name is escaped where it is
interpolated, which is the last point anything can tell it from the words around it, and
both renderings are public for a caller whose own output names the same bytes: `printable`
for text a person reads, and `push_json_string` for a JSON string literal.

### The filesystem's own boundary

An ext filesystem usually occupies a partition, or the region of a larger file that `base`
names, so the bytes after its final block belong to something else. **Every reference the
reader follows is bounded by the filesystem's own block count before any of it is read** —
a group descriptor's bitmaps and inode table, an external extent node, an attribute block,
every pointer in a classic block map, and the table bytes an inode is read from, which are
bounded through the block the inode's *last* byte falls in. A reference past the end is a
`ReadError::OutOfRange`, and a scan's structural finding under the subsystem that named it.

That is a different bound from the source's length, and both are kept: the block count says
which bytes are the filesystem's, and the source's length is what a truncated image runs out
of. Bounding by the source alone would let a crafted image read whatever follows it — a
neighbouring partition, the rest of a disk — back as its own metadata, with nothing in the
image saying otherwise.

The source's length here is the length from `base` on, measured once when the filesystem is
opened. That is the filesystem's share of the source: a 16 MiB partition at the end of a
2 TiB disk image is bounded by the 16 MiB that could hold it, not by everything in front of
it. A source that cannot report its own end fails the open, rather than answering zero and
leaving every bound built on it satisfied by a filesystem with nothing in it.

The references an image makes to its own inodes are bounded the same way: a directory entry
naming an inode past `s_inodes_count` is `ReadError::DirEntryNoSuchInode` where the entry is
read, so a listing never carries a name that resolves to nothing, and a scan reports the
directory holding it.

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

## Reading a FAT volume

`fat::Reader` is the FAT family's counterpart to `ext::Reader`, and reads any conformant
FAT volume with one or two allocation tables, whatever wrote it — the count `fsck.fat`
supports, and the one a mirror comparison is defined against. It derives the type from the
geometry the way every driver does, follows cluster chains, reassembles long names from the
entries that carry them, and streams file contents:

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
directory entry describes and carries no number: FAT has no inodes, so there is nothing
that would distinguish a file from a second name for it — the format has no second names.
Its `Storage` is a cluster chain, or the fixed region a FAT12 or FAT16 volume reserves for
its root, or nothing at all, which is what an empty file owns. Its `times` are an `Option`,
because the root directory has no entry on any type and so no times to read.

`read_dir` hands back an `Entry` carrying both the name and the short name, and
`has_long_name` saying which the volume actually stored. A name that is already its own
8.3 short name needs no long-name entries and gets none; anything else — lower case,
longer, punctuated differently — is stored in long-name entries and pairs with a generated
short name.

**Every name it hands back is one a directory can hold.** A name resolving to `.` or `..`,
or carrying a path separator or a NUL, is `ReadError::HostileName` — an error under
`ReadPolicy::Strict`, a `Severity::Structural` finding a scan collects under `Lenient` —
rather than an entry in the list. The refusal is at the one place an entry's bytes become a
name, so it holds for everything downstream at once: the entry list, the paths a walk
builds, and an archive or a tree written from them. The dot entries the format requires are
a separate matter: they are recognized by their eleven-byte name field, which is where the
format defines them, and are simply not entries in the tree.

This is a rule about untrusted input rather than about damage. Neither field a name
arrives in rules such a name out — a long name is UTF-16 and may spell anything, and a
short name is eleven bytes the image chooses — and a crafted volume controls every byte of
a long-name run, the ordinal and the checksum included, so a run can be perfectly well
formed and still spell `..`. A reader that built a path from one would be the component
that produced the traversal.

**A path resolves however its letters are cased.** `lookup` matches a component exactly
first and, failing that, without regard to the case of its ASCII letters, which is how
every FAT driver finds a name. Bytes above ASCII are compared as they stand, for the reason
below.

### Short names above ASCII

An eleven-byte short name is bytes in whatever code page the machine that created the entry
was running under, and **nothing in a FAT volume records which one**. `BS_OEMName` names
the formatter rather than a code page, and the format's own specification says never to
interpret it; the page was a property of the machine and the moment each name was created,
so one directory may legitimately hold names written under two of them.

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

Five single-byte pages are built in — `Cp437` (the original IBM PC set, and the OEM default
in the United States), `Cp850` (Western Europe), `Cp852` (Central Europe), `Cp865`
(Nordic), and `Cp866` (Cyrillic) — and `Custom(&'static [char; 128])` reaches any other
single-byte page without waiting for a release. The double-byte pages are not among them:
a lead byte selects a second table for the byte after it, so reading one is a state machine
over the name rather than a lookup per byte. Read such a volume under `Verbatim` and
transcode the bytes it hands back.

Naming a page also changes what a strict read does. A byte above ASCII the reader cannot
interpret is a conformance deviation, and `ReadPolicy::Strict` stops at it; the same byte
with a page named is a cosmetic remark, and a strict read carries on. The severity tracks
whether the reader recognized what it saw, which is the only thing naming a page changes
about the bytes.

Long names take no such input. They are UTF-16, which is unambiguous, so there is nothing
for a caller to steer — a unit with no partner is replaced by U+FFFD and reported.

### Checking a FAT volume

`fat::Reader::scan` is the family's whole-volume pass, and what it audits is what a FAT
volume has to audit. There are no checksums anywhere in the format, so the file allocation
table's copies standing in for one is the closest thing: two copies of one allocation record
that disagree mean at least one is wrong and nothing in the volume says which, which is
reported at the same severity a failed ext checksum is. `verify_tables` is the strict
counterpart, failing at the first entry two copies disagree about.

Past that it checks the parameter block against itself, the backup boot sector against
sector 0, the information sector's hints, every directory entry — a long name whose
checksum does not tie it to the entry it precedes, a run that is not whole, a name no
directory could hold, a first cluster outside the volume, a `.` or `..` that is not what the
format requires — and every cluster chain, for a loop, for a cluster two chains both claim,
and for clusters that are marked allocated and reached by nothing at all. That last one
needs the whole allocation rather than any single structure, so a scan carries one bit per
cluster, which is a thirty-second of one copy of the table on any volume — and the count is
held at open to what the type addresses, so that is 32 MiB at the very largest FAT32 there
is.

A `fat::ScanReport` projects into the same `FindingReport` an ext scan does, through
`to_report`, so one parser reads both. Its `Category` is FAT's own vocabulary — the boot
sector, the information sector, the allocation table, a directory — because ext's means
nothing about a FAT and the reverse.

**A strict read accepts every volume this crate's own writer produces**, at every parameter
set it accepts. That is the line the severities are drawn against, and it is why an
undersized FAT32 — which the writer emits on request — is a cosmetic remark rather than a
refusal.

## Opening an image without knowing what it is

`open` classifies a source and hands back the reader for whichever family claimed it,
already open over the same bytes at the same offset. The result is an enum of concrete
family readers rather than a common trait, because the readers are genuinely not
interchangeable — one has inodes, link counts, owners, modes, symbolic links, and extended
attributes, and the other has none of the six:

```rust,ignore
# extern crate ferrosys;
use ferrosys::{FsReader, open};

match open(file)? {
    FsReader::Ext(mut reader) => { let _ = reader.superblock(); }
    FsReader::Fat(mut reader) => { let _ = reader.layout(); }
    // The enum is `#[non_exhaustive]`: a build compiles in the variants of the families it
    // compiles in, so a match carries a wildcard arm.
    _ => {}
}
```

What every variant does share is `FsTree` — walk a directory, stat an entry, stream a
file's bytes, resolve a link — so an extraction needs no `match` at all. `ArchiveSink` and
`DirectorySink` are written once against it and drain whichever family answered.

`open_with` takes the crate's own `OpenOptions`, which carries the three inputs every
family takes: where the filesystem begins, how strictly it is read, and what one read may
allocate. A knob only one family has — a checksum seed to verify against, a code page to
read short names under — is on that family's own open, reached by opening its reader
directly.

## Saying what an image is

`detect` reads a source and reports the `Filesystem` family it holds — the crate root's own
vocabulary. Each variant names one family and carries that family's own sub-classification:
`Filesystem::Ext` carries the `Profile` its feature words classify to, and `Filesystem::Fat`
carries the `FatType` its cluster count derives to. `detect_with` does the same at an offset
within the source, for a partition inside a whole-disk image or a region a carver located:

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
multi-byte magic at a fixed offset is tried first; two such magics do not collide, so at
most one of those families claims any image. A family whose marker is weak enough to
collide, or that has none, is tried afterwards and is classified only by checking a whole
header for internal consistency. FAT is the second kind: its only fixed marker is the boot
signature at the end of sector 0, which is on every bootable sector ever written —
including the master boot record of a disk whose partitions hold something else entirely.
So a FAT volume is recognized by its whole BIOS parameter block agreeing with itself, and
never by that signature.

Detection answers with one family rather than every family that might match, and it asks
what an image *is*, not whether it is sound: it classifies leniently, so an image with a
quirk a strict read would refuse still answers here. `Reader` and `scan` are what say
whether a filesystem is well-formed.
