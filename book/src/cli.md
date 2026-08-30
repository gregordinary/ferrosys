# The `ferrosys` command line

The `ferrosys-cli` crate ships one binary, `ferrosys`. It writes ext2, ext3, and ext4
filesystems, FAT12, FAT16, and FAT32 volumes, exFAT volumes, and btrfs filesystems. It
reports on them, reads their contents back out, and changes what an ext filesystem is
known by. It is the library's surface for anyone not writing Rust.

```console
$ ferrosys format  --size SIZE --uuid HEX --time SECS [options] OUT.img
$ ferrosys inspect [options] IMAGE
$ ferrosys extract [options] IMAGE (--to-tar F|- | --to-dir DIR | --cat PATH | --stat PATH | --list)
$ ferrosys detect  [options] IMAGE
$ ferrosys identity [options] IMAGE
```

The library is modular, and a program that wants one filesystem compiles one. This binary
is the deliberate exception: it carries every family, so `detect` and `inspect` identify an
image whatever it turns out to hold. `format -t` is where you say which one to write.

Install it from the workspace:

```console
$ cargo install --path crates/ferrosys-cli
```

## Everything the image depends on is an input

Everything an image's bytes depend on is an input you supply, so two runs given the same
inputs write the same image, byte for byte. Reproducibility is the only mode the tool
has, and it is always on.

That has one consequence worth stating plainly: an identity is required, and `--time` is
required for every family whose format records an instant. Each family names its own
identity. That is `--uuid` for ext, `--volume-id` for a FAT, `--volume-serial` for exFAT,
and `--fsid` for btrfs. The tool mints neither an identity nor a time. Pipe an identity in
from a tool that does, and pass the time explicitly or set `SOURCE_DATE_EPOCH`:

```console
$ ferrosys format --size 512M --uuid "$(uuidgen)" --time 1700000000 rootfs.img
$ SOURCE_DATE_EPOCH=1700000000 ferrosys format --size 512M --uuid "$(uuidgen)" rootfs.img
```

The directory-hash seed defaults to the UUID's bytes, so it too is an identity you
supplied. `--hash-seed` overrides it.

## Streams and exit codes

The standard output carries **exactly one artifact per run**: a report, a listing, a tar
stream, or one file's bytes. Everything else — a format's summary, warnings, errors —
goes to the standard error. So `ferrosys extract img --to-tar - | tar -t` never has a
summary line spliced into its input, and `ferrosys inspect --json img > report.json`
never has a warning in it.

The exit codes mirror `e2fsck`'s. The line between 4 and 8 is whether an opinion about a
filesystem could be formed at all:

| Code | Meaning                                                              |
| ---- | -------------------------------------------------------------------- |
| `0`  | The command did what it was asked, and any filesystem it read is sound. |
| `4`  | A filesystem was read, and it is bad.                                  |
| `8`  | The command could not be carried out: the host got in the way, the bytes are not a filesystem at all, or an option named a concept the image's family does not have. |
| `16` | The command line could not be understood.                              |

## `format`

```console
$ ferrosys format --size 512M --uuid f0e17055-0000-4000-8000-000000000000 \
      --time 1700000000 --from-tar rootfs.tar rootfs.img
```

The image streams out through the library's streaming writer, which touches only the
blocks the filesystem uses. The file therefore stays sparse, and the tool writes a
filesystem far larger than memory.

### Where the contents come from

`--from-tar FILE` and `--from-dir DIR` are the two sources. Without either, the filesystem
is empty but for `/lost+found`. Giving both is a usage error, since nothing here decides
the rules for a merge.

**`--from-tar FILE`** reads an uncompressed tar archive. A named file is left on disk, and
each member is read as its file is placed. Peak memory is therefore the largest single
member, not the archive. `--from-tar -` reads the standard input, which cannot be sought
back over and so is held whole. That is the one case where a large archive needs the
memory to match, and the one that carries a size cap. A stream past four gibibytes is
refused, and naming the archive as a file is both the way past it and the cheaper route.

A compressed archive is named as such rather than reported as malformed tar:

```console
$ gunzip -c rootfs.tar.gz | ferrosys format ... --from-tar - rootfs.img
```

**`--from-dir DIR`** walks a directory tree on this machine. `DIR` itself becomes the
filesystem root. Modes, ownership, all three times, symlinks, hard links, device, FIFO and
socket nodes, and extended attributes with their POSIX ACLs all come across. Each file is
read as it is placed, so peak memory is the largest single file.

The walk records Linux inode metadata and Linux extended attributes, so this is the one
option carried out on Linux alone. A binary built elsewhere refuses it by name and exits
8, having opened nothing. Every other part of the tool is the same on every platform: an
empty filesystem, `--from-tar`, `inspect`, `extract`, `detect`, and every geometry option.

The walk records the uid and gid the host files carry, which for a build that does not run
as root is that user's own. Use **`--owner UID:GID`** to replace them, and a rootless
build almost always wants `--owner 0:0`:

```console
$ ferrosys format --size 512M --uuid "$(uuidgen)" --time 1700000000 \
      --from-dir staging/rootfs --owner 0:0 rootfs.img
```

### Sizing the image to its contents

`--size auto` works the size out from what goes in the filesystem, instead of being told:

```console
$ ferrosys format --size auto --from-dir staging \
      --uuid "$(uuidgen)" --time 1700000000 rootfs.img
```

It finds the smallest filesystem that holds the contents by planning candidate sizes and
placing the contents into each. The size it settles on is therefore one that formats, and
one allocation unit less does not. Nothing is written while it searches, so a size that
cannot be found leaves the destination untouched like any other planning failure. Pair it
with `--dry-run` to learn the number without writing anything at all.

It works for every family, and each measures itself in its own unit. An ext filesystem is
searched a block at a time. A FAT volume is searched a sector at a time, because its
cluster size is derived from its size rather than given.

The smallest filesystem holding something is one with nothing left in it. That is right
for an image that will only be read, and useless for one that will be written to.
`--slack` says how much must stay free:

```console
$ ferrosys format --size auto --slack 20% --from-dir staging \
      --uuid "$(uuidgen)" --time 1700000000 rootfs.img
$ ferrosys format --size auto --slack 64M --from-dir staging \
      --uuid "$(uuidgen)" --time 1700000000 rootfs.img
```

The share is of the finished filesystem, measured in whatever its own free counter counts:
blocks for ext, clusters for FAT. So `--slack 20%` is what `df` reports as 80% used. On ext
the super-user reservation (`--reserved-percent`) is separate accounting over the same
blocks, so an unprivileged writer sees 15% of it at the 5% default. `--slack` belongs to
`--size auto` and is a usage error over a size that was named outright, which has no room to
find.

On FAT a share can leave a volume unchanged where a byte figure does not. FAT32 needs 65525
clusters whatever it holds, so a small tree already lands on a volume that is almost
entirely free. Only `--slack 200M` and the like ask for more than that floor already gives.

On a small image the floor is often the journal rather than the contents. A log costs
about 4 MiB whatever goes in the filesystem, so `--size auto -t ext2` is what fits a
boot partition to what it holds.

### The destination must be a regular file

A format writes only the blocks the filesystem uses, and extends the file to its full size
with a single byte at the end. Every byte it does not write must already read as zero,
which creating or truncating a regular file guarantees and a block device does not.
Formatting a device would leave whatever it held interleaved with the new filesystem, so
the tool refuses.

### A failing run leaves the destination alone

The source is parsed, the geometry planned, and the inode model built and checked *before*
the destination is opened. A run that cannot succeed therefore never truncates the image
already at that path.

`--dry-run` goes one step further. It reports the geometry the command would realize,
without opening the destination at all.

`--atomic` covers the other end. It writes to a sibling temporary file, and renames it over
the destination once the image is whole. A failure part-way through the write is therefore
not visible either. Note what `--atomic` costs: the destination becomes a *new* file. Its
mode comes from this process's umask, and any ownership, ACLs, or extra hard links the old
file carried do not survive the rename. Without `--atomic` the image is written in place.

The two do not combine. `--dry-run` opens no destination, so there is nothing left for
`--atomic` to decide, and a flag that decides nothing reads as one that worked.

### Geometry the command line names, and geometry it does not

A family's layout can be decided by more than its size. Where it is, the choice is spelled
out for the family that records it in its own superblock and reads it back as identity.
btrfs takes `--sector-size`, `--node-size`, and the two replication profiles. ext takes
`--block-size` and `--inode-size` for the same reason.

FAT and exFAT derive their cluster size, table count, reserved sectors, and root capacity
from the volume's size, by the rules their reference formatters use. The command line does
not offer to override them. The library does. A caller can pin a cluster size, a sector
size, an OEM name, or a boot sector. That caller builds a plan request directly and formats
through the crate. What comes out of either route is the same filesystem.

### Choosing a filesystem

`-t` (or `--type`) selects which filesystem to write: `ext2`, `ext3`, `ext4` (the default),
`fat12`, `fat16`, `fat32`, `exfat`, or `btrfs`. It names the family as well as the variant.
Each family takes its own identity and its own options, and an option belonging to another
one is refused by name rather than passed over. A line that named two families has said two
things that cannot both be honored, and is told so.

`exfat` is one word where the others are three, because the format has one revision and
every volume records it. The family is the finest answer there is, so there is no variant
to choose between. `btrfs` is one word for a related reason spelled differently. What
varies between two btrfs filesystems is a feature word and a geometry. Both are options
rather than a variant a `-t` value could name.

Within the ext family it seeds the whole feature set from that profile's baseline. The `-O`
list and the geometry options layer on top, exactly as they do for `mke2fs -t`:

```console
$ ferrosys format --size 256M --uuid "$(uuidgen)" --time 1700000000 -t ext2 rootfs.img
$ ferrosys format --size 256M --uuid "$(uuidgen)" --time 1700000000 -t ext3 rootfs.img
```

An image is judged by the features it carries, not the profile it started from, so the two
compose freely. `-t ext2 -O has_journal` writes exactly what `-t ext3` does, which is a
journal over the ext2 baseline, and `ferrosys inspect` labels either one `ext3`. The order
of `-t` and `-O` on the line does not matter. The profile is always the base, and `-O`
always layers on top.

### Feature words

Features are named on disk, and `-O` turns them on and off left to right over the selected
profile (ext4 unless `-t` says otherwise):

```console
$ ferrosys format --size 64M --uuid "$(uuidgen)" --time 1 \
      -O ^has_journal,^orphan_file,^metadata_csum_seed,^metadata_csum small.img
```

That clears the journal and the checksums, and leaves the rest of the profile intact.
`extent`, `64bit`, `flex_bg`, `huge_file`, `dir_nlink`, and `extra_isize` are all still
set. The image is therefore an ext4 one without a journal, and `ferrosys inspect` labels
it `ext4`.

`-t ext2` is not a shorthand for a list of `^` words. It selects a different base, and
reaching that base by clearing words means clearing every ext4-layer word, `extent`
included. Name the profile you want, and layer `-O` on top of it.

A combination that must never reach disk is refused by name. Dropping `has_journal` while
`orphan_file` remains is one, since the orphan file's entries are journaled. That is why
the line above clears both.

The same rule covers what the source holds, because a feature word is a promise about the
structures the filesystem carries. Two examples are refused by name and by path. Dropping
`ext_attr` from a source whose entries have extended attributes is one. Dropping
`large_file` from one holding a file of 2 GiB or more is the other. The attribute is
neither dropped nor written into a filesystem whose words deny it.

`^large_file` at the 4096-byte block size is refused on its own, before any source is read.
The resize inode a growable filesystem carries is itself a file that large.

`-O` reads btrfs's feature words too, in btrfs's own vocabulary — the words its tooling
takes and `ferrosys inspect` prints back, which are not ext's:

```console
$ ferrosys format --size 1G --fsid "$(uuidgen)" --time 1700000000 -t btrfs \
      -O ^block-group-tree old-kernel.img
```

That is the one most worth naming. A filesystem carrying `block-group-tree` needs a kernel
of 6.1 or newer. Clearing it is how you write an image for an older one.

The grammar is the same in both families. A bare word sets a feature, `^` clears it, and
`none` starts from nothing. The list applies left to right. The vocabularies are disjoint,
so a word belonging to the other family is refused rather than quietly ignored. A feature
this tool does not write is refused by name, and so is one whose prerequisites were not
asked for. `block-group-tree` rests on `free-space-tree` and `no-holes`, so clearing either
of those means clearing it in the same list.

### ext geometry and defaults

#### `--grow`

`--grow` sizes the reserved descriptor blocks that let the filesystem grow online without
relocating its descriptor table. It defaults to `max`, which reserves the most the format
allows. `--grow 4G` reserves exactly enough to reach a known target, and `--grow none`
reserves nothing.

#### `--block-size` and `--inode-size`

`--block-size` and `--inode-size` set the two sizes every other ext number is derived from.
A block is 1024, 2048, or 4096 bytes, and 4096 by default. An inode is a power of two from
128 up to the block size, and 256 bytes by default. A 128-byte inode holds no nanosecond
field and no creation time, so it is the choice that decides which times an image can carry.

#### `--journal`

`--journal` sizes the journal in filesystem blocks, where the default sizes it from the
filesystem. The journal is a real file and costs its size in free space, which is four
mebibytes of a sixteen-mebibyte filesystem. `-t ext2` writes none, and is the way to spend
that space on contents instead.

#### `--errors`

`--errors` sets what a kernel does when it detects an error in the filesystem. `continue`
notes it and carries on, `remount-ro` remounts read-only, and `panic` stops the machine. It
defaults to `continue`, which is the kernel's own default.

#### `--fixed-time`

`--fixed-time` forces every inode's times to one instant, whatever the source recorded. It
is for the image whose contents came from a tree whose timestamps are not reproducible.
`--time` alone stamps the filesystem, and this stamps everything in it.

#### `--hash` and `--hash-signedness`

`--hash` and `--hash-signedness` decide how a directory's names are hashed for its index.
The hash is `half_md4` by default, and `tea` and `legacy` are the alternatives. The
signedness decides whether a name's bytes are read as signed or unsigned, and it is
unsigned by default. That is what makes the hash independent of the host. A `char` is
signed on one architecture and unsigned on another. A directory hashed one way is not
readable by a kernel hashing the other.

#### `--label`

`--label` names the filesystem, up to sixteen bytes. A longer label is refused rather than
truncated, so the name a filesystem carries is the one that was asked for:

```console
$ ferrosys format --size 64M --uuid "$(uuidgen)" --time 1 --label rootfs fs.img
```

#### `--inodes` and `--bytes-per-inode`

`--inodes` and `--bytes-per-inode` set how many inodes the filesystem has, overriding the
count the size alone would choose. `--inodes 20000` names the count directly.
`--bytes-per-inode 16384` names the density it is derived from, which is one inode for
every so many bytes. The two share one setting, and the last given wins. A density that
would need more inodes in a group than its one-block bitmap indexes is refused rather than
quietly reduced.

A named count is a target, not a floor. It is spread across the groups. Each group's share
is rounded up to fill whole inode-table blocks, and then down to a multiple of eight. The
group's inodes therefore end on a byte boundary in the inode bitmap. That is the same
`s_inodes_per_group` `mke2fs` derives for the request.

The rounding meets or exceeds the request wherever an inode-table block holds a multiple of
eight inodes. Where a block holds fewer than eight, the multiple-of-eight step can leave
the realized total a few inodes short. That is the 1024-byte block at the default 256-byte
inode, and the 2048-byte block once `--inode-size 512` halves how many fit. `ferrosys
inspect` reports the count the filesystem actually carries.

#### `--reserved-percent`

`--reserved-percent` sets the share of blocks held back for the super-user, from 0 to 50,
with up to two decimal places. `--reserved-percent 1.5` reserves 1.5%. It defaults to 5.
The count is exact, `floor(blocks × percent)` in integer arithmetic, so a filesystem's
reservation is reproducible to the block.

#### `--json`

`--json` prints the geometry the format realized on the standard output:

```console
$ ferrosys format --size 64M --uuid "$(uuidgen)" --time 1 --json fs.img
{"schema":2,"family":"ext","variant":"ext4","uuid":"f0e17055-...","volume_name":"",
 "created":1,"features":[...],...}
```

Every JSON document this tool writes opens with the same `"schema"` field. The shape is a
contract of its own that no command-line signature describes, so it names its own version.
The receipt also carries `free_blocks` and `free_inodes`, read back from the filesystem
that was just written. A format's overhead is otherwise invisible, and on a small image it
is most of it. On a `--dry-run`, where no filesystem was written to have them, both are
`null` and `"written"` is `false`.

### Writing a FAT volume

An EFI System Partition is FAT and has no alternative, so it is the case this family exists
for:

```console
$ ferrosys format -t fat32 --size 512M --volume-id "$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')" \
      --time 1700000000 --label ESP --owner 0:0 \
      --accept-loss change-time,time-precision --from-dir esp-staging esp.img
```

`--volume-id` is this family's identity. It is a 32-bit serial number, taken as eight hex
digits in either the bare form or the dashed one every tool prints (`1A2B-3C4D`). It is a
separate option from `--uuid` rather than four bytes cut from one. A value silently
narrowed is a value you did not choose.

The type is what the geometry must *derive to*, not what gets written down. Nothing in a
FAT volume records which of the three it is, and every driver counts the clusters and
compares against two thresholds. So `-t fat32` on a size that cannot reach a FAT32 cluster
count is refused rather than written as a FAT16 wearing a FAT32 label.

The command line names a type outright. The library additionally offers the type the
geometry reaches on its own, and a FAT32 volume below the cluster count the specification
sets for one. That is a shape every mainstream driver reads and no specification blesses.
Asking for it is therefore explicit, and the command line does not ask.

`--label` goes through this family's own rules: eleven bytes, upper-cased, in the OEM
character set. A label the field cannot hold is refused rather than truncated, as on the ext
side. So is `--time`. A FAT directory entry represents 1980-01-01 through 2107-12-31 at a
two-second granularity. An instant outside that is refused rather than written as a
plausible-looking one inside it.

#### What a FAT volume cannot carry, and why the build stops

A FAT directory entry holds a name, one attribute byte, three coarse timestamps, a first
cluster, and a length. There is no field for an owner, a group, or permission bits. There
is none for a symbolic link, a second name for a file, a device number, or an extended
attribute. So a build that would drop any of those **fails and names the entry and the
property**. `--accept-loss` is how you name the ones that can go:

```console
$ ferrosys format -t fat32 --size 512M --volume-id 1A2B3C4D --time 1 \
      --from-dir staging esp.img
ferrosys: /EFI: a FAT volume cannot carry the ownership of this entry
```

Refusing is the default because the alternative is worse than inconvenient. A root
filesystem written to FAT with silent mode loss is a security bug wearing a convenience
feature's clothes. No report after the fact makes that acceptable.

A property counts as lost when the *value* does not survive, rather than when the format
has no field for it. That distinction is what keeps the acknowledgement meaningful. A read
of a FAT image fills an owner and a mode in from `--assume-owner` and `--assume-modes`,
which default to root and `0644`/`0755`. A root-owned tree of conventionally moded files
therefore goes in, comes back unchanged, and loses nothing by them.

Two losses a tree walked off a host always takes:

- `change-time`, because the format records no change time on anything.
- `time-precision`, because it stores a write time to two seconds and an access time to the
  day.

So the line above is the realistic minimum for `--from-dir`. Properties are named one by
one on purpose. A caller who accepted losing permission bits must not thereby have accepted
every symbolic link in the tree disappearing. That is the surprise the option exists to
prevent. `--accept-loss all` is the deliberate exception, and it covers a property a later
version names as well.

Set `--assume-owner` and `--assume-modes` to whatever the extraction will use, so the two
ends of a round trip agree about what survived. What the build did cost is the last thing
the summary prints, in the same words `--accept-loss` reads:

```console
DIRECTION  PROPERTY             ENTRIES
dropped    time-precision       4
dropped    change-time          4
```

A build that lost nothing says `nothing dropped or synthesized` rather than printing an
empty table, so silence never has to be interpreted.

### Writing an exFAT volume

An SDXC card specifies exFAT, and every current desktop operating system reads one as it
ships. This is the family for a card or a stick that has to be read somewhere else:

```console
$ ferrosys format -t exfat --size 8G \
      --volume-serial "$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')" \
      --label MEDIA --owner 0:0 \
      --accept-loss change-time,time-precision --from-dir card-staging card.img
```

`--volume-serial` is this family's identity. It is the `VolumeSerialNumber` both boot
regions record, taken as eight hex digits in either the bare form or the dashed one every
tool prints. It is a third option rather than a reuse of `--volume-id`, because it is a
different field of a different format. The two being the same width is a coincidence of the
lineage, not a shared value.

There is no `--time` here, and the absence is the format's. An exFAT volume records no
instant of its own anywhere. Every time on it belongs to an entry, and comes from the
source that named it. The flag is refused for this family, the way every option of a family
that was not named is.

`--label` goes through this family's own rules again. It takes up to eleven UTF-16 code
units, which is eleven *characters* rather than eleven bytes for anything outside ASCII.
It takes text rather than bytes. The format stores a label as code units, so there is
no encoding to guess for bytes that are not text. As everywhere else, a label the field
cannot hold is refused rather than truncated.

This family does two things its neighbor cannot. A **name is stored whole**, up to 255
UTF-16 code units, in the case it was given, with no second shortened name derived beside
it. What goes in is therefore what a listing shows. A lookup also folds through the
**volume's own up-case table**. A path in any case therefore reaches the entry a driver
reading the same volume would reach:

```console
$ ferrosys extract card.img --cat /DCIM/IMG_0001.JPG
$ ferrosys extract card.img --cat /dcim/img_0001.jpg   # the same file
```

The one thing this family does not do is `--size auto`. That search plans candidate sizes,
and places the contents into each until the smallest one that holds them is found. The
search is a family's own, and this one has none. `--size auto -t exfat` is therefore refused
while the command line is being read, before a source is opened, so nothing is walked to say
so. Name a size.

#### What an exFAT volume cannot carry

The same properties a FAT volume cannot, for the same reason. An entry set records a name,
five attribute bits, three times, and two lengths. It has no field for an owner, a group, or
permission bits. It has none for a symbolic link, a second name for a file, a device number,
or an extended attribute.

`--accept-loss`, `--assume-owner` and `--assume-modes` mean exactly what they mean for FAT.
A build that would lose something you have not named fails, and says which entry and which
property.

What differs is how much *time* survives, and it is worth knowing before choosing between
the two families. exFAT records a creation and a modification time to ten milliseconds, and
each of its three times with a UTC offset. FAT records a write time to two seconds, an
access time to the day, and no zone at all. A volume this tool writes says its times are UTC
rather than leaving a reader to guess a locality. A host tree still loses `time-precision`,
because exFAT's access time is two-second granular like FAT's. It loses far less of it.

### Writing a btrfs filesystem

Fedora and openSUSE default to btrfs, and both lay out subvolumes rather than one flat tree.
This is therefore the family for a distribution root image, and the layout is the point
rather than a refinement:

```console
$ ferrosys format -t btrfs --size 8G --fsid "$(uuidgen)" --time 1700000000 \
      --label fedora --owner 0:0 \
      --subvol "$(uuidgen):/@" --subvol "$(uuidgen):/@home" --default-subvol /@ \
      --from-dir root-staging root.img
```

`--fsid` is this family's identity. It is the id `blkid` reports, and the id a `UUID=` line
in `/etc/fstab` names. It is taken as 32 hex digits in either the bare form or the dashed
one. It is a fourth option rather than a reuse of `--uuid`, because it is a different field
of a different format. The two being the same width is a coincidence.

**A btrfs records five identifiers**, and the other four have options of their own.
`--metadata-uuid` is the id every tree block is stamped with, where it is to differ from the
visible one. That is what lets the visible id change later without rewriting every block,
and what a filesystem records as a feature bit in that state.

`--chunk-tree-uuid`, `--device-uuid`, and `--subvolume-uuid` are the chunk tree's, the
device's, and the top-level subvolume's. Each defaults to zero, which is a legitimate value
and an obviously unset one. None of them is derived from another. A filesystem whose bytes
you can reproduce is one that states all five. A value this tool invented would be a value
you could not state.

`--subvol [ro:]UUID:PATH` makes the source directory at `PATH` the root of a subvolume of
its own. It is repeatable, and **each needs its own identifier**. The filesystem's UUID tree
is keyed by them, so two subvolumes sharing one would produce a tree with a repeated key.
The command line says so by name, rather than letting the writer discover it. `ro:` in front
makes one read-only. The identifier leads and the path is everything after it, so a path can
contain a colon.

`--default-subvol PATH` says which subvolume a mount that was told none lands on. Without it
a mount lands on the top-level tree every btrfs starts with, which `subvolid=5` names. That
is rarely what a root image wants:

```console
# mount -o subvol=@ root.img /mnt        # what --default-subvol /@ makes the default
```

A subvolume root is still a directory. The source declares it as one and `--subvol` says how
to lay it out, which is why the same staging tree feeds every family unchanged. A hard link
cannot span two subvolumes, and no btrfs holds one. A source naming one is refused rather
than silently written as two files.

`--label` is up to 255 bytes, taken as they come. The superblock's label field records no
encoding, so what you supply is what every reader of the image sees. A label the field
cannot hold is refused rather than truncated, as everywhere else.

The geometry is four options. `--sector-size` is the smallest addressable unit of file data,
and `--node-size` is the size of a tree block. Each is a power of two from 4K to 64K,
defaulting to 4096 for the sector size and 16K for the node. The node size decides how much
a leaf holds, and so how large a file can be before it stops fitting inside the metadata.

`--metadata-profile` and `--data-profile` say how each kind of block group is replicated.
`dup` writes two copies on the one device, which is what protects the trees against a bad
sector, and `single` writes one. Metadata defaults to `dup` and data to `single`, which is
what the format's own tooling does on one device.

Unlike the other three families, **nothing is lost on the way in**. btrfs has a field for
every property a source states:

- An owner and a group.
- A full mode.
- A link count.
- A device number.
- Four timestamps, each to the nanosecond.
- As many names per object as you give it.
- An extended attribute, as a record of its own.

`--accept-loss` is therefore not an option this family takes, and a build here never refuses
a tree for what it cannot hold. The format summary says so in a line rather than by silence.

`--size auto` is refused for this family, as it is for exFAT and for the same reason. The
search behind it plans candidate sizes and places the contents into each, and that search is
a family's own. Name a size.

The smallest a btrfs can be is 109 MiB at the default profile pairing, and 45 MiB at
`--metadata-profile single`. A volume below whichever applies is refused with the number it
would have taken.

#### Two btrfs images from one directory can differ, and it is the directory that changed

Everything above holds the general rule: the same inputs write the same bytes. What is worth
knowing for this family in particular is what counts as *the same inputs* when the input is a
host directory tree.

Walking a tree reads its files, and on a filesystem that records access times, reading a
file updates that file's access time. btrfs is the one family here that stores an access
time to the nanosecond, so it is the one where that shows. Two `--from-dir` builds of one
tree, run one after the other, can differ by a millisecond in every entry's `atime`. The
tool read no clock. The tree it was pointed at was not the same tree twice.

If images have to be byte-identical across runs, give the build a source that reading does
not change. `--from-tar` is one, and its member times are in the archive. Mounting the
staging tree `noatime` is another, and so is stamping the tree's times before each build.

Every other input is already fixed. `--time` and the five identifiers are values you state,
and nothing else in the tool reads anything but the source.

### A small partition

A format's defaults are sized for a general-purpose filesystem, and on a small one they
cost more than they are worth. Two of them dominate. The growth headroom (`--grow`) is one.
The journal is the other, and it is a real file costing its size in free space, which is
4 MiB of a 16 MiB filesystem. On a partition that will not grow and does not need a
journal, say so:

```console
$ ferrosys format --size 16M --uuid "$(uuidgen)" --time 1700000000 \
      -t ext2 --grow none --reserved-percent 0 boot.img
```

That leaves 3830 of the 16 MiB image's 4096 blocks free, which is 93.5% of it usable,
against 2710 at the defaults. If the partition will be mounted read-write and power loss is
a real risk, keep the journal (`-t ext3`). Drop it where the partition is written once and
read afterwards, which is what a boot partition usually is. The format summary reports what
was reserved and what is left free, so the cost of any combination is one command away.

## `inspect`

```console
$ ferrosys inspect rootfs.img
Filesystem family:          ext
Filesystem variant:         ext4
Filesystem size:            67108864
Allocation unit:            4096
Filesystem identifier:      f0e17055-0000-4000-8000-000000000000

Filesystem UUID:            f0e17055-0000-4000-8000-000000000000
Filesystem magic number:    0xEF53
Filesystem features:        has_journal ext_attr resize_inode dir_index orphan_file ...
Inode count:                16384
Block count:                16384
...

no findings
```

Every report opens with the same five lines, whatever the image holds. Those are which
family, which variant of it, how large it is, what it allocates in, and what identifies it.
Everything after them is that family's own:

- An ext image describes itself in superblock fields.
- A FAT volume describes itself in its parameter block.
- An exFAT volume describes itself in its boot region.
- A btrfs describes itself in its superblock, its chunk map, and its trees.

So a tool that only wants to know what an image is, and whether it is sound, reads the head
and stops:

```console
$ ferrosys inspect esp.img
Filesystem family:          fat
Filesystem variant:         fat32
Filesystem size:            67108864
Allocation unit:            512
Filesystem identifier:      1A2B-3C4D

Volume label:               ESP
Volume serial number:       1A2B-3C4D
Type string:                FAT32
OEM name:                   ferrosys
Bytes per cluster:          512
Allocation tables:          2
Sectors per table:          1009
Clusters:                   129022
...

no findings
```

The FAT body reports the volume's own claim about its type beside the count the head's
variant was derived from. No driver reads that string, because the type follows from the
cluster count and from nothing else. A volume whose string disagrees with its geometry is
read by its geometry, and this is the one place the disagreement is visible.

An exFAT report is the same envelope over a third body, and the four fields it leads with
are ones no boot sector holds:

```console
$ ferrosys inspect card.img
Filesystem family:          exfat
Filesystem variant:         exfat
Filesystem size:            8589934592
Allocation unit:            32768
Filesystem identifier:      5E71-A10C

Volume label:               MEDIA
Volume state:               clean
Percent in use:             3%
Bytes per cluster:          32768
Clusters:                   262016

Allocation bitmap at cluster: 2
Up-case table at cluster:   3
Root directory at cluster:  4
...

no findings
```

Where the allocation bitmap and the up-case table are, and how long each is, are recorded
nowhere but in the root directory. The format stores them as ordinary directory entries.
Those lines are therefore what a reading of that directory recovered, rather than a field
read off the boot sector.

`Volume state` is the other thing only this family reports. It is the two flags a mounted
driver writes, which sit outside the boot checksum precisely so it can. A volume that was
not cleanly unmounted is reported and is not a fault. A strict read of a card somebody
pulled out of a reader therefore still succeeds.

A btrfs report is the same envelope again, over the one body in this tool that describes two
layers, because the format has two. Above is a logical address space with the trees on it.
Below is a chunk map that translates every address in it onto the device. A filesystem whose
trees all verify and whose map is missing a range is a different report from one where both
are sound. Both are therefore there:

```console
$ ferrosys inspect fedora-root.img
Filesystem family:          btrfs
Filesystem variant:         btrfs
Filesystem size:            8589934592
Allocation unit:            4096
Filesystem identifier:      1b4e28ba-2fa1-11d2-883f-0016d3cca427

Label:                      fedora
Metadata identifier:        1b4e28ba-2fa1-11d2-883f-0016d3cca427
Generation:                 42
Bytes used:                 1735983104
Sector size:                4096
Tree block size:            16384
Filesystem features:        free-space-tree free-space-tree-valid block-group-tree ...
Superblock copies:          present, present, outside the device

Mapped chunks:              5
Mapped bytes:               2214592512

ROOT_TREE at:               30523392 (level 0)
CHUNK_TREE at:              22036480 (level 0)
EXTENT_TREE at:             30507008 (level 1)
...

Subvolume <top-level>:      id 5
Subvolume root:             id 256, default
Subvolume home:             id 257

no findings
```

The last section is the one nothing else in this tool has. A subvolume is a filesystem tree
inside the filesystem, with inode numbers of its own. Someone points this command at a
btrfs to ask which ones are on an image. They ask, too, which is the default a mount
reaches with no `subvol=`. The top-level tree is a subvolume too, and it is the one no
directory entry names.

`Filesystem features` is one list across the three words the superblock carries, in the words
`format -O` takes. A feature read off a report can therefore be typed straight back into a
format. Nothing has to be translated from the all-capitals spelling the format's own header
uses.

A bit no feature of this crate's own table covers is reported on its own line, as the word
it belongs to and its value. That line is there whether or not any such bit is set. An
image carrying something this tool does not understand can therefore never read as one it
does.

`Superblock copies` is listed one entry at a time rather than counted, because which copy is
damaged is what a person acts on. The format writes a copy at each of three fixed locations
the device is long enough to hold all of. A filesystem smaller than 256 GiB therefore has
two, and two is the whole count for it.

An option belonging to one family is refused for another rather than passed over.
`--groups` reports the block-group descriptors of an ext filesystem. A FAT or exFAT volume
has one flat cluster heap, and a btrfs is divided by a chunk tree instead. Asking for them
there is a question with no answer, and is told so. A report that quietly omitted the
section would read as a volume with no groups in it, which is a different claim.

The whole image is scanned by default: every group descriptor, bitmap, inode, extent
tree, and directory block, with each metadata checksum recomputed. That is what makes a
bad image *bad* (exit 4) rather than merely described. `--quick` reports the superblock
alone and reaches no verdict. It cannot be combined with `--fail-on`, which is a verdict on
the scan `--quick` skips. The two together would be a CI gate that looks armed and exits 0
on a filesystem whose bytes are destroyed. They are refused rather than accepted with one of
them inert.

`--fail-on` moves the line at which the scan's findings make the filesystem bad. It defaults
to `integrity`. A filesystem is bad when its own bytes contradict each other, which is a
checksum that does not match what it covers. It is bad, too, when a structure the reader
must follow cannot be followed.

The threshold below it, `conformance`, means something else, and is worth knowing about
before you reach for it. It faults a filesystem that is *valid for its format but not the
form this tool writes*. A filesystem `mke2fs` or `mkfs.fat` made is exactly that, and it is
not thereby broken. So `conformance` is a check on this tool's own output, an opt-in
self-check, and not what `inspect` does by default.

The four severities mean the same thing for every family. The categories a finding falls
into do not, and are each family's own. A superblock and a boot sector are not one subsystem
under two names. `--fail-on structural` faults only an image whose structures cannot be
followed at all. `--fail-on never` reports every finding and exits 0 regardless, which is
what to use when you want the report and not the judgment.

`--groups` is bounded the same way and for the same reason. A superblock's group count is
its own claim, and a crafted one reaches four billion. The listing stops at a million
groups and says how many of the claimed total it showed. It does not grow to a count no
image behind it could hold. The JSON report carries the same fact as `"groups_complete"`.

A scan reads an image it has no reason to trust, so what it collects is bounded. It stops
at ten thousand findings and says so, in the table, in the `"truncated"` field of the JSON
report, and as a SARIF notification. A truncated report is a floor. The image holds at
least these findings, and the rest of it went unread, so the verdict it reaches reads
"at least *n* findings". Ten thousand findings is far past what a filesystem needs to be
called bad.

`--groups` adds every block group's descriptor. `--json` reports the same data as a JSON
document, shaped as the same envelope the table is. That is a head which means the same
thing whatever the image holds, then a body named for the family:

```console
$ ferrosys inspect --json rootfs.img
{"schema":2,"family":"ext","variant":"ext4","size":67108864,"allocation_unit":4096,
 "identifier":"f0e17055-...","offset":0,"findings":{"schema":2,"clean":true,"count":0,
 "truncated":false,"findings":[]},"ext":{"superblock":{...},"features":{...}}}
```

The head is six fields and the findings. The body under `"ext"` carries the superblock, the
feature names split by word, the unknown feature bits, and with `--groups` every group
descriptor. The unknown bits are reported whether or not there are any. An image carrying a
feature the tool does not know can therefore never read as one it understood.

A consumer that reads only the head never learns what a block group is. One that wants
ext4's geometry reads the body. A later filesystem family adds a body beside `"ext"` rather
than reshaping anything above it.

The two dialects differ in one way on purpose. The table omits a row it has nothing to say
in, because a person reading a report wants what is there. An image with no journal grows no
journal rows.

The JSON body's shape is fixed instead. The same keys are present for every image of a
family, carrying the value the filesystem holds. A consumer therefore indexes a key without
first asking whether this image has one. That is why the document carries a field or two the
table does not print.

Every finding carries its severity, the family that found it, that family's own word for the
subsystem, and the byte offset when there is one. It carries that family's own coordinates
as well. Those are `{"group":3,"inode":12,"block":40}` for an ext image, and whatever
addresses a finding in some other format.

`--sarif` reports the scan's findings as a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
log, so a static-analysis or forensic pipeline can consume them as it would any other
tool's. It reports those findings alone,
and not the superblock description.

Each finding becomes one result. Its severity maps to the SARIF level, where `structural`
and `integrity` are `error`, `conformance` is `warning`, and `cosmetic` is `note`. The exact
severity travels in the result's `properties`, together with the family, the subsystem, the
byte offset, and the coordinates it sits at. A rule is named `family/subsystem`, so two
formats that both call something a `directory` do not merge into one rule.

`--sarif` reports scan findings, so it runs the scan and cannot be combined with `--quick`.
It selects a different output format from `--json`:

```console
$ ferrosys inspect --sarif rootfs.img > findings.sarif
```

`--offset` reads a filesystem that begins partway into a larger file — a partition inside
a whole-disk image:

```console
$ ferrosys inspect --offset 1M disk.img
```

The JSON document carries that coordinate back as `offset`, the same field `detect --json`
carries. A caller that scanned a disk and then described what it found lines the two
documents up by it.

## `extract`

Exactly one of five things comes out.

Whatever the family, what comes out is the filesystem rather than one of its parts. On a
btrfs that is worth saying plainly, because the format has parts a path could stop at and
does not. A subvolume is a filesystem tree of its own, with inode numbers that start again
from the same value the top-level tree's do. Every mode here crosses that boundary the way
it crosses a directory.

`/home/user/notes` reaches the file whether or not `/home` is a subvolume, and a listing of
the image names everything in every subvolume once. Symbolic links are resolved through as
well. A path continuing through `/bin` on a tree where that is a link into `/usr` therefore
reaches what it names.

A btrfs also stores a file's bytes compressed where a mount was told to. Every distribution
that defaults to this filesystem tells it to for at least some of the tree.
This binary carries the three decoders the format defines, which are DEFLATE, LZO1X, and
Zstandard. A file stored that way comes out as the file rather than as a refusal. The
checksums are checked either way. They cover the bytes the filesystem stored, so `inspect`
verifies a compressed extent without expanding it.

### A tar archive

Ownership, modes, symlinks, hard links, and device and FIFO nodes travel in the header. The
paths, the ids, the times (to the nanosecond, and negative for a file older than the epoch),
the extended attributes, and the POSIX ACLs travel in PAX records, because the header cannot
hold them. GNU tar and bsdtar both read it.

```console
$ ferrosys extract rootfs.img --to-tar rootfs.tar
$ ferrosys extract rootfs.img --to-tar - | tar -tv
```

The archive opens with a `./` member describing the root directory and omits
`/lost+found`, which every filesystem makes for itself. What comes out is what
`format --from-tar` reads back in, so a filesystem survives a round trip through the
archive unchanged.

A socket is the one thing tar cannot express, because it has no entry type for one. An
image holding a socket is a typed error rather than an archive quietly missing a file.

That refusal comes part-way through the walk, as an inode that does not read does, and as an
ACL that does not decode does. A named destination is created and truncated before the walk
starts. `--atomic` covers that, as it does for `format`. The archive is written to a sibling
temporary file, and renamed over the destination once the walk is complete. A walk that
fails therefore leaves whatever was at that path untouched.

`--atomic` applies to `--to-tar FILE`, the only mode with a destination to rename into.
Asking for it anywhere else is refused rather than accepted and ignored.

```console
$ ferrosys extract rootfs.img --to-tar rootfs.tar --atomic
```

### A directory tree

This is `format --from-dir` in reverse:

```console
$ ferrosys extract rootfs.img --to-dir unpacked
Names written:          1284
```

The destination is made if it is not there, and it must be empty. An extraction states what
the filesystem holds. A name already present would be an entry that could not be created,
found part-way through with the tree half written. The destination takes the filesystem
root's own mode, ownership, times, and extended attributes. Everything the filesystem holds
appears beneath it at the path it holds inside the image. `/lost+found` is not written, so
the tree is one `format --from-dir` reads straight back.

Everything the archive carries is carried here too, set on the files themselves. That is
modes, ownership, symlinks, hard links, device and FIFO nodes, sockets, extended attributes,
and POSIX ACLs. Two things no host lets a caller set, so the tree carries the time it was
written for those two alone. They are an inode's **change time** and its **creation time**.
Access and modification times are set exactly, to the nanosecond.

Four parts of a tree need privileges:

- A device node needs `CAP_MKNOD`.
- Setting a recorded owner needs `CAP_CHOWN`.
- An extended attribute in the `security` or `trusted` namespace is the host's to write.
- A destination filesystem with no notion of a second name for a node refuses a hard link.

An unprivileged run therefore stops at the first of them and names it. That is the right
answer for a tree meant to be faithful. A rootfs quietly missing `/dev/null` is a rootfs
that boots differently, and one whose `ping` lost its `security.capability` is one that no
longer runs unprivileged.

`--skip-privileged` is the opt-in for a run that wants what it can have. What it left out is
named on the standard error rather than assumed:

```console
$ ferrosys extract rootfs.img --to-dir unpacked --skip-privileged
Names written:          1282
Ownership:              not applied — this process may not set another owner
Attributes:             not applied — this process may not set security or trusted attributes
Skipped:                /dev/console
Skipped:                /dev/null
```

The reserved attributes are what an unprivileged extraction of a real root filesystem meets
first. A Debian tree carries `security.capability` on the binaries that hold one, and a tree
built under SELinux carries `security.selinux` on nearly every inode.

A file's contents are written as the filesystem reports them, and a hole reads as zeros. A
sparse file therefore lands in the destination fully allocated. A tree holding one occupies
more space on the host than it does in the image.

A directory's mode is applied once its contents are in place, so one the image records as
read-only still receives them. One recorded *without owner-search permission* waits until
the whole run is done. A second name for a hard-linked file is written by traversing to the
first, and a directory that cannot be searched cannot be traversed. Applying such a mode
early is what would make an ordinary user's extraction of an ordinary image fail part-way.

The image is untrusted input, and a name in it is not a path to resolve. Every directory is
created and then *opened*, and everything beneath it is created through that open handle by
its single-component name. A name holding a separator, a `..`, or a NUL is therefore refused
rather than followed, and nothing lands outside the destination.

The reader refuses such a name too, where it resolves it. Both `--to-dir` and `--to-tar` are
therefore safe against one, and neither depends on the other's check. No path through the
destination tree is walked a second time. Nothing swapped into it while a run is in flight
can redirect a write. Symbolic links are written exactly as the image records them,
absolute targets and all, which is safe precisely because nothing here ever follows one.

There is no `--atomic` for a tree: no rename publishes a whole tree at once, and inventing
one would promise something the run cannot do. The empty destination is what stands in its
place. A failure part-way leaves a partial tree in a directory that held nothing, rather
than mixed into one that did.

### How strictly the image is held to its format

Extraction is the one command whose output is the image's contents. What it makes of a
filesystem it does not fully understand therefore matters more here than anywhere else. An
image carrying a feature this reader does not follow can be interpreted best-effort, and the
result looks complete without being it.

So the strict read is tried first, always. `--strict` makes its refusal the answer. Without
it, the read falls back to a lenient one, which is what makes a damaged or unfamiliar image
recoverable at all. That read names on the standard error the deviation it decided to
interpret through:

```console
$ ferrosys extract odd.img --to-dir unpacked
ferrosys: reading odd.img leniently: unsupported incompat features: 0x400
ferrosys: what it holds is interpreted best-effort; --strict refuses instead
```

A run that says nothing read an image it could hold to its format entirely.

### What a filesystem does not record

`--assume-owner U:G` and `--assume-modes F:D` say what to record where the filesystem being
read has no field for it. They change nothing about an ext image. ext records an owner, a
mode, and three times on every entry, so what comes out is what was stored. They change
nothing about a btrfs either, which records those and a creation time besides.

They exist because a FAT volume does not. A format with no notion of an owner still has to
become host files with *some* owner, and something has to decide which. Every driver that
mounts such a format has `uid=`, `gid=`, `fmask=`, and `dmask=` mount options for exactly
this reason. Here the same decision is a flag, and its default is the conservative one. That
default is root ownership, `0644` for a file and `0755` for a directory, and never anything
more permissive. A tree that landed world-writable because nothing was named would be a
security bug made out of a format limitation.

Whatever was assumed is reported on the standard error beside what the host refused. An
extraction therefore says which parts of the tree came from the image, and which were
policy:

```console
Assumed:                ownership (1282 entries)
Assumed:                permissions (1282 entries)
Assumed:                change-time (1282 entries)
```

The properties are named in the same words `format --accept-loss` reads. A property an
extraction reports can therefore be typed straight back into the build that would preserve
it.

### One file's bytes

Nothing else goes to the standard output:

```console
$ ferrosys extract rootfs.img --cat /etc/hostname
ferrosys
```

The path is a path *inside the image*, taken as the bytes you typed, because an ext4 name
need not be text. Symbolic links are followed against the image's own root, so `/lib/modules`
resolves on a merged-`/usr` tree where `/lib` is a link into `/usr`. A `..` component
ascends, whether you wrote it or a link in the image stores it. `/usr/lib64 -> ../lib` is
the shape a multiarch root filesystem has.

At the root there is nothing to ascend to, so a run of them stays there. Every path names
something inside the image, and nothing here reaches the machine reading it.

### A listing

```console
$ ferrosys extract rootfs.img --list
drwxr-xr-x   2      0      0       4096 2023-11-14T22:13:20Z /etc
-rw-r--r--   1   1000   1000          9 2023-11-14T22:13:20Z /etc/hostname
lrwxrwxrwx   1      0      0         17 2023-11-14T22:13:20Z /etc/mtab -> /proc/self/mounts
```

`--list --json` produces the same listing as a JSON document. It adds each entry's inode
number, its extended attributes, and any POSIX ACL decoded into readable entries. The inode
number is what tells one file with two names from two files with the same contents.

A field the family has no notion of is **absent** rather than null or zero. A FAT entry
carries no `inode` and no `links`, because the format has neither inode numbers nor a
second name for a node. A one there would be this tool answering a question the format never
asked. What it does carry is a `synthesized` list naming the properties the report filled in
rather than read. That list is always present, empty or not, so "the image recorded
everything" and "this document did not say" stay distinguishable. In the table the
link-count column reads `-` for such a family, which keeps the columns where a reader
expects them.

### One path's metadata

This is the answer to "what is `/usr/bin/ping`, exactly" without listing a hundred thousand
other lines:

```console
$ ferrosys extract rootfs.img --stat /usr/bin/ping
Path:                   /usr/bin/ping
Inode:                  15
Type:                   file
Mode:                   0755 (-rwxr-xr-x)
Owner:                  0:0
Links:                  1
Size:                   76672
Blocks:                 152
Accessed:               2023-11-14T22:13:20Z (0 ns)
Modified:               2023-11-14T22:13:20Z (0 ns)
Changed:                2023-11-14T22:13:20Z (0 ns)
Created:                2023-11-14T22:13:20Z (0 ns)
Xattr security.capability: \x01\x00\x00\x02\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
```

It reports the type, the mode both ways, ownership, size, and times. Where the family
records them, it also reports the inode number, the link count, a device node's numbers, a
symlink's target, and every extended attribute. A stored POSIX ACL is decoded rather than
shown as bytes. A path naming a symlink describes the link itself, not its target. `--json`
reports the same as a document.

On a family that records fewer of them the report is shorter, and it says what it assumed:

```console
$ ferrosys extract esp.img --stat /EFI/BOOT/BOOTX64.EFI
Path:                   /EFI/BOOT/BOOTX64.EFI
Type:                   file
Mode:                   0644 (-rw-r--r--)
Owner:                  0:0
Size:                   76672
Accessed:               2023-11-14T00:00:00Z (0 ns)
Modified:               2023-11-14T22:13:20Z (0 ns)
Changed:                2023-11-14T22:13:20Z (0 ns)
Created:                2023-11-14T22:13:20Z (640000000 ns)
Assumed:                ownership, permissions, change-time
```

Three things to read out of that. There is no `Inode:` and no `Links:` line, because the
format has neither. The access time is midnight, because FAT records a date and no time of
day for it. And the change time equals the modification time, because the format records no
change time at all and the closest thing it has stands in. That is what the `Assumed:`
line is there to say.

An attribute's value is bytes, and it is rendered the way a name is. Printable characters go
out as themselves, and everything else as a `\xNN` escape, with the backslash escaping
itself so the rendering names exactly one value.

A bidirectional formatting character is escaped too, as `\u{202e}`. It is not a control
character, and left alone it reorders the rest of the line, so `photo\u{202e}gnp.exe` would
display as `photo exe.png`. To read the bytes rather than look at them, take `--json`. A
value that is not text carries a `value_hex` field beside it holding the bytes exactly. The
field's presence is itself the signal that the value is not text.

A JSON document escapes both classes as well, as the `\uXXXX` escape the grammar defines. A
parser therefore reads back the character the name held, and nothing between the document
and the parser acts on it. The same rule covers every name a document carries: a path, a
symlink target, an attribute name, a volume label.

In a JSON document the `mode` field is the permission bits as a **decimal** number, since
JSON has no octal literal, so `509` is `0o775`. `mode_octal` beside it carries the usual
spelling.

`--stat` reports more of an entry than `--list` does. It adds a creation time, the extended
attributes, a device node's numbers, and, where the family records it, how many blocks the
entry occupies. A listing leaves those out on every family, including the families that
record them. Reading them costs a read per entry, and a listing is the shape a caller uses
to walk a whole tree.

So a field's absence from a listing entry means "a listing does not carry this". A field's
absence from `--stat` means "this filesystem does not record it". When the question is what
one path holds, `--stat` is the answer that leaves nothing out.

### Reading an image you do not trust

A file's size is the image's own claim about it, and a sparse file legitimately dwarfs the
filesystem holding it. Nothing structural therefore bounds what a read of one would write.
An inode claiming sixteen tebibytes and mapping nothing costs an extraction sixteen
tebibytes of zeros, from an image of a hundred kilobytes. A hole reads back as zeros and
occupies nothing.

So `extract` caps it whether or not you ask. The default is **sixteen times the length of
the filesystem being read**, which no ordinary file approaches and no crafted one survives.
`--max-file-bytes N` names a different cap, for an image that holds a file legitimately
sparser than that:

```console
$ ferrosys extract suspect.img --cat /etc/passwd --max-file-bytes 64M
$ ferrosys extract sparse.img --to-dir out --max-file-bytes 512G
```

There is no spelling for "no cap", and none is needed. The cap is a size, so a run that
means to read a file of some size names that size.

Over the cap the read is an **error**, not a short file. A truncated file that looked whole
would be the worse outcome, because a pipeline would carry it forward and never know. Where
the cap that stopped a read was the default rather than one you named, the command says so
on the standard error. It also says what raises it.

The cap is the same cap in every mode and on every family. `--cat` streams a file into the
standard output and holds nothing, and it answers to the cap all the same. What a stream
*writes* follows the length the image declares, so a mode that streamed without the cap
would be the one way past it. A flag that meant something different depending on which
family answered would be the worst of both.

## `detect`

```console
$ ferrosys detect rootfs.img
ext4
$ ferrosys detect --offset 1M disk.img
ext2
$ ferrosys detect esp.img
fat32
```

One word goes to the standard output, so it reads well in a shell test. That word is
`ext2`, `ext3`, `ext4`, `fat12`, `fat16`, `fat32`, `exfat`, `btrfs`, or `unrecognized`.
`--json` produces a document instead.

For every family this tool writes it is the same word `format -t` takes. What `detect` says
about such an image is therefore what you would type to write another like it. `btrfs` is
the word for a family it reads. `--offset` points it at a partition inside a whole-disk
image, or at a region a carver located.

One further answer, `unknown`, is what a tool prints when the library classifies a family
that build has no name for. Something recognized the image, so `unrecognized` would be the
wrong word for it.

The families are tried in order of how distinctive their magic is. ext, and any family with
a multi-byte magic at a fixed offset, are classified first. FAT is classified last and never
by its boot signature. `0xAA55` at the end of sector 0 appears on every bootable sector
ever written. That includes the master boot record of a disk whose *partition* holds an
ext4 filesystem.

A FAT volume is claimed only when the whole parameter block is internally consistent. That
is what keeps a healthy filesystem of another family from being misidentified as this one.

This asks what an image *is*, not whether it is sound. An image with a quirk `inspect`
would refuse still classifies here. An unrecognized image exits 8, since there is no
filesystem to have an opinion about.

## `identity`

```console
$ ferrosys identity --uuid "$(uuidgen)" --label rootfs rootfs.img
3 superblock copies written, journal superblock updated
```

Changes what an existing ext filesystem is known by: its UUID, its volume label, or the seed
its metadata checksums derive from. It is the one command that writes to an image it did
not create, and the only one whose destination already holds something worth keeping.

Every superblock copy is rewritten, the primary and each group's backup alike. So is the
journal's own record of the UUID. No copy is left claiming the old identity. Each copy
is patched where it lies, and keeps every field this change does not name, including the
ones this tool has no opinion about.

Nothing is written until every copy has been read and every check has passed, so a refusal
leaves the image exactly as it was. There is no `--atomic`. An image is rewritten in place,
and a sibling temporary file would mean copying every byte of it to change sixteen.

The journal keeps its own copy of the UUID, and on most images a checksum over it. Linux
sets `csum_v3` on the log of any `metadata_csum` filesystem the first time it mounts one. An
image that has ever been used therefore carries a crc32c covering the whole journal
superblock. A rescue image being cloned is one such image, and so is a rootfs that was
booted once and is now being re-stamped per device. That word is recomputed with the UUID,
so the log stays one the kernel will load.

A journal whose stored checksum does not match its contents is refused, as a damaged
filesystem superblock is. Writing a correct checksum over wrong bytes would replace a fault
a checker finds with one it does not.

At least one of `--uuid`, `--label`, and `--set-checksum-seed` is required. A run that would
write nothing is a command line that meant to say something.

`--offset` points it at a filesystem inside a whole-disk image, as every image-reading verb
takes one. This command rewrites ext identity fields. Pointed at a sound volume of another
family, it refuses with the word `detect` prints for what the image holds. The volume is
fine and the request does not apply to it. That is a different verdict from a damaged
filesystem, and it carries a different exit code.

### When the UUID is the checksum seed

```console
$ ferrosys identity --uuid "$(uuidgen)" legacy.img
legacy.img: changing the UUID would invalidate every metadata checksum: this filesystem
has metadata_csum without metadata_csum_seed, so its checksums are seeded from the UUID
itself — set the checksum seed to keep them valid
$ ferrosys identity --uuid "$(uuidgen)" --set-checksum-seed legacy.img
1 superblock copies written, journal superblock updated, metadata_csum_seed set
```

Under `metadata_csum`, every metadata object in the filesystem carries a checksum seeded
from the filesystem's seed. Those objects are each group descriptor, inode, bitmap,
directory block, and extent node. Where `metadata_csum_seed` is set, that seed is a
superblock field and the UUID is free to move. Where it is not, the seed *is* the UUID, so
changing the UUID invalidates every checksum in the image at once.

That is refused rather than half-performed. `--set-checksum-seed` is the way through. It
records the seed the current UUID implies and turns `metadata_csum_seed` on, after which
the UUID moves and every existing checksum stays valid. It is asked for rather than assumed
because it sets an incompatible feature. A kernel that does not know `metadata_csum_seed`
will not mount the result.

Images `ferrosys format` writes carry `metadata_csum_seed` already, so this is a question
about filesystems made elsewhere.

## A round trip, end to end

```console
$ tar -cf rootfs.tar -C rootfs .
$ ferrosys format --size 512M --uuid "$(uuidgen)" --time 1700000000 \
      --from-tar rootfs.tar rootfs.img
$ ferrosys inspect rootfs.img
$ ferrosys extract rootfs.img --to-tar - | tar -tv
```

Or with a tree at both ends, and the size taken from the tree rather than named:

```console
$ ferrosys format --size auto --slack 20% --uuid "$(uuidgen)" --time 1700000000 \
      --from-dir rootfs --owner 0:0 rootfs.img
$ ferrosys extract rootfs.img --to-dir unpacked --skip-privileged
```

Every time is UTC, printed as `YYYY-MM-DDTHH:MM:SSZ`. The tool has no time zone and no
locale.
