# The `ferrosys` command line

The `ferrosys-cli` crate ships one binary, `ferrosys`, which writes ext2, ext3, and ext4
filesystems, reports on them, reads their contents back out, and changes what they are
known by. It is the library's surface for anyone not writing Rust.

```console
$ ferrosys format  --size SIZE --uuid HEX --time SECS [options] OUT.img
$ ferrosys inspect [options] IMAGE
$ ferrosys extract [options] IMAGE (--to-tar F|- | --to-dir DIR | --cat PATH | --stat PATH | --list)
$ ferrosys detect  [options] IMAGE
$ ferrosys identity [options] IMAGE
```

Install it from the workspace:

```console
$ cargo install --path crates/ferrosys-cli
```

## Everything the image depends on is an input

Everything an image's bytes depend on is an input you supply, so two runs given the same
inputs write the same image, byte for byte. Reproducibility is the only mode the tool
has; it is always on.

That has one consequence worth stating plainly: `--uuid` is required and `--time` is
required. The tool takes its UUID as an input, so pipe one in from a tool that mints them
— of whatever version you like — and pass the time explicitly or set `SOURCE_DATE_EPOCH`:

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
| `8`  | The command could not be carried out: the host got in the way, or the bytes are not an ext filesystem at all. |
| `16` | The command line could not be understood.                              |

## `format`

```console
$ ferrosys format --size 512M --uuid f0e17055-0000-4000-8000-000000000000 \
      --time 1700000000 --from-tar rootfs.tar rootfs.img
```

The image streams out through the library's streaming writer, which touches only the
blocks the filesystem uses, so the file stays sparse and a filesystem far larger than
memory can be written.

### Where the contents come from

`--from-tar FILE` and `--from-dir DIR` are the two sources; without either, the filesystem
is empty but for `/lost+found`. Giving both is a usage error, since nothing here decides
the rules for a merge.

**`--from-tar FILE`** reads an uncompressed tar archive. A named file is left on disk and
each member is read as its file is placed, so peak memory is the largest single member,
not the archive. `--from-tar -` reads the standard input, which cannot be sought back over
and so is held whole — that is the one case where a large archive needs the memory to
match. A compressed archive is named as such rather than reported as malformed tar:

```console
$ gunzip -c rootfs.tar.gz | ferrosys format ... --from-tar - rootfs.img
```

**`--from-dir DIR`** walks a directory tree on this machine. `DIR` itself becomes the
filesystem root, and modes, ownership, all three times, symlinks, hard links, device,
FIFO and socket nodes, and extended attributes with their POSIX ACLs all come across.
Each file is read as it is placed, so peak memory is the largest single file.

The walk records Linux inode metadata and Linux extended attributes, so this is the one
option carried out on Linux alone; a binary built elsewhere refuses it by name and exits
8, having opened nothing. Every other part of the tool — an empty filesystem,
`--from-tar`, `inspect`, `extract`, `detect`, and every geometry option — is the same on
every platform.

The walk records the uid and gid the host files carry, which for a build that does not run
as root is that user's own. **`--owner UID:GID` replaces them**, and a rootless build
almost always wants `--owner 0:0`:

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
placing the contents into each — the same placement a format performs, over a destination
that keeps nothing — so the size it settles on is one that formats, and one block less does
not. Nothing is written while it searches, so a size that cannot be found leaves the
destination untouched like any other planning failure. Pair it with `--dry-run` to learn
the number without writing anything at all.

The smallest filesystem holding something is one with nothing left in it, which is right
for an image that will only be read and useless for one that will be written to.
`--slack` says how much must stay free:

```console
$ ferrosys format --size auto --slack 20% --from-dir staging \
      --uuid "$(uuidgen)" --time 1700000000 rootfs.img
$ ferrosys format --size auto --slack 64M --from-dir staging \
      --uuid "$(uuidgen)" --time 1700000000 rootfs.img
```

The share is of the finished filesystem, so `--slack 20%` is what `df` reports as 80%
used; the super-user reservation (`--reserved-percent`) is separate accounting over the
same blocks, so an unprivileged writer sees 15% of it at the 5% default. `--slack` belongs
to `--size auto` and is a usage error over a size that was named outright, which has no
room to find.

On a small image the floor is often the journal rather than the contents — a log costs
about 4 MiB whatever goes in the filesystem — so `--size auto -t ext2` is what fits a
boot partition to what it holds.

### Two more things about `format`

**The destination must be a regular file.** A format writes only the blocks the
filesystem uses and extends the file to its full size with a single byte at the end, so
every byte it does not write must already read as zero — which creating or truncating a
regular file guarantees and a block device does not. Formatting a device would leave
whatever it held interleaved with the new filesystem, so the tool refuses.

**A failing run leaves the destination alone.** The source is parsed, the geometry planned,
and the inode model built and checked *before* the destination is opened, so a run that
cannot succeed never truncates the image already at that path. `--dry-run` goes one step
further and reports the geometry the command would realize without opening the destination
at all; `--atomic` covers the other end, writing to a sibling temporary file and renaming
it over the destination once the image is whole, so a failure part-way through the write is
not visible either. Note what `--atomic` costs: the destination becomes a *new* file, so
its mode comes from this process's umask and any ownership, ACLs, or extra hard links the
old file carried do not survive the rename. Without it the image is written in place.

### Choosing a base filesystem

`-t` (or `--type`) selects which of the ext family to write — `ext2`, `ext3`, or `ext4`
(the default). It seeds the whole feature set from that profile's baseline; the `-O` list
and the geometry options layer on top, exactly as they do for `mke2fs -t`:

```console
$ ferrosys format --size 256M --uuid "$(uuidgen)" --time 1700000000 -t ext2 rootfs.img
$ ferrosys format --size 256M --uuid "$(uuidgen)" --time 1700000000 -t ext3 rootfs.img
```

An image is judged by the features it carries, not the profile it started from, so the
two compose freely: `-t ext2 -O has_journal` writes exactly what `-t ext3` does — a
journal over the ext2 baseline — and `ferrosys inspect` labels either one `ext3`. The
order of `-t` and `-O` on the line does not matter; the profile is always the base and
`-O` always layers on top.

Features are named on disk, and `-O` turns them on and off left to right over the selected
profile (ext4 unless `-t` says otherwise):

```console
$ ferrosys format --size 64M --uuid "$(uuidgen)" --time 1 \
      -O ^has_journal,^orphan_file,^metadata_csum_seed,^metadata_csum small.img
```

That clears the journal and the checksums and leaves the rest of the profile intact:
`extent`, `64bit`, `flex_bg`, `huge_file`, `dir_nlink`, and `extra_isize` are all still
set, so the image is an ext4 one without a journal, and `ferrosys inspect` labels it
`ext4`. `-t ext2` is not a shorthand for a list of `^` words — it selects a different
base, and reaching that base by clearing words means clearing every ext4-layer word,
`extent` included. Name the profile you want and layer `-O` on top of it.

A combination that must never reach disk is refused by name — dropping `has_journal`
while `orphan_file` remains, for instance, since the orphan file's entries are
journalled, which is why the line above clears both.

The same rule covers what the source holds, because a feature word is a promise about the
structures the filesystem carries. Dropping `ext_attr` from a source whose entries have
extended attributes, or `large_file` from one holding a file of 2 GiB or more, is refused
by name and by path: the attribute is neither dropped nor written into a filesystem whose
words deny it. `^large_file` at the 4096-byte block size is refused on its own, before any
source is read, because the resize inode a growable filesystem carries is itself a file
that large.

`--grow` sizes the reserved descriptor blocks that let the filesystem grow online without
relocating its descriptor table. It defaults to `max`, which reserves the most the format
allows; `--grow 4G` reserves exactly enough to reach a known target, and `--grow none`
reserves nothing.

`--label` names the filesystem, up to sixteen bytes. A longer label is refused rather than
truncated, so the name a filesystem carries is the one that was asked for:

```console
$ ferrosys format --size 64M --uuid "$(uuidgen)" --time 1 --label rootfs fs.img
```

`--inodes` and `--bytes-per-inode` set how many inodes the filesystem has, overriding the
count the size alone would choose. `--inodes 20000` names the count directly;
`--bytes-per-inode 16384` names the density it is derived from — one inode for every so
many bytes. The two share one setting, and the last given wins. A density that would need
more inodes in a group than its one-block bitmap indexes is refused rather than quietly
reduced.

A named count is a target, not a floor. It is spread across the groups, and each group's
share is rounded up to fill whole inode-table blocks and then down to a multiple of eight,
so the group's inodes end on a byte boundary in the inode bitmap — the same
`s_inodes_per_group` `mke2fs` derives for the request. The rounding meets or exceeds the
request wherever an inode-table block holds a multiple of eight inodes; where a block
holds fewer than eight, the multiple-of-eight step can leave the realized total a few
inodes short. That is the 1024-byte block at the default 256-byte inode, and the
2048-byte block once `--inode-size 512` halves how many fit. `ferrosys inspect` reports
the count the filesystem actually carries.

`--reserved-percent` sets the share of blocks held back for the super-user, from 0 to 50,
with up to two decimal places — `--reserved-percent 1.5` reserves 1.5%. It defaults to 5.
The count is exact, `floor(blocks × percent)` in integer arithmetic, so a filesystem's
reservation is reproducible to the block.

`--json` prints the geometry the format realized on the standard output:

```console
$ ferrosys format --size 64M --uuid "$(uuidgen)" --time 1 --json fs.img
{"schema":1,"uuid":"f0e17055-...","volume_name":"","created":1,"profile":"ext4",...}
```

Every JSON document this tool writes opens with the same `"schema"` field: the shape is a
contract of its own that no command-line signature describes, so it names its own version.
The receipt also carries `free_blocks` and `free_inodes`, read back from the filesystem
that was just written — a format's overhead is otherwise invisible, and on a small image
it is most of it. On a `--dry-run`, where no filesystem was written to have them, both are
`null` and `"written"` is `false`.

### A small partition

A format's defaults are sized for a general-purpose filesystem, and on a small one they
cost more than they are worth. Two of them dominate: the growth headroom (`--grow`) and the
journal, which is a real file costing its size in free space — 4 MiB of a 16 MiB
filesystem. On a partition that will not grow and does not need a journal, say so:

```console
$ ferrosys format --size 16M --uuid "$(uuidgen)" --time 1700000000 \
      -t ext2 --grow none --reserved-percent 0 boot.img
```

That leaves 3830 of the 16 MiB image's 4096 blocks free — 93.5% of it usable — against
2710 at the defaults. Keep the journal (`-t ext3`) if the partition will be mounted
read-write and power loss is a real risk; drop it when the partition is written once and
read afterwards, which is what a boot partition usually is. The format summary reports what
was reserved and what is left free, so the cost of any combination is one command away.

## `inspect`

```console
$ ferrosys inspect rootfs.img
Filesystem UUID:            f0e17055-0000-4000-8000-000000000000
Filesystem magic number:    0xEF53
Filesystem features:        has_journal ext_attr resize_inode dir_index orphan_file ...
Filesystem profile:         ext4
Inode count:                16384
Block count:                16384
...

no anomalies
```

The whole image is scanned by default: every group descriptor, bitmap, inode, extent
tree, and directory block, with each metadata checksum recomputed. That is what makes a
bad image *bad* (exit 4) rather than merely described. `--quick` reports the superblock
alone and reaches no verdict.

`--fail-on` moves the line at which the scan's findings make the filesystem bad. It
defaults to `integrity`: a filesystem is bad when its own bytes contradict each other — a
checksum that does not match what it covers — or when a structure the reader must follow
cannot be.

The threshold below it, `conformance`, means something else, and is worth knowing about
before you reach for it: it faults a filesystem that is *valid ext4 but not the form this
tool writes*. A filesystem `mke2fs` made is exactly that, and it is not thereby broken —
so `conformance` is a check on this tool's own output, an opt-in self-check, and not what
`inspect` does by default. `--fail-on structural` faults only an image whose structures
cannot be followed at all; `--fail-on never` reports every finding and exits 0 regardless,
which is what to use when you want the report and not the judgement.

A scan reads an image it has no reason to trust, so what it collects is bounded: it stops
at ten thousand findings and says so, in the table, in the `"truncated"` field of the JSON
report, and as a SARIF notification. A truncated report is a floor — the image holds at
least these findings, and the rest of it went unread — so the verdict it reaches reads
"at least *n* anomalies". Ten thousand findings is far past what a filesystem needs to be
called bad.

`--groups` adds every block group's descriptor. `--json` reports the same data as a JSON
document carrying a `"schema"` field, the feature names split by word, the ext2/ext3/ext4
profile those words classify to, the unknown feature bits (reported whether or not there
are any, so an image carrying a feature the tool does not know can never read as one it
understood), and the scan's findings.

`--sarif` reports the scan's findings — and those alone, not the superblock description —
as a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log, so a static-analysis or
forensic pipeline can consume them as it would any other tool's. Each anomaly becomes one
result: its severity maps to the SARIF level (`structural` and `integrity` are `error`,
`conformance` is `warning`, `cosmetic` is `note`), and the exact severity together with
the block, group, or inode it sits at travels in the result's `properties`. Because it
reports scan findings, `--sarif` runs the scan and so cannot be combined with `--quick`,
and it selects a different output format from `--json`:

```console
$ ferrosys inspect --sarif rootfs.img > findings.sarif
```

`--offset` reads a filesystem that begins partway into a larger file — a partition inside
a whole-disk image:

```console
$ ferrosys inspect --offset 1M disk.img
```

## `extract`

Exactly one of five things comes out.

**A tar archive.** Ownership, modes, symlinks, hard links, and device and FIFO nodes
travel in the header; the paths, the ids, the times (to the nanosecond, and negative for
a file older than the epoch), the extended attributes, and the POSIX ACLs travel in PAX
records, because the header cannot hold them. GNU tar and bsdtar both read it.

```console
$ ferrosys extract rootfs.img --to-tar rootfs.tar
$ ferrosys extract rootfs.img --to-tar - | tar -tv
```

The archive opens with a `./` member describing the root directory and omits
`/lost+found`, which every filesystem makes for itself. What comes out is what
`format --from-tar` reads back in, so a filesystem survives a round trip through the
archive unchanged.

A socket is the one thing tar cannot express: it has no entry type for one. An image
holding a socket is a typed error rather than an archive quietly missing a file.

That refusal — like an inode that does not read, or an ACL that does not decode — comes
part-way through the walk, and a named destination is created and truncated before the
walk starts. `--atomic` covers that, as it does for `format`: the archive is written to a
sibling temporary file and renamed over the destination once the walk is complete, so a
walk that fails leaves whatever was at that path untouched. It applies to `--to-tar FILE`,
the only mode with a destination to rename into; asking for it anywhere else is refused
rather than accepted and ignored.

```console
$ ferrosys extract rootfs.img --to-tar rootfs.tar --atomic
```

**A directory tree**, which is `format --from-dir` in reverse:

```console
$ ferrosys extract rootfs.img --to-dir unpacked
Names written:          1284
```

The destination is made if it is not there and must be empty — an extraction states what
the filesystem holds, so a name already present would be an entry that could not be
created, found part-way through with the tree half written. It takes the filesystem
root's own mode, ownership, times, and extended attributes, and everything the filesystem
holds appears beneath it at the path it holds inside the image. `/lost+found` is not
written, so the tree is one `format --from-dir` reads straight back.

Everything the archive carries is carried here too, set on the files themselves: modes,
ownership, symlinks, hard links, device and FIFO nodes, sockets, extended attributes, and
POSIX ACLs. Two things no host lets a caller set, so the tree carries the time it was
written for them alone: an inode's **change time** and its **creation time**. Access and
modification times are set exactly, to the nanosecond.

Three parts of a tree need privileges — a device node needs `CAP_MKNOD`, setting a
recorded owner needs `CAP_CHOWN`, and an extended attribute in the `security` or
`trusted` namespace is the host's to write — so an unprivileged run stops at the first of
them and names it. That is the right answer for a tree meant to be faithful: a rootfs
quietly missing `/dev/null` is a rootfs that boots differently, and one whose `ping` lost
its `security.capability` is one that no longer runs unprivileged. `--skip-privileged` is
the opt-in for a run that wants what it can have, and what it left out is named on the
standard error rather than assumed:

```console
$ ferrosys extract rootfs.img --to-dir unpacked --skip-privileged
Names written:          1282
Ownership:              not applied — this process may not set another owner
Attributes:             not applied — this process may not set security or trusted attributes
Skipped:                /dev/console
Skipped:                /dev/null
```

The reserved attributes are what an unprivileged extraction of a real root filesystem
meets first: a Debian tree carries `security.capability` on the binaries that hold one,
and a tree built under SELinux carries `security.selinux` on nearly every inode.

A file's contents are written as the filesystem reports them, and a hole reads as zeros,
so a sparse file lands in the destination fully allocated. A tree holding one occupies
more space on the host than it does in the image.

The image is untrusted input, and a name in it is not a path to resolve. Every directory
is created and then *opened*, and everything beneath it is created through that open
handle by its single-component name — so a name holding a separator, a `..`, or a NUL is
refused rather than followed, and nothing lands outside the destination. No path through
the destination tree is walked a second time, so nothing swapped into it while a run is in
flight can redirect a write. Symbolic links are written exactly as the image records them,
absolute targets and all, which is safe precisely because nothing here ever follows one.

There is no `--atomic` for a tree: no rename publishes a whole tree at once, and inventing
one would promise something the run cannot do. The empty destination is what stands in its
place — a failure part-way leaves a partial tree in a directory that held nothing, rather
than mixed into one that did.

**One file's bytes**, and nothing else on the standard output:

```console
$ ferrosys extract rootfs.img --cat /etc/hostname
ferrosys
```

The path is a path *inside the image*, taken as the bytes you typed — an ext4 name need
not be text. Symbolic links are followed against the image's own root, so `/lib/modules`
resolves on a merged-`/usr` tree where `/lib` is a link into `/usr`.

**A listing:**

```console
$ ferrosys extract rootfs.img --list
drwxr-xr-x   2      0      0       4096 2023-11-14T22:13:20Z /etc
-rw-r--r--   1   1000   1000          9 2023-11-14T22:13:20Z /etc/hostname
lrwxrwxrwx   1      0      0         17 2023-11-14T22:13:20Z /etc/mtab -> /proc/self/mounts
```

`--list --json` produces the same listing as a JSON document, with each entry's inode
number — which is what tells one file with two names from two files with the same
contents — its extended attributes, and any POSIX ACL decoded into readable entries.

**One path's metadata**, which is the answer to "what is `/usr/bin/ping`, exactly" without
listing a hundred thousand other lines:

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

It reports the type, the mode both ways, ownership, link count, size, all four times, a
device node's numbers, a symlink's target, and every extended attribute — with a stored
POSIX ACL decoded rather than shown as bytes. A path naming a symlink describes the link
itself, not its target. `--json` reports the same as a document.

An attribute's value is bytes, and it is rendered the way a name is: printable characters
as themselves, everything else as a `\xNN` escape, with the backslash escaping itself so
the rendering names exactly one value. To read the bytes rather than look at them, take
`--json`: a value that is not text carries a `value_hex` field beside it holding the bytes
exactly, and the field's presence is itself the signal that the value is not text.

In a JSON document the `mode` field is the permission bits as a **decimal** number, since
JSON has no octal literal — `509` is `0o775` — and `mode_octal` beside it carries the usual
spelling.

### Reading an image you do not trust

A file's size is the image's own claim about it, and a sparse file legitimately dwarfs the
filesystem holding it, so nothing structural bounds what `--cat` would allocate.
`--max-file-bytes N` is the bound to set on an image that has not earned trust:

```console
$ ferrosys extract suspect.img --cat /etc/passwd --max-file-bytes 64M
```

Over the cap the read is an **error**, not a short file. A truncated file that looked
whole would be the worse outcome: a pipeline would carry it forward and never know.

## `detect`

```console
$ ferrosys detect rootfs.img
ext4
$ ferrosys detect --offset 1M disk.img
ext2
```

One word on the standard output — `ext2`, `ext3`, `ext4`, or `unrecognized` — so it reads
well in a shell test, and `--json` for a document. `--offset` points it at a partition
inside a whole-disk image or a region a carver located. A fifth answer, `unknown`, is what
a tool prints when the library classifies a family that build has no name for: something
recognized the image, so `unrecognized` would be the wrong word for it.

This asks what an image *is*, not whether it is sound: an image with a quirk `inspect`
would refuse still classifies here. An unrecognized image exits 8, since there is no
filesystem to have an opinion about.

## `identity`

```console
$ ferrosys identity --uuid "$(uuidgen)" --label rootfs rootfs.img
3 superblock copies written, journal superblock updated
```

Changes what an existing filesystem is known by: its UUID, its volume label, or the seed
its metadata checksums derive from. It is the one command that writes to an image it did
not create, and the only one whose destination already holds something worth keeping.

Every superblock copy is rewritten — the primary and each group's backup — along with the
journal's own record of the UUID, so no copy is left claiming the old identity. Each copy
is patched where it lies: it keeps every field this change does not name, including the
ones this tool has no opinion about. Nothing is written until every copy has been read and
every check has passed, so a refusal leaves the image exactly as it was. There is no
`--atomic`: an image is rewritten in place, and a sibling temporary file would mean copying
every byte of it to change sixteen.

The journal keeps its own copy of the UUID, and on most images a checksum over it. Linux
sets `csum_v3` on the log of any `metadata_csum` filesystem the first time it mounts one,
so an image that has ever been used — a rescue image being cloned, a rootfs that was booted
once and is now being re-stamped per device — carries a crc32c covering the whole journal
superblock. That word is recomputed with the UUID, so the log stays one the kernel will
load. A journal whose stored checksum does not match its contents is refused, as a damaged
filesystem superblock is: writing a correct checksum over wrong bytes would replace a fault
a checker finds with one it does not.

At least one of `--uuid`, `--label`, and `--set-checksum-seed` is required, since a run
that would write nothing is a command line that meant to say something.

### When the UUID is the checksum seed

```console
$ ferrosys identity --uuid "$(uuidgen)" legacy.img
legacy.img: changing the UUID would invalidate every metadata checksum: this filesystem
has metadata_csum without metadata_csum_seed, so its checksums are seeded from the UUID
itself — set the checksum seed to keep them valid
$ ferrosys identity --uuid "$(uuidgen)" --set-checksum-seed legacy.img
1 superblock copies written, journal superblock updated, metadata_csum_seed set
```

Under `metadata_csum`, every metadata object in the filesystem — each group descriptor,
inode, bitmap, directory block, and extent node — carries a checksum seeded from the
filesystem's seed. Where `metadata_csum_seed` is set, that seed is a superblock field and
the UUID is free to move. Where it is not, the seed *is* the UUID, so changing the UUID
invalidates every checksum in the image at once.

That is refused rather than half-performed. `--set-checksum-seed` is the way through: it
records the seed the current UUID implies and turns `metadata_csum_seed` on, after which
the UUID moves and every existing checksum stays valid. It is asked for rather than assumed
because it sets an incompatible feature — a kernel that does not know `metadata_csum_seed`
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
