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
use ferrosys::ext::acl::{Acl, AclEntry, AclQualifier, EXEC, READ, WRITE};
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::{Metadata, TreeBuilder};

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

Three more fields tune what the size alone would decide, each defaulting to what the
size implies. `volume_name` labels the filesystem, up to sixteen bytes NUL-padded into
`s_volume_name`. `inodes` (an `InodeCount`) sets how many inodes it holds — a
bytes-per-inode density or an exact count — overriding the size-driven default; a
density past what a group's bitmap indexes is refused rather than reduced. `reserved`
(a `ReservedRatio`) sets the share of blocks held back for the super-user, in exact
hundredths of a percent, defaulting to 5%.

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
reference out of range, a structure that does not parse. It reports what is wrong; it
does not refuse the image. `verify_checksums` is the strict counterpart, failing on
the first object whose stored checksum does not match its recomputed value.
