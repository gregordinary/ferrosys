# Changelog

All notable changes to ferrosys are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is below `1.0`, the minor version is the breaking axis: a
breaking change bumps the minor, and the patch covers backward-compatible fixes.

## [0.5.0] - 2026-08-18

Two filesystem families, and one crate rearranged to hold four. ferrosys writes and reads
exFAT volumes and btrfs filesystems beside the ext and FAT families it already had, each
behind a feature of its own, and every concept the four share is answered once rather than
per family.

One home per concept. The shapes every family needs — a bounded findings accumulator, a
depth-first walk, a path resolution, a scan report, a JSON writer, a calendar, a checksum
recipe, a padded on-disk field, a flag newtype, the list of names an option accepts — are each
written once, with each family supplying only what genuinely differs. Nothing an image holds changes: the
bytes this crate writes are the bytes it wrote, and the oracle gates that pin them are
unchanged.

The same move reaches the layer below: what a path is made of and which of its components a
directory can hold are one rule each rather than three; the arithmetic that turns a block or
a sector number into a byte offset is checked in one place rather than five; reading exactly
`len` bytes at an offset is one function; a deviation's projection into a `Finding` is one
function each family passes its own coordinates to; and the conversion that records an i/o
failure is written by a macro rather than transcribed per error type. Two of those closed
real gaps rather than only duplication — see **Fixed**.

Two behaviours the shared shapes settle. A FAT scan run with `Limits::max_findings` set to
zero reported a clean volume, because reaching the cap without meeting a deviation was not
recorded as having stopped; it reports a truncated one, as an ext scan does — an absence of
findings from a scan that never looked is not a verdict. And an ext scan bounds what it holds
by the cap it will report under, rather than collecting past it and trimming at the end.

To migrate: `ext::ScanReport` and `fat::ScanReport` are now aliases for `ScanReport<A>` at
the crate root, with the same methods and the same behaviour; `ext::Profile::name` and
`ext::HashVersion::name` become `as_str`, as every other named choice already spelled it; and
`ext::OpenOptions` and `fat::OpenOptions` hold the crate's `OpenOptions` in a `common` field
in place of their `base`, `policy`, and `limits` fields — `OpenOptions::new().base(..)` and
the other two builders are unchanged, so only a caller that read or wrote those fields
directly is affected. `ext::ondisk::InodeFlags` and `fat::ondisk::Attributes` no longer expose
their inner word as a public tuple field; `bits()` reads it and `from_bits()` wraps one, as
the feature words always did.

### Added

- **The `btrfs` feature**, and with it the btrfs family: the default root filesystem on Fedora
  and openSUSE, the storage layer under a large share of network storage appliances, and the
  format image-based Linux tooling increasingly assumes. Off by default like `fat` and `exfat`,
  with no dependencies of its own. It reads one in full and writes one from a source tree,
  subvolumes included.

  btrfs is a different shape of format from the other three, and the module's shape follows.
  The others address storage directly — a block number or a cluster number is arithmetic away
  from a byte offset. **Every address in a btrfs is logical**, and a chunk tree maps that space
  onto the device, so a tree root, a child pointer, and a file's extents are all addresses in a
  space that exists only because something translates it. That leaves a bootstrap problem the
  format solves in the superblock, and `ChunkMap` is what comes out of solving it.

  - **`btrfs::Volume`** opens a filesystem over any `Read + Seek` source: it reads every
    superblock copy the device holds, chooses the one at the highest generation, refuses what
    it cannot read by a name saying what it would take, loads the bootstrap chunk array,
    and reads the chunk tree through it — after which the map covers the whole address space.
    `superblock`, `chunk_map`, `mirrors`, `tree_roots`, and `read_block` are what it offers.
  - **`btrfs::Tree`** is one tree, searched by the key tuple or iterated in key order.
    `for_each_item`, `for_each_item_from`, `for_each_block`, `find_first`, `find_exact`, and
    `count_items`; every block is fetched through the one chunk map and its checksum verified
    before a caller sees it.
  - **`btrfs::ondisk`** is the byte-exact layer: the 17-byte key and the item type that says
    what a record is, a tree block's header and the two things one may hold, the superblock
    and its three feature words, a chunk and its stripes, a device item, a root item, and the
    checksum recipe that covers a superblock and a tree block alike — the format gives them the
    same first field, so it is one recipe.
  - **`btrfs::Mirror`** says what was found at each of the three superblock locations, and it
    has more states than "there" and "not there". A copy records its own location, and that
    field is inside what its checksum covers — so a copy written somewhere other than where it
    belongs verifies perfectly and says the wrong thing about itself, which is what an image
    carved out of a disk at the wrong offset looks like. `Misplaced` is that, and it is a
    different thing from `Damaged`. Under `ReadPolicy::Strict` a copy the device has room for
    that is not the live one is a refusal; under `ReadPolicy::Lenient` the volume opens through
    the surviving copy and every state is reported.

  What it refuses to read at all, each by name rather than by an unexpected value: an
  `incompat` feature bit outside `btrfs::SUPPORTED_INCOMPAT`, a checksum algorithm this crate
  does not compute, a filesystem spanning more than one device, and a chunk whose copies are
  pieces rather than whole. Each of those is a filesystem that is entirely well-formed and
  beyond this reader, and the message says what it would take. An unrecognized *item type* is
  the opposite contract and gets the opposite answer: it keeps its byte and has no name, since
  a reader that refused what it could not name would refuse every filesystem that has been
  used.

  A walk over an image that was crafted rather than formatted is bounded on six things: a
  count larger than the block holds, an item whose data escapes its leaf, a leaf whose data is
  not packed, a block reached twice, a child that is not exactly one level below its parent,
  and keys out of order. The third of those is the one worth naming — data moved within a leaf
  with the offsets moved to match leaves every item inside the block and every item pointing at
  bytes that are not its own, so a bound on each element is not a bound on the arrangement.

  - **`btrfs::Reader`** is the filesystem view built on that address space, and the two are
    separate entry points because the format has two layers. It reads inodes, both forms of
    name record, the directory records the format keys three ways, extended attributes, and
    file extents inline and addressed alike; `lookup` and `lookup_no_follow` resolve a path,
    following a symbolic link in the last component or not, as they do in `ext`; `walk`
    crosses a subvolume boundary rather than stopping at it, so what it yields is the
    filesystem and not one tree; `subvolumes` enumerates them; `verify_data` holds a file's
    bytes against the checksum tree, per file rather than per filesystem, that being a
    different order of cost from a scan.
  - **`btrfs::Reader::scan`** walks every tree and reports rather than stopping. Two of its
    findings are this family's alone: a filesystem still pointing at a log tree, whose message
    says the committed trees are stale rather than naming the field; and an item type this
    reader has no opinion about, counted and named one finding per type rather than one per
    record.
  - **`btrfs::plan_layout`** decides, as a pure function, where every chunk of a btrfs of a
    given shape sits — every chunk in ascending logical order with the device offset of each
    copy, which superblock locations the device has room for, and a bound on the metadata the
    filesystem may spend. `minimum_volume_bytes` answers whether a device can hold one at all.
    A layout carries the reader's own `MappedChunk`, so a plan is a map the reader would have
    built. It refuses a sector or node size the format does not define, a volume too small for
    the profiles asked of it, content too large for the volume, a feature this crate does not
    write, and — unlike the format's own tooling, which drops it and exits zero — a feature
    whose prerequisites were not asked for.

  - **`btrfs::format`** writes a filesystem from any `Source` and hands back the bytes;
    `btrfs::format_to` streams one into any seekable destination, touching only the blocks it
    occupies and never reading back — so a volume far larger than memory becomes a file that
    stays sparse, and an empty btrfs costs a few hundred kibibytes of writing whatever the
    volume's size. Ten trees come out of it, and one more per subvolume: the chunk, device,
    extent, root, filesystem, checksum, UUID, free-space, block-group, and data-relocation
    trees, every block checksummed, every allocated block recorded in the extent tree with the
    tree that owns it, a crc32c beside every sector of file data, and every superblock copy the
    device has room for written last.

    **A tree goes in whole.** btrfs has a field for every property a `SourceEntry` carries — an
    owner, a group, a full mode, a link count, a device number, four timestamps each to the
    nanosecond, as many names per object as a caller states, and an extended attribute as a
    record of its own — so `Image::fidelity` is empty on every build. It is the one family here
    for which that is true, and it answers rather than being absent so that a caller writing one
    build step against four families asks all four the same question.

    **Subvolumes are named by path.** `FormatOptions::subvolume` says which of the source's
    directories becomes the root of a tree of its own, and `default_subvolume` says where a
    mount that names none lands — which is the `@`/`@home` layout every distribution that
    defaults to btrfs expects. A subvolume root is still a directory; a hard link cannot span
    two of them, so a source that names one is refused rather than silently written as a copy.

    A filesystem written here is at `btrfs::GENERATION` and stops. There is no history: nothing
    is rewritten and no block is freed, so every block group is filled from its start and left
    with one run of free space, and every tree is packed full in key order rather than grown by
    insertion. An empty one carries the same trees, the same records, and the same number of
    tree blocks as the format's own tooling produces; a populated one carries the same objects,
    with the same fields, as the same tooling writes from the same directory.

    Reproducible by construction, and more so than the format's own tooling: every value a
    formatter would conventionally take from the clock or from a random source is a
    `btrfs::FormatOptions` input, and objects are numbered in sorted path order — where
    `mkfs.btrfs -r` numbers them in the order the host's `readdir` happened to return names. Two
    formats of one tree at one parameter set are the same bytes.

    **A name, and five identifiers.** `FormatOptions::label` is the name the superblock
    records, up to 255 bytes taken as they come — the field states no encoding, so what a
    caller supplies is what every reader of the image sees. Beside it are the filesystem's own
    id, the id every tree block carries where it is to differ from that, the chunk tree's, the
    device's, and the top-level subvolume's: five, where the other three families record one,
    and every one of them an input.

    `btrfs::FormatPlan` is the plan-then-write split the other three families already have —
    everything a format can fail on but I/O happens when the plan is built, so what a
    filesystem will be, and whether it can be built at all, is answerable before a destination
    is opened.

  The family is reachable without naming it: `detect` claims a btrfs, the root's `open` hands
  back its reader, and the shipping binary writes, reads, describes, and extracts one under
  `format -t btrfs`, `detect`, `inspect`, and `extract`.

- **`format -t btrfs`**, with this family's own inputs. `--fsid` is its identity, and the four
  other identifiers a btrfs records — `--metadata-uuid`, `--chunk-tree-uuid`, `--device-uuid`,
  `--subvolume-uuid` — are each their own option, because a filesystem whose bytes you can
  reproduce is one that states all of them and a value this tool invented would be one you
  could not state. `--label` is the name, `--sector-size`, `--node-size`,
  `--metadata-profile`, and `--data-profile` are the geometry, and `--subvol [ro:]UUID:PATH`
  with `--default-subvol PATH` is the `@`/`@home` layout a distribution root needs — repeatable,
  keyed by path, and refused by name when two of them share an identifier. `--size auto` is
  refused for this family, the search behind it being one this family does not have.

- **The `exfat` feature**, and with it the exFAT family: the interchange format for large
  removable media, the one SDXC cards specify, and the one every current desktop operating
  system reads as it ships. It shares a name with FAT and no bytes — a different boot region,
  a different directory entry format, a different name encoding, and an allocation bitmap FAT
  has no concept of — so it is a family of its own behind a feature of its own, off by
  default like `fat`.

  - **`exfat::format`** writes a volume from a `Source` and hands back the bytes;
    **`exfat::format_to`** writes the same bytes to any seekable destination without ever
    holding them all, so a volume far larger than memory can be created into a file that stays
    sparse. `TreeBuilder::new()` places nothing, which is what an empty volume is. Both boot
    regions go out with their own computed checksum sectors, the allocation table gets the two
    entries the format reserves and a chain for each resident, and the cluster heap gets the
    allocation bitmap, the up-case table, and every directory and file. `Image`,
    `FormatOptions`, `VolumeLabel`, `LabelError`, `ModelError`, `NameError`, `TimeField`, and
    `FormatError` are its vocabulary.

    The images are byte-reproducible, and one input is the whole of what that costs:
    `FormatOptions::volume_serial`. The times an entry records come from the source that named
    it, and its creation time is derived from its modification time rather than read from a
    clock.

    A volume with no name carries a label entry with a character count of zero rather than no
    entry, and the root's second slot is a volume GUID entry with its in-use bit cleared. That
    slot is not the end of the directory: an exFAT directory ends at a zero type byte and
    nowhere else, and the two entries a driver most needs are behind it.

    Three things about a populated volume are worth stating, because each is a place exFAT
    differs from the format it shares a name with. A **name is stored whole** — up to 255
    UTF-16 code units, in the case it was given, with no second shortened name to derive; one
    the format cannot hold is a typed refusal naming the path, never a truncation. **Every
    stream is contiguous and says so**, setting `NoFatChain`, so the allocation table holds
    chains for three things only and the allocation bitmap is what records that a cluster is in
    use. And **a modification time survives to ten milliseconds**, because the creation and
    modification fields each carry a hundredths byte; the access field has none and is granular
    to two seconds. Each of the three records a zone offset, and a volume this crate writes
    says its times are UTC rather than leaving a reader to guess a locality.

    Two names one directory cannot hold are refused before a byte is written. exFAT compares
    names through the volume's own up-case table, so `README` and `readme` in one directory are
    one name to every driver that reads the volume — and the fold this crate checks is that
    same table rather than a host locale's idea of case, which would refuse pairs a driver
    tells apart and, worse, accept pairs it will not.
  - **`exfat::FormatPlan`**, a format decided but not yet performed. Everything a format can
    fail on but I/O happens when the plan is built, so a destination is never truncated for a
    build that then fails on its source — and `FormatPlan::fidelity` is where a caller reads
    what putting a tree on the volume will cost before it costs it. A hard link is written as a
    second copy of its file, and the plan is where the size that takes is a number to read
    rather than to discover.

    An exFAT volume records a name, five attribute bits, three times, and two lengths, and has
    no field for an owner, a mode, a symbolic link, a device node, or an extended attribute. A
    build that would lose one of those is **refused** until `FormatOptions::accepted_loss`
    names it, and what each then cost comes back as a `FidelityReport`. A property counts as
    lost only when the value a read hands back is not the value stated, so a root-owned
    `0644`/`0755` tree goes in and comes back out unchanged — read-only is the one permission
    bit the format carries, and a `0444` file survives too.
  - **`exfat::MAX_DIRECTORY_BYTES`** and **`MAX_DIRECTORY_ENTRIES`**, the one capacity limit
    exFAT puts on the shape of a tree. Every directory has it, the root included: unlike its
    FAT counterpart, exFAT's root is an ordinary cluster chain rather than a fixed region. A
    file has no limit of its own — the length field is 64 bits wide, so what bounds a file is
    the volume.
  - **`exfat::ondisk::RECOMMENDED_UPCASE_TABLE`**, the case-folding mapping the format
    recommends, with `write_upcase_table` to lay it down and `RECOMMENDED_UPCASE_CHECKSUM` to
    recognize it by. The checksum is a value written down rather than derived from the table:
    a table checked against arithmetic over its own bytes checks out however badly it was
    transcribed.
  - **`exfat::plan_layout`** derives every field the format records from a volume size, a
    sector size, and an allocation unit: where the allocation table begins and how long it
    is, where the cluster heap begins and how many clusters it holds, and which of those the
    allocation bitmap, the up-case table, and the root directory occupy. Pure, so a caller
    can ask what a volume would look like without writing one. `PlanRequest`, `ClusterSize`,
    `BoundaryAlign`, `ExfatLayout` and `GeometryError` are its vocabulary.
  - **`exfat::ondisk`** holds the byte-exact structures — `MainBootSector`, the sector-sized
    members of a boot region, `DirEntry` and its `EntryType`, the three entries a format writes
    into a root directory (`VolumeLabelEntry`, `AllocationBitmapEntry`, `UpcaseTableEntry`) and
    the three a file's set is made of (`FileEntry`, `StreamExtensionEntry`, `FileNameEntry`)
    with their `FileAttributes` — the values an allocation table entry takes, and the format's
    four checksums as pure functions: `boot_checksum`, `upcase_checksum`, `entry_set_checksum`,
    and `name_hash`. `BOOT_CHECKSUM_SKIPS` names the two fields a mounted driver rewrites in
    place, which the boot region's checksum steps over rather than sums. `pack_timestamp`,
    `unpack_timestamp`, and `utc_offset_minutes` are how an instant reaches an entry: the two
    packed words in one 32-bit field, and the zone offset beside them.
  - **`exfat::ondisk::UpcaseTable`**, the case folding a volume's up-case table defines,
    decoded from the run-compressed form the heap stores it in. It is a value built from a
    table rather than a function, because every comparison exFAT makes goes through the table
    *the volume carries* — a writer builds it from what it is about to lay down, and a reader
    will build it from what it found.
  - **`Filesystem::ExFat`**, which `detect` answers for such a volume. It carries nothing,
    because the family has nothing to sub-classify. The claim is the format's magic *and* the
    53 bytes it requires to be zero: that magic shares an offset with a FAT boot sector's
    arbitrary OEM text, so a FAT volume can spell it exactly, and claiming that volume would
    mean FAT is never tried.
  - **`exfat::Reader`** reads any conformant exFAT volume, whatever wrote it, and
    **`FsReader::ExFat`** is what `open` hands back for one. Opening parses both boot regions
    and verifies each against its own checksum, compares the backup to the main one by field
    rather than by byte — the two a mounted driver rewrites are excluded, so a volume that has
    been written to is not reported as one whose backup drifted — and reads the allocation
    bitmap and the up-case table out of the root directory, which is where the format records
    them and nowhere else. A volume describing neither is refused by name rather than answered
    with an empty tree.

    Both of the format's run shapes are followed and reach one answer: a stream declaring
    `NoFatChain` is read as consecutive clusters *without consulting the allocation table*,
    which is what the flag means, and one that does not is followed through the table. Every
    entry set's checksum and every name's hash are recomputed. A wrong hash is the failure a
    reader is uniquely placed to name — it costs no data and makes the file invisible to every
    driver that trusts the field, and the set's own checksum is satisfied by a hash and a name
    that disagree.

    **Names are compared through the table the volume carries.** It is read out of the cluster
    heap at open, verified against the checksum its describing entry advertises, and its run
    compression decoded; every lookup and every hash check goes through it. A reader folding
    through a copy of its own would resolve names a driver does not and miss names a driver
    finds. Every name it hands back is one a directory can hold: `.`, `..`, an empty name, a
    separator, or a NUL is a refusal rather than an entry.

    Two states a driver leaves behind are reported and are not faults, so a strict read of a
    card somebody pulled out of a reader still succeeds: a volume that was not cleanly
    unmounted, and a stream whose written length trails its allocated one. Reads yield zeros
    between the two lengths, as every driver does — that region is allocated and nothing wrote
    it, so what is on the medium there is whatever it last held. A volume recording two
    allocation tables is the transaction-safe variant and is refused by name under either
    policy; which of the two is live is a flag rather than a convention.

    `Reader::scan` reports every deviation rather than stopping at the first, and holds every
    cluster the tree occupies against the allocation bitmap in both directions — including the
    disagreement no checker reaches, since `fsck.exfat` objects only about a cluster a file
    *chains through* and a contiguous stream chains through nothing. `Node`, `Storage`,
    `Times`, `Entry`, `WalkEntry`, `ReadError`, `Anomaly`, `Category`, `Location` and
    `ScanReport` are its vocabulary, and `FsTree` is what an extraction drains it through
    without naming the family. It takes the crate's own `OpenOptions` and mints none of its
    own: this family has no knob beyond where a volume begins, how strictly it is read, and
    what one read may allocate.
- **`ferrosys format -t exfat`, and the command line's third family throughout.** The binary
  carries every family the library has, so `detect` names an exFAT volume, `inspect` describes
  one through the same envelope the other two get, and `extract` reads one back — over volumes
  this tool wrote and over volumes it did not.

  - **`--volume-serial HEX`** is this family's identity, taken as eight hex digits bare or
    dashed. A third option rather than a reuse of `--volume-id`: it is a different field of a
    different format, and the two being the same width is a coincidence of the lineage.
  - **`--label`** goes through this family's own rules — up to eleven UTF-16 code units, which
    is eleven characters rather than eleven bytes outside ASCII, and text rather than bytes,
    since the format stores code units and there is no encoding to guess for bytes that are
    not text.
  - **`--accept-loss`, `--assume-owner` and `--assume-modes` reach two families now.** exFAT
    and FAT record a name, a few attribute bits and some times and have nowhere to put
    anything else, so they lose the same six properties for the same reason; an option about
    that belongs to the pair rather than to either, and the refusal for a family outside it
    names both. What differs is time: exFAT keeps a creation and a modification time to ten
    milliseconds and each of its three times with a UTC offset, so a host tree loses far less
    precision than it does on FAT — and still loses some, because its access time is
    two-second granular.
  - **`--size auto` is refused for this family, by name, while the command line is read.** The
    search plans candidate sizes and places the contents into each until the smallest one that
    holds them is found, and that search is a family's own; this one has none. The refusal
    happens before a source is opened, so nothing is walked to say so.
  - **`inspect` reports four fields no boot sector holds** — where the allocation bitmap and
    the up-case table begin and how long each is, which the format records only as directory
    entries — and the two flags a mounted driver writes. A volume that was not cleanly
    unmounted is reported and is not a fault.
- **`ScanReport<A>`** at the crate root, with `Deviation` — the two things everything above a
  family needs of a typed deviation, its severity and its projection into a `Finding`. Each
  family's `ScanReport` is this over its own anomaly, so the report, its cap, what truncation
  means, and the `to_report` projection are one implementation.
- **`ferrosys::json`**, the JSON writer every document this crate emits is built through:
  `Object`, `Array`, and the value kinds a report carries. Public for a caller wrapping a
  findings report in a document of its own — and so that comma placement, key quoting, and
  string escaping are decided in one place for both documents rather than two.
- **`hex`**, the rendering that loses nothing, beside `printable` and `push_json_string`. It
  is what a document puts beside a name it could not render, and what a value that is an
  identifier rather than text — a UUID, a hash seed — is written as.
- **`Civil`** and **`Timestamp::civil`**: the civil date and time of day an instant reads as,
  computed arithmetically in the proleptic Gregorian calendar and always UTC. It is the
  calendar the FAT writer encodes a date with, so what a tool prints and what an image stores
  are read off the same arithmetic. `Civil::to_secs` is the inverse, and `Display` renders
  `YYYY-MM-DDTHH:MM:SSZ`.
- **`NamedChoice`**, and `NAMES` / `as_str` / `from_name` on every closed set of names a
  caller names: `Severity`, `ext::Profile`, `ext::HashVersion`, `ext::HashSignedness`,
  `ext::ErrorBehavior`, and `fat::FatType`. One table serves both directions, so a name a
  report prints is a name whatever accepts one takes, and a message offering the choice
  offers exactly the words it accepts.
- **`ext::ondisk::unpadded` and `fat::ondisk::unpadded`**, each stating where its format's
  padding of a fixed-width text field stops — NULs for ext's `s_volume_name`, trailing spaces
  for every FAT name field.
- **`ext::ondisk::superblock_checksum`**, the one statement of the superblock's crc32c: over
  the record up to its own field, seeded from `!0` rather than through the checksum seam. The
  writer stamping a copy, the reader verifying one, and a re-identification recomputing one
  all call it.
- **`ext::ondisk::SuperBlock::{MAGIC,FEATURE_INCOMPAT,UUID,VOLUME_NAME,CHECKSUM_SEED,CHECKSUM}_OFFSET`**,
  the offsets something outside the on-disk layer addresses by number.
- **`ext::Location::or`, `at_inode`, and `at_group`**, so stamping a walk's coordinates onto a
  deviation keeps the more specific of the two — the merge FAT's `Location` already had.
- **`is_empty`, `without`, `from_bits`, and `BitOrAssign`** on `ext::ondisk::InodeFlags` and
  `fat::ondisk::Attributes`. Every flag newtype in the crate now carries the same set
  operations; three of them were each missing a different part of it.
- **`FsTree::family` and `FsTree::max_file_bytes`**, which is what lets `check_file_size` be
  one default body rather than an identical one per family.
- **`From<std::io::Error> for DetectError`**, which the family readers' `ReadError` already
  carried. Detection's own i/o failures were reached through a private constructor, so a
  caller composing detection into a function of its own could not use `?` where the two
  readers allowed it.
- **`btrfs::Reader::lookup_no_follow`**, and `lookup` now resolves symbolic links — see
  **Fixed**, since the reader could not read a distribution's root filesystem without it.
  The pair means the same thing here as on the ext side: `lookup` expands a link in the last
  component and `lookup_no_follow` stops at it, and both expand the ones before it.
- **`btrfs::MAX_SYMLINK_HOPS`**, the number of links a path resolution follows before calling
  it a loop, matching `ext::MAX_SYMLINK_HOPS` because it is the same number: a root filesystem
  is laid out the same way whichever format holds it.
- **`btrfs::tree_name`**, the name a tree is reported under — the format's own where it has
  one, and its id where the tree is a subvolume. It is what a finding about a tree already
  named it, and now what anything listing them can use, so a report and a finding about one
  filesystem cannot end up with two vocabularies.
- **`btrfs::ReadError::SymlinkLoop`**, for a chain of links that does not end.
- **`btrfs::ReadError::BadCompressedExtent`**, for a file whose bytes are compressed with an
  algorithm this build decodes and are not a well-formed stream of it. Apart from
  `UnsupportedCompression`, because the two say opposite things about the filesystem: that one
  is a filesystem that is entirely sound and beyond this build, and this one is a filesystem
  whose bytes do not hold what they say they hold.
- **The command line reads btrfs.** `ferrosys detect` answers `btrfs`; `ferrosys inspect`
  renders a body of that family's own — the superblock, which of the three superblock
  locations hold what, how much of the address space the chunk tree maps, every tree with its
  root and height, and the subvolumes with their ids and which one is the default; and
  `ferrosys extract` reads the contents back out in all five of its modes, crossing a
  subvolume boundary the way it crosses a directory.

- **The `zlib`, `lzo` and `zstd` features**, and with them a file whose bytes a filesystem
  stored compressed. Every distribution defaulting to btrfs compresses at least part of its
  tree, so this is the difference between reading a root filesystem and reading most of one.
  Each is off by default and each is named for the algorithm rather than for a family, an
  encoding being a property of a run of bytes and not of the format around it.

  What a build carries decides two different things, and the difference is the format's:

  - **A file** stored with an algorithm this build cannot decode is refused by name, and every
    other file on the filesystem reads.
  - **A filesystem** advertising LZO or Zstandard in its `incompat` word cannot be opened at
    all without that decoder, because that word is the format saying in advance that a reader
    without it will misread what follows. DEFLATE sets no such bit, so a filesystem using it
    opens either way.

  Verification takes none of them: the checksums a filesystem records cover the bytes it
  stored, so `btrfs::Reader::verify_data` checks a compressed extent without expanding it.

  `lzo` takes no dependency — the decoder is in this crate, in safe Rust, as `crc32c` and the
  directory hashes are — and the other two take `miniz_oxide` and `ruzstd`, which decode and
  are reached by nothing else. A record's declared expansion is a number the image supplied and
  it sizes a buffer, so it is held to what the format compresses in before a byte is allocated
  for it.

- **`format -O` reads btrfs's feature words**, in that family's own vocabulary — the words its
  tooling takes and `inspect` prints back. The grammar is the one ext's `-O` already had: a
  bare word sets a feature, `^` clears one, `none` starts from nothing, and a list applies left
  to right. The vocabularies are disjoint, so a word belonging to the other family is refused
  by name rather than quietly ignored. The case it exists for is `-O ^block-group-tree`, which
  is how to write a filesystem a kernel older than 6.1 can mount.

- **`inspect` reports a btrfs filesystem's features**, as one list across the three words the
  superblock carries and in the words `-O` takes, with the bits no feature covers reported on
  their own line whether or not there are any. A feature read off a report is one that can be
  typed straight into a format.

### Changed

- **A closed set serializes as the word this crate writes it as.** Under the `serde`
  feature, `Property`, `Direction`, `Category`, `Profile`, `Severity`, and `Family` emitted
  their Rust variant names — `"ChangeTime"`, `"ExFat"`, `"GroupDescriptor"` — which is a
  second vocabulary for a set the crate already spells one way everywhere else. They now
  serialize as `as_str` writes them: `"change time"`, `"exfat"`, `"group descriptor"`. A
  consumer embedding one of these in its own document reads the word this crate prints.
- **`inspect --json` carries the offset the filesystem was found at.** `detect --json`
  already did, so a caller scanning a whole-disk image and then describing what it found had
  the coordinate in one document and not the other. Additive: the field is `offset`, spelled
  as `detect` spells it, and the schema version is unchanged.
- **`format -t exfat` refuses `--time`, which it required and ignored.** An exFAT volume
  records no instant of its own anywhere — every time on it belongs to an entry and comes from
  the source that named it — so the flag is refused for this family the way every option of a
  family that was not named is, and the command line without it is complete. The other three
  families still require it (or `SOURCE_DATE_EPOCH`).
- **`identity` classifies a sound foreign volume as what it is.** Pointed at a FAT, exFAT, or
  btrfs volume it answered "a filesystem was read and it is bad" (exit 4); it now detects
  first and refuses with the verdict every verb gives a request it cannot carry out (exit 8),
  naming what the image holds in the word `detect` prints. It also takes `--offset`, as every
  other image-reading verb does, reaching a filesystem inside a whole-disk image through the
  new `ext::rewrite_identity_at`.
- **The numeric serial in FAT receipts is `volume_serial_number`.** The lineage's two families
  spelled one concept two ways in the shared head of their receipts — `volume_id` against
  `volume_serial_number` — while sharing the rendered `volume_serial` beside it. The flag
  stays `--volume-id`, naming the format's own field; the receipt names the shared concept.
- **The symlink-hop budget has one path, `ferrosys::MAX_SYMLINK_HOPS`.** Resolution is the
  crate's shared seam and its budget governs every family alike, so the constant moved to the
  crate root from the two family paths that each carried it (`ext::read::MAX_SYMLINK_HOPS`,
  `btrfs::MAX_SYMLINK_HOPS`).
- **The readers spend less to answer the same questions.** Opening an exFAT volume detects a
  cyclic root chain with a step counter rather than a whole-heap set; FAT mirror verification
  compares the tables a mebibyte at a time rather than a sector; a FAT or exFAT component
  lookup folds and scans once rather than twice; an ext component lookup streams the directory
  and stops at its name rather than materializing every entry; btrfs data verification reads
  into one reused buffer, and the btrfs writer finds a block's chunk by bisection and grants
  data space from a cursor; ext hard-link chains resolve through a memo, so a long chain costs
  its length once.

- **A feature word's names are generated once, for every family that has one.** The table that
  made ext's three words readable and writable — the flag, the word it is known by, and the
  bits no name covers — is `ferrosys`'s one shape for a flag word a caller names, and btrfs's
  three words now carry it. So `btrfs::ondisk::IncompatFlags`, `CompatRoFlags` and
  `CompatFlags` gain `names`, `from_name` and `unknown_bits`, ext's `Compat`, `Incompat` and
  `RoCompat` gain `describe`, and every one of them renders its flags by name in `Debug`.

  Which of a format's two spellings the table holds is decided by which one this crate has to
  *accept*: btrfs's own header spells its features in capitals and its tooling in lowercase
  words, and a report printing one while an option refuses it is the failure a single table
  exists to prevent. So `IncompatFlags::describe` now writes `skinny-metadata` where it wrote
  `SKINNY_METADATA`, and a refusal naming an unsupported feature names it the way `-O` would
  take it.

- **`btrfs::GeometryError::FeatureUnsupported` names the features it refuses**, beside the bits
  it already carried — the words are what a caller asked for and would have to stop asking for,
  and the bits cover the one a later release of the format defines and this one has no word for.
  The enum is no longer `Copy` as a result.

- **The DOS date and time have one home, `ferrosys::DosTimestamp`.** FAT and exFAT do not each
  define a date format — they carry the same one, inherited from the same ancestor: the same
  two packed words, the same 1980 epoch, the same two-second granularity, the same companion
  field of hundredths. So the arithmetic between an instant and those words is written once,
  and what stays in each family's own layer is where the format puts the words in an entry and
  what it keeps beside them.

  To migrate: `fat::ondisk::{DosTimestamp, encode_time, decode_time, time_is_representable,
  TIME_SECS_MIN, TIME_SECS_MAX}` are `ferrosys::DosTimestamp` and its associated
  `encode`, `decode`, `represents`, `SECS_MIN`, and `SECS_MAX`. The conversion is unchanged
  field for field, and the ext family's own `encode_time` — a different encoding entirely — is
  untouched.
- **`ext::Profile::name` and `ext::HashVersion::name` are `as_str`**, which is what the other
  ten named choices already spelled it. `Display` is unchanged on both.
- **`ext::OpenOptions` and `fat::OpenOptions` hold a `common: OpenOptions`** in place of their
  `base`, `policy`, and `limits` fields. The three builders are unchanged; `common(..)` sets
  all three at once, which is what `open_with` now hands across. A shared input added later
  reaches every family without a second edit.
- **`ext::ScanReport` and `fat::ScanReport` are type aliases** for the crate's `ScanReport`
  over each family's `Anomaly`. Every method a caller used is still there and answers the
  same.
- **`ext::ondisk::InodeFlags` and `fat::ondisk::Attributes` keep their inner word private**,
  as the ext feature words always did. `bits()` reads it; `from_bits()` wraps one.
- **A `--fail-on`, `-t`, `--hash-version`, `--hash-signedness`, or `-e` value the tool refuses
  is offered exactly the names it accepts**, read off the type's own table rather than a list
  transcribed beside the parser.
- **`ferrosys inspect --json` carries `percent_in_use_field` beside `percent_in_use`** on an
  exFAT volume. The first is the percentage or `null`; the second is the byte as it sits on
  disk. A consumer that read the number alone would take a volume nobody measured for a full
  one, and the table rendering answers the third case in words — a value between a percentage
  and "not known" is `<not a percentage: N>` rather than `200%`.
- **New vocabulary for the ranges the readers now check**, each the constant the check is
  written against rather than a literal at the site: `DosTimestamp::is_well_formed` and
  `DosTimestamp::MAX_TENTH`; `exfat::ExfatLayout::heap_bytes`;
  `exfat::ondisk::MainBootSector::{major_revision, minor_revision}`;
  `exfat::ondisk::{FILE_SYSTEM_MAJOR_REVISION, PERCENT_IN_USE_MAX, PERCENT_IN_USE_UNKNOWN}`.
  Each family's `ReadError` gains the variants naming what it found; both enums are
  `#[non_exhaustive]`, so a `match` on one already carried a wildcard arm.
- **What a read of a format storing no POSIX metadata invents has one home**,
  `Attributes::from_read_only_bit`, which both the FAT and exFAT readers' `stat` answers
  through. The two families invent the same four properties, clear the write bits on the same
  attribute, let the modification time stand for the change time neither records, and leave a
  root with no times at all — every one of those a decision, and two copies of a decision
  drift. It sits one function from the write side of the same question, which was already
  shared. Nothing a caller sees changes.

### Fixed

- **A FAT directory's long-name debris is a fatal finding under a strict read, deliberately.**
  A run of long-name entries with no short entry after it — what an LFN-unaware driver's
  delete leaves behind — is reported as `OrphanedLongName` at `Severity::Integrity` at every
  ending a run can have, including the two that dropped it silently. The library's default
  `ReadPolicy::Strict` refuses such a volume, which is the line a strict read draws: the run's
  ordinals and checksum describe an owner that is not there, so the directory's own entries
  disagree. A caller reading media that some other driver wrote opens `Lenient` — which is
  what `inspect` does, and what `extract` falls back to with a notice on the standard error.
- **A btrfs `format()` with subvolumes could abort once the root tree outgrew one leaf.** The
  root tree is shaped before its records hold real addresses and refilled after, and the
  placeholder pass emitted its records in production order where the refill sorts by key — two
  divisions of the same records into leaves, agreeing only while the tree stayed inside one.
  Both passes now run one enumeration, every key being known before any address is, so the
  shapes agree by construction; the free-space tree, whose record count can change as the last
  allocations land, is computed against the settled allocation for the same reason. Reachable
  from `format -t btrfs --subvol` at ordinary sizes.
- **The UUID tree was keyed by a placeholder rather than by the top-level subvolume's
  identifier.** The model opened the top-level subvolume under zeros for the root item to
  substitute later, and the substitution reached one of the two records that name the
  identifier — so any filesystem given a `subvolume_uuid` carried a root item with the real
  identifier and a UUID tree mapping the null one. A lookup by identifier missed, and the
  format's own tooling silently rewrites such a tree on the first writable mount. The model now
  carries the identifier from the start so every record reads one value; an all-zero identifier
  writes no entry at all, which is the format's own "none was set"; two subvolumes sharing a
  nonzero identifier are refused by the library rather than only by the command line; and
  `scan()` holds the tree and the root items to each other in both directions, the one
  disagreement neither `btrfs check` nor a tree-by-tree walk can see.
- **A whole-file read of a crafted btrfs could abort rather than fail.** `read_data` sized its
  buffer from the inode's declared length, and under the default no-cap limits a length past
  what one allocation can represent panicked instead of erroring. The declared length is now
  held to the machine's own ceiling beneath whatever cap the caller set, refused as
  `FileTooLarge` — and the fuzz target that believed it was capping its reads now applies the
  cap it builds.
- **`GrowReservation::Max` — the default — refused a band of sizes that format without it.**
  The reservation was clamped by the format's ceiling and by its share of the filesystem, and
  not by the room the block group leaves beside the superblock and the live descriptor table,
  so near the size where the descriptor run outgrows a 1 KiB-block group the headroom itself
  pushed the run over. The missing clamp is in place, the invariant sweep asserts that `Max`
  fails only where the geometry itself cannot be expressed, and the band formats.
- **Two ext superblock fields could silence a whole scan.** A `s_first_data_block` at or past
  the block count, or a zero `s_blocks_count`, made the derived group count zero — every scan
  loop ran no times and `is_clean()` answered yes for an image whose every real read fails.
  Both are refused at open, as the two per-group divisors already were, the family's own
  library refusing the same shapes.
- **A crafted hash-index block was invisible to `verify_checksums`.** A stored `limit` that
  places the checksum tail past the block made the verifier answer clean without comparing
  anything — and the fields that place the tail are inside what the checksum covers, so
  arbitrary edits to the block went unseen. An unplaceable tail is now a fault, as the kernel
  treats it, and the parser refuses a declared capacity past the block's own.
- **An orphaned long-name run was reported at one of the ways a run can end.** A run ending at
  an ordinary short entry was checked; one ending at the directory's end marker, at a deleted
  entry — the classic corruption, a short entry deleted with its long-name slots left behind —
  at the volume label, at a fresh sequence start, or at the end of the storage vanished without
  a finding. All are reported now, and a complete run longer than the format's 255-unit cap is
  a conformance finding rather than a name that reads clean and cannot be written back.
- **A hostile zstd frame header could buy a large allocation from a small image.** The frame's
  own declared window is allocated before a byte is produced, and the caller's declared-size
  cap never constrained it. The window is now clamped to the buffer the caller sized — its next
  power of two, floored at the format's minimum — so no image-supplied number buys an
  allocation, and no frame a real encoder produces is refused.
- **A tar member dense with distinct extended attributes cost quadratic time.** Each `SCHILY`
  record scanned the gathered list for its name and each `LIBARCHIVE` record scanned it again,
  so an archive built to carry millions of records amplified megabytes of input into hours.
  Both lookups go through one index now; a repeated name still keeps the later value.
- **A `Metadata.mode` carrying file-type bits wrote a corrupt inode without complaint.** The
  entry's kind supplies the type, so a raw `st_mode` passed through whole — the natural
  mistake — put a second file type on the inode, and the image wrote cleanly while `e2fsck`
  faults it and a kernel misreads it. Both mode-writing families refuse it as a typed error
  now, and a hard link stating extended attributes of its own — records no filesystem holds,
  which were counted against the format and then dropped with the fidelity report still
  answering faithful — is refused the same way.
- **An extraction to a directory could leave a short file that looks whole.** A file whose
  storage yielded fewer bytes than the recorded length was quietly truncated on the host with
  no error and no report entry; it is now a refusal naming both lengths.
- **A fit search could refuse a size that fits.** The climb doubles, so a window of workable
  sizes narrower than one doubling could be stepped over and the upward-closed refusal above it
  returned as the answer. The refusal now bounds a search of the window instead — met in
  practice by a FAT12 tree that fits only at the largest cluster sizes.
- **Smaller reader corrections.** An ext fast symlink flagged `huge_file` with an attribute
  block was misclassified against the kernel, the per-inode flag moving the block count's unit;
  a FAT sector past the volume was blamed on `BPB_TotSec32` whatever named it; a truncated FAT
  chain reported a byte count it had not measured; a self-looping chain was blamed on a second
  chain that does not exist; an exFAT reserved-table finding rendered a table slot as a heap
  cluster; a named ACL entry carrying the reserved undefined id — one the kernel refuses with
  `EINVAL` — is refused at construction; an ext file within one block of the no-`huge_file`
  ceiling could serialize a wrapped block count through its attribute block's charge; a
  caller-built `LinearDir` whose tail outgrows the block is a typed error rather than an
  underflow; and a btrfs checksum item keyed at the top of the address space no longer wraps
  the bound under the overflow-checked profiles.
- **A path holding a `..` component resolved to nothing, on every family.** The spelling asks
  two different questions and one answer was being given to both. A directory entry *named*
  `..`, read off a volume, is one no reader hands back: written into a path it would traverse
  out of its own directory, and into an archive member or a host file it would traverse out of
  the destination. A `..` *component* in a path a caller writes, or in the target of a symbolic
  link stored in the image, is ordinary — and `/usr/lib64 -> ../lib` is the shape a multiarch
  root filesystem has, so `extract --cat` on a real one met the difference. A resolution now
  keeps the directories it descended through and ascends on `..`, which answers for a format
  that stores dot entries and for one that stores none. Where the resolution started, it stays:
  a run of them at the root is the root, so every path names something inside the image.

  The ascent holds the directories rather than their numbers, which is what makes it correct
  across a btrfs subvolume boundary — an inode number means one thing in one subvolume's tree
  and something else in another, so a path that descends through a subvolume and back out
  returns to the directory it left rather than to a file that shares its number.
- **A btrfs whose two identifiers differed could not be opened, by this crate or by the format's
  own tooling.** A btrfs may carry a second identifier — the one every tree block is stamped
  with — so that the id a person sees can be changed without rewriting every block. The device
  record stamped in the superblock belongs to the metadata rather than to what a person sees,
  and both the writer and the reader held it against the visible id instead. So a filesystem
  written with a metadata id was one `btrfs check` refused to open, and one this crate's own
  reader refused too; both values are inside what the superblock's checksum covers, so nothing
  about the image looked damaged. Every filesystem whose two ids are one — which is every
  filesystem until somebody changes the visible one — was unaffected, which is why no gate had
  met it.
- **A btrfs written with subvolume identifiers that did not sort in subvolume order produced an
  unreadable UUID tree.** The tree is keyed by halves of each subvolume's own identifier, and
  its records were emitted in the order the subvolumes were numbered — so two identifiers whose
  order differed from their subvolumes' left a tree whose keys descend. Every lookup in a btrfs
  is a binary search, so such a tree answers "not found" for records that are there; `btrfs
  check` refuses it outright. Nothing in a block says which order it is in and no checksum
  covers the question. The records are sorted, and every tree this crate writes is now held to
  ascending key order by a gate rather than by each producer remembering.
- **A btrfs path could not be resolved through a symbolic link.** `btrfs::Reader::lookup`
  walked a path component by component through directory entries and stopped wherever one
  named a link — in the middle of a path as well as at the end. Every current distribution's
  root filesystem makes `/bin`, `/lib`, and `/sbin` links into `/usr`, so reading
  `/bin/sh` off a Fedora or openSUSE root found nothing at all, and neither did
  `ferrosys extract --cat` on the same path.

  `lookup` now expands every link along the way including one in the last component, and
  `lookup_no_follow` is the form that stops at the last one — the same pair of names, meaning
  the same two things, as on the ext side. A target beginning with `/` restarts at the
  top-level subvolume's root and one that does not continues from the directory holding the
  link; a resolution follows at most `MAX_SYMLINK_HOPS` links and refuses with
  `ReadError::SymlinkLoop` past that, so a cycle terminates and a chain that is merely long
  cannot be spun out by an image this crate did not write.

  The budget itself was ext's and is now the crate's, shared by both readers that resolve a
  path: a root filesystem is laid out the same way whichever format holds it, and a budget
  that differed between them would make one format's `/bin/sh` reachable and another's not.
- **`read_data_to` did not honour `Limits::max_file_bytes` on FAT or exFAT.** The cap is
  documented as "the largest file a read will hand out, and the largest one an extraction
  will write", and three of the four paths applied it — every family's `read_data`, ext's
  streaming form, and every sink. The one that did not is the one that streams, so
  `ferrosys extract --cat` bypassed the cap that governed `--to-dir` and `--to-tar` on the
  same file in the same run. Both families gained a `whole_file_len` beside ext's, and every
  whole-file form goes through it.
- **An exFAT stream's `DataLength` was bounded by nothing, and the format bounds it by the
  cluster heap.** exFAT has no holes — a stream's bytes are its allocation — so a length past
  the heap is one no volume could hold, and the bound refuses nothing conformant. Without it,
  a stream declaring eight gibibytes with a `ValidDataLength` of zero read back as eight
  gibibytes of zeros from a sixteen-mebibyte image, without a cluster being touched. The bound
  narrows the length as well as reporting it, so a lenient read is bounded too.
- **Reading an exFAT directory cost its declared length rather than its contents.** Every
  cluster the length covered was read, including the ones past the end-of-directory marker,
  so a directory of two entries declaring the rest of the heap cost a full-heap read — once
  per directory, with the count of directories bounded only by the cluster count. The
  traversal stops at the marker, which is where the directory ends and where every driver
  stops; a directory's length is held to `MAX_DIRECTORY_BYTES` besides, which is the cap the
  format states and the writer was already held to.
- **A dozen exFAT fields whose valid range the format states were accepted in silence**, each
  now refused under `ReadPolicy::Strict` and collected under `Lenient` at the severity it
  deserves: a `FileSystemRevision` whose major half is not 1 (a `shall` in the format, and now
  refused where the rest of the boot sector is judged, so the classifier and the reader answer
  together); a `FirstCluster` of zero beside a non-zero length, whose directory mirror was
  already reported; reserved `FileAttributes` bits; a stream extension with `AllocationPossible`
  clear and an allocation attached; a directory length that is not whole clusters; a
  `CharacterCount` past eleven, which was clamped in silence and turned an unnamed volume's
  eleven zero units into a label of eleven NULs — the writer refuses `U+0000` in a label, so
  the reader now reports one and answers `None`; a set carrying more name entries than its
  name needs, the mirror of which was already reported; a second allocation bitmap, up-case
  table or volume label in the root; a `PercentInUse` between 100 and 255, which is a
  different remark from a percentage that is merely stale; an extended boot sector missing the
  signature the format requires, which the region's checksum covers without judging; and a
  chain reaching the bad-cluster mark, which was caught by a range test and is now named as
  what it is.
- **A FAT file with a length and no first cluster was invisible to a scan.** FAT has no
  holes, so a length is a claim about clusters and a first cluster of zero says there are
  none — and the entry produced the same "no storage" a legitimately empty file does, so the
  scan's length-against-chain comparison had no chain to make it against. A volume `fsck.fat`
  truncates the file on scanned clean and exited zero, and the only thing that objected was a
  read of the file, three structures later. The disagreement is reported where the entry is
  parsed, as `ReadError::SizeWithoutAllocation` at `Severity::Structural`, so a strict read
  names it and a scan collects it.
- **The converse held on an exFAT volume**, and it hides better: a stream extension recording
  a first cluster and a `DataLength` of zero read back as an ordinary empty file, and its
  clusters surfaced only at the far end of a scan as space in use and reached by nothing.
  `ReadError::AllocationWithoutLength` names it where the entry is parsed, at
  `Severity::Conformance` — the volume still reads, and the space is spent. Both families now
  answer both directions of the constraint the two formats state alike.
- **A date no calendar has was reported by neither family's scan.** `DosTimestamp::decode`
  documents taking every field as it is found because "a scan is what judges it", and no scan
  did — so a creation timestamp of zero read back as a date in 1979, and a hundredths byte of
  255 moved an instant 2.55 seconds by a field whose range the format states as 0 to 199.
  `DosTimestamp::is_well_formed` is that judgment, and both readers ask it. FAT judges its
  write time always and its creation and access times where the field is not wholly zero,
  which is how the format records that an implementation did not keep them.
- **A subdirectory naming the root's first cluster was treated as the root**, so an allocation
  bitmap, up-case table or volume label entry inside it escaped `MisplacedRootEntry`. The root
  is the one directory the format records no entry for, which `Node::times` being `None`
  already said — the identity is read off the node rather than recomputed from where its bytes
  are.
- **An exFAT cluster size derived from a crafted boot sector could be one no arithmetic
  produced.** `MainBootSector::bytes_per_cluster` compared the sum of the two shifts a volume
  records against the ceiling the format sets, and both are bytes an image supplies: a cluster
  shift near the top of the range carried the sum past what a byte holds, so the comparison
  wrapped and *passed*, after which a 32-bit sector size was shifted by more places than it
  has bits. The sum is checked, and a volume whose shifts leave the format's range has no
  cluster size rather than an implausible one. Nothing a formatter writes reaches it; the
  reader's never-panic sweep does.
- **A FAT scan capped at zero findings reported a clean volume.** Reaching the findings cap
  without meeting a deviation was not recorded as having stopped, so the report read as a
  verdict about a volume nothing had looked at. It is truncated now, and `is_clean` is false —
  which is what an ext scan already answered.
- **An ext scan collected findings past its cap before trimming them.** One inode's checks
  could overshoot, and the excess was discarded at the end. Nothing about the report changes;
  what a scan holds while producing it is now bounded by the cap it will report under.
- **A FAT volume's sector offsets are computed with the checked arithmetic ext's block
  offsets always used.** Nothing reached the unchecked form — a volume whose sectors do not
  fit the bytes the source holds from its base is refused when its parameter block is read,
  which bounds every offset below `u64::MAX` — so this closes an asymmetry rather than a
  hole. It is worth closing because an address that wraps is not a read that fails but a
  successful read of whatever sits at the offset it wrapped to.
- **Two offsets in ext's group-descriptor and re-identification paths were computed with
  unchecked multiplication** while every offset beside them was checked. Both were bounded
  by fields validated elsewhere; neither says so any more, because a bound another function
  applies is not one this arithmetic should depend on.
- **An i/o failure while detecting a FAT volume is reported rather than read as "not a FAT
  volume".** A source that could not be sought to at the requested base was answered as
  though the family had declined to claim the image, which is what the module documents for
  a source *too short* to hold a boot sector and not for one that failed. A short source is
  still "not ours"; a failure is now a failure.
- **Fourteen more places read a field out of a buffer, or split a path, by hand.** An ACL
  entry, an extended attribute's ACL record, a FAT12 entry straddling a sector, a FAT32
  information sector's trailer, the journal's block-map backup, the host path an extraction
  reports, and the key a FAT model files an entry under each did their own version of
  something the crate states once. None was wrong; each was a second place for the rule to
  change. They are the first output of the two consistency gates described below, which is
  what those gates are for.
- **The pages that introduce this crate named fewer families than the crate carries.** The
  library's registry front page did not mention exFAT anywhere and miscounted its own
  features; the workspace front page opened with a count several lines above a highlight
  that stopped short of it, and claimed every command takes any family when `identity`
  rewrites ext identity alone; and the command-line crate's page still described an ext-only
  tool, down to an exit code documented as "not an ext filesystem at all". Every page names
  every family now, and `ci/family-coverage.sh` holds them there — over the guide's front
  matter and every one of its design pages as well as the front pages.
- **The guide's design chapters stated crate-wide claims in one family's vocabulary.**
  Determinism listed "the two such values" where ext alone has three, and named none of the
  other families' inputs; it now states them per family — the UUID, the directory-hash seed
  and the timestamps for ext, the volume serial and the timestamps for FAT, the volume
  serial alone for exFAT, an empty volume of which records no time anywhere, and the five
  identifiers a btrfs records. The safe-by-construction and rootless chapters say what they
  mean across every family, and the resize-safe chapter says which one family it is about.

### Gates

Two gates run in CI and in `ci/preflight.sh`, against the failure that a concept solved
once gets solved again somewhere else, differently — which passes every test on the day it
is written and drifts apart later.

- **`ci/one-home.sh`** fails when a shared primitive is spelled out a second time. Each rule
  in `ci/one-home.txt` names a concept, the module that answers it, and the spelling that
  means someone answered it again; an exception is allowlisted with the reason it is not a
  copy, and an exception that stops matching anything fails too, so a reason cannot outlive
  what it excused.
- **`ci/duplicate-bodies.sh`** fails when a function body resembles another one over the
  baseline in `ci/duplicate-bodies.txt`. It knows nothing about which concepts have been
  standardized, which is what lets it catch one nobody has named yet.

A third gate, against a different failure with the same shape: **`ci/family-coverage.sh`**
holds every page a stranger reads — the two crate front pages a registry renders, the
workspace front page, the guide's first page, and the `description` and `keywords` a registry
search matches word for word — to naming every family the crate defines. Adding a family
fails loudly in the code and silently in the prose, and it had gone silently wrong once per
family, on a different page each time. The family list is read from the crate's own `Family`
enum, so a fourth family fails the gate until every page has been told about it.

The exFAT family joins every gate a family owes, in the change that adds it: a build of it
alone in `ci/lint-features.sh` and `ci/preflight.sh`, a sixth pinned configuration in
`ci/public-api.sh`, a floor in `ci/test-floors.txt`, and the workflow step the parity check
requires. Its own tier in `crates/ferrosys/tests/exfat_oracle.rs` grew eight gates holding
this crate's arithmetic to the pinned `exfatprogs`: the planner against the baseline's boot
sector and root directory at every row of its matrix, the planner against `dump.exfat` field
by field, the boot sector this crate parses against an independent decode of the same bytes
and a re-serialization that reproduces them, the two checksums an empty volume carries
against what the baseline stored, the two it does not against a directory entry set
`fsck.exfat` accepted, and detection over every row with negative controls built by
`mkfs.fat` and `mke2fs` themselves.

The formatter's own gate is the strongest statement the family makes short of a kernel
mounting a volume: **a whole-image byte comparison against a `mkfs.exfat` baseline, at every
row of the matrix, excluding nothing.** Not the boot code, not the reserved runs, not the
padding from the up-case table's end to the end of the cluster it sits in, and not the holes.
A field-by-field comparison sees only the fields it compares, and the FAT family paid for that
twice. Beside it: `fsck.exfat` clean on every volume this crate writes, `exfatlabel` reading
back the label out of a root directory it walked itself, and a control asserting that changing
the serial moves exactly the bytes it moves in the baseline — a writer that had quietly pinned
something else to the serial would pass the byte comparison at one serial and fail there.

**A pinned btrfs tier joins them, ahead of any btrfs code.** `ci/build-btrfs-progs.sh` builds
one exact `btrfs-progs` release from a sha256-pinned source tarball with fixed configure
switches, giving `mkfs.btrfs`, `btrfs check`, `btrfs inspect-internal`, `btrfstune`,
`btrfs-image`, and the corruptor upstream builds and does not install. Nothing in the library
changes; what this buys is an oracle whose verdicts have been calibrated before anything
consults them, which is the order every family here is built in.

`crates/ferrosys/tests/btrfs_oracle.rs` is what calibrates them, in 32 gates. Five controls,
each a defect class a from-scratch writer can plausibly produce, are observed being rejected —
a superblock whose checksum no longer covers it, a tree block whose checksum no longer covers
it, a leaf whose item offsets no longer describe its items, an extent nothing accounts for,
and a file whose bytes have been altered — with the same image accepted before each damage. The
last of those is the one that makes `btrfs check --check-data-csum` a second gate rather than a
louder first one: altered file bytes are a *clean* filesystem to the metadata check, and no
other family in this project has an oracle that reads data back at all.

The rest is measurement. The pinned formatter's default feature words, block-group profiles,
sector and node sizes, and minimum volume are read out of images it wrote rather than
transcribed; every superblock field offset is read and held against the baseline's own
rendering of the same image; the three superblock locations are asserted at each threshold,
including the boundary where a volume of exactly 256 GiB carries two and one superblock more
carries three; and each tool is exercised in the role it is named for before the work that will
depend on it. The suite reports the switches it was configured with on the second line of its
version banner, so this is the first pinned tier where "pin the build, not only the source" is
a gate rather than a comment in a build script.

**And the reader is held to it, block for block.** Every tree the baseline writes is reached
through this crate and the address and entry count of every block of each is compared against
the baseline's own rendering, over a seven-row parameter set and over a populated image whose
filesystem tree is two levels deep. Four of the tier's corruptions are watched being rejected
by this reader as well as by the checker; the two that are not are findings about *content*,
which this layer does not read. One of the four found a real defect — a leaf whose data has
been moved with its offsets moved to match passed every bound the reader applied, and the
packing rule that catches it is the kernel's own.

**Each feature word this crate takes as input means the bit the baseline moves for it.** A
table of names is exactly the kind of thing that can be wrong by one bit with nothing noticing,
so it is measured rather than transcribed: for every word `mkfs.btrfs -O list-all` offers, the
tier formats an image with it, reads the two feature words back out of the superblock at
literal offsets, and requires the bit that moved to be the one this crate resolves the word to.
A word the pinned build refuses is skipped and counted rather than quietly passed, and a word
that moves no bit at all — the suite offers one — must be one no feature table here holds.

The decoders are gated at three depths, because there is no host tool that compresses and so
no ordinary way to reach them. The stream decoder written in this crate is round-tripped
against a second implementation over every length up to a kibibyte in two shapes, and swept
over arbitrary bytes for the property that it either fills the buffer it was given or refuses.
The framing around it — how many streams one extent is cut into and where each begins — is
held to a real compressed extent taken off a filesystem a Linux kernel wrote. And the whole
path is certified end to end against a kernel mount: a kernel mounts a filesystem with
`compress-force=` for each of the three algorithms, and what this crate reads back is
compared byte for byte against what went in. That tier asserts the fixture is the fixture
before it judges anything — that each file really carries extents of the algorithm it was
written under, and that one of them frames across enough sectors to meet the padding rule the
format has — because a driver free to store those files uncompressed would leave every
comparison passing with no decoder ever reached.

## [0.4.0] - 2026-08-08

A second filesystem family, and the surface that makes room for it. ferrosys formats and
reads FAT12, FAT16, and FAT32 beside ext2, ext3, and ext4, and a family is something a
build takes or leaves. Every ext image this crate writes is the same bytes it was.

The crate's surface splits in two: what is true of a filesystem whatever family it is now
lives at the crate root, and the ext family lives behind `ferrosys::ext` as one family among
others. Nothing about an ext image changes — the same bytes, the same geometry, the same
verdicts — but the paths a caller names, the shape of an emitted document, and the sinks'
signatures all move.

To migrate: `ferrosys::ext::ondisk::Timestamp` becomes `ferrosys::ext::Timestamp` (or
`ferrosys::Timestamp`, which is the same type); `Timestamp::encode`/`decode`/`EPOCH_MIN`/
`EPOCH_MAX`/`is_representable` become `ext::ondisk::encode_time`/`decode_time`/
`TIME_SECS_MIN`/`TIME_SECS_MAX`/`time_is_representable`; `Limits::max_anomalies` becomes
`Limits::max_findings`; `ScanReport::to_json`/`to_sarif`/`to_table` become
`ScanReport::to_report()` followed by the same three on the `FindingReport` it returns;
and `ArchiveSink::write_tree`/`DirectorySink::write_tree` take anything implementing
`FsTree` and report what a source filesystem could not supply.

The two ends of a tree move with it: `ferrosys::ext::ArchiveSource`, `ArchiveSink`,
`ArchiveError`, `DirectorySource`, `DirectorySink`, `ExtractReport`, and `HostError` become
`ferrosys::ArchiveSource` and the rest, reached at the root and nowhere else — a source feeds
whichever family is being written and a sink drains whichever one was opened, so neither
belongs under a family. `Acl`, `AclEntry`, `AclError`, and `AclQualifier` become
`ferrosys::Acl` and are reached flat under `ext` as well, like the rest of the vocabulary a
`SourceEntry` carries; `ext::acl::{READ, WRITE, EXEC}` become `Acl::READ`/`WRITE`/`EXEC`;
`Acl::encode`/`Acl::decode` now produce and parse the version-2 `posix_acl_xattr` form every
boundary speaks, and ext4's compact on-disk form is `ext::ondisk::encode_acl`/`decode_acl`;
and `ext::Slack` becomes `ferrosys::Slack`.

**A `system.posix_acl_*` attribute is the version-2 form everywhere this crate carries one**
— in a `SourceEntry` going in, and in the `Attributes` a read hands back. Each family
narrows it to whatever it stores and widens it again on the way out, so a caller that built
one with `Acl::encode` and a caller that read one back now see the same bytes. What ext
writes to disk is the compact form it always was, so an image built from an `ArchiveSource`
or a `DirectorySource` is byte for byte the one 0.3.1 wrote. An entry a caller assembled by
hand is where this is a fix rather than a relocation, and it is listed as one below.

`tar`, `dir`, and `serde` no longer enable `ext`. A build can now carry a family, a source,
and a sink without the default family — `--no-default-features --features fat,dir` formats a
FAT volume from a directory tree on this machine and extracts one back, with no ext code
compiled.

### Added

- **`GeometryError::DescriptorsExceedGroup`**, for a size whose descriptor table has grown
  until the run that opens every group carrying a copy no longer fits a block group. See the
  fix below.
- **`FormatError::BlockCountWithoutHugeFile`**, for an inode charged more 512-byte sectors
  than a feature set without `huge_file` records.
- **`AllocError::BitmapTooLargeInMemory`**, for a used-block bitmap whose byte count exceeds
  what a `usize` addresses. Reachable on a 32-bit target at 128 TiB; unreachable on a 64-bit
  one. `Allocator::new` is fallible for it.
- **`IdentityError::BackupPastEnd`**, for a superblock claiming groups whose backups lie past
  the end of the image.
- **`ext::ReadError::PathTooLong` and `fat::ReadError::PathTooLong`**, for a walked path
  longer than `PATH_MAX`, which is the ceiling on what a path can be used for.
- **`HostError::TooManyDeferredDirectories`**, for a tree with more directories waiting for
  their metadata than one extraction holds open at once.
- **`HostError::UnsupportedAttribute`**, for an extended attribute this host will not hold on
  a node of that kind, whatever privilege the process has — which the kernel reports with the
  errno a missing privilege uses and is not one.
- **`HostError::OutOfOrder`**, for an entry that reached an extraction before the directory
  holding it. Nothing in this crate's readers produces it; it was previously reported as
  `HostileName`, which named the wrong thing.
- **`printable` and `push_json_string`**, the two renderings that escape a name off an
  untrusted image — one for a terminal, one for a JSON document. Every message and finding
  this crate emits already goes through them; they are public for a caller whose own output
  names the same bytes, and so that the tool does not carry a second copy of the rules.
- **`FsTree::check_file_size`**, so `Limits::max_file_bytes` bounds what an extraction writes
  and not only what a whole-file read returns.
- **`ExtractReport::more_skipped` and `ExtractReport::MAX_SKIPPED`**, so the list of skipped
  paths is bounded by this crate rather than by the tree it was pointed at.
- **`FeatureSet::has_huge_file`**.
- **`ferrosys extract --strict`**, which refuses an image the reader cannot hold to its
  format rather than interpreting it best-effort.
- **`fat::ReadError::HostileName`**, at `Severity::Structural`, for a directory entry whose
  name is one no directory can hold. See the fix below.
- **`ext::ReadError::DirEntryNoSuchInode`**, at `Severity::Structural`, for a directory entry
  naming an inode number the filesystem does not have. See the fix below.
- **`ext::ReadError::HostileName`**, at `Severity::Structural`, for a directory entry whose
  name is one no ext4 directory can hold — the sibling of the FAT variant of the same name,
  and of `DirEntryNoSuchInode` for the other field of the same record. See the fix below.

- **`format --size auto` and `--slack` for FAT.** The smallest volume that holds a tree,
  found the same way ext's is: a candidate is planned and the tree allocated into it, and
  what that leaves free judges the candidate — so the answer is a size that formats, with the
  sector below it proven not to. `fat::FormatPlan::fit` is the library entry point and
  `free_clusters` reports what the volume has left, which is also a new line in the summary
  and a new `free_clusters` field in the JSON receipt.
- **A family-agnostic crate root.** `Source`, `SourceEntry`, `EntryKind`, `Metadata`,
  `FileContent`, `FileRange`, `TreeBuilder`, `LayeredSource`, `Xattr`, and `Timestamp`
  describe a directory tree, which is not any one filesystem's concept, so they live at the
  root and every family consumes them unchanged. `ferrosys::ext` re-exports all of them, so
  a caller formatting an ext image still names one namespace.
- **`open` and `FsReader`** — detect an image and get the matching family's reader back,
  whole. The result is a `#[non_exhaustive]` enum of concrete readers rather than a common
  interface: the families' readers are genuinely not interchangeable, so a trait wide enough
  to be useful would be a lie about the narrowest of them. `OpenOptions`, `ReadPolicy`, and
  `Limits` say where to look, how strictly, and within what bounds.
- **`FsTree`** — the one behavioural trait the families share, and the extraction surface:
  walk the names, stat one, stream a file's bytes, resolve a link. Four operations, kept to
  what `ArchiveSink` and `DirectorySink` actually call. It is not a general filesystem
  interface and is not meant to become one — a question only one family can answer stays on
  that family's concrete reader.
- **`Finding`, `FindingReport`, `Severity`, and `Family`** — the frame every family's
  findings project into, carrying the severity, the family, that family's own word for the
  subsystem, the byte offset, and that family's own named coordinates. Rendering — JSON,
  SARIF, a table, a `--fail-on` threshold — is written once against this, so there is one
  document shape and one severity scale however many families a build carries. ext's
  `Anomaly` taxonomy stays exactly as it was and projects into it through
  `Anomaly::to_finding` and `ScanReport::to_report`.
- **`FidelityReport`, `Property`, `Direction`, and `Synthesis`** — what a format could not
  hold and what a read had to invent, both directions in one report. `ArchiveSink` and
  `DirectorySink` return one, and it is faithful for an ext image, which records every
  property a host file needs. `Synthesis` is what a read fills a missing field from, with
  conservative documented defaults — owned by root, `0644` and `0755` — because a tree
  extracted from a format with no permission bits must not land world-writable because
  nothing was named.
- **`extract --assume-owner U:G` and `--assume-modes F:D`** surface those inputs on the
  command line, and what was assumed is reported on the standard error beside what the host
  refused.
- **The FAT family**, behind the off-by-default `fat` feature: `ferrosys::fat`, a formatter
  and a reader for FAT12, FAT16, and FAT32. One implementation parameterized by the type,
  because the three are one lineage sharing a boot sector, a directory format, and a cluster
  heap, and differ only in the width of a file allocation table entry and in where the root
  directory sits.

  Which of the three a volume is follows from its cluster count and from nothing else — no
  image records it — so `plan_layout` takes what the derivation must arrive at rather than
  what to write down, and reports what it reached. Output is byte-reproducible: every value
  a formatter conventionally draws from the clock or from randomness is an input, dates
  convert in UTC, and entries are sorted by path before anything is placed, so a directory's
  order, each short name, and every cluster are functions of the tree.

  A FAT volume has no field for an owner, a permission bit, a symbolic link, a second name
  for a file, a device number, or an extended attribute, so a build that would lose one
  fails until the caller has named it in an `AcceptedLoss`. A property counts as lost when
  the value a read gets back is not the value that was stated, which is narrower than the
  format lacking a field: a root-owned tree of `0644` files and `0755` directories goes in
  and comes back unchanged, and reports itself faithful.
- **`fat::Reader`** reads any conformant FAT volume, whatever wrote it: cluster chains
  followed at all three entry widths, long names reassembled and tied to their short entry
  by checksum, and the Windows NT case flags honoured on reading though never written. Its
  `scan` is the whole-volume pass — the parameter block against itself, every copy of the
  allocation table against the first, the information sector, every directory entry, and
  every chain, including the clusters that are allocated and reached by nothing. FAT carries
  no checksums, so the table's copies disagreeing is what integrity means here. A strict read
  accepts every volume this crate's own writer produces, which is the line the severities are
  drawn against.
- **`fat::ShortNameCharset`** — how the bytes of a short name above ASCII are read. Nothing
  in a FAT volume records its code page, and the page was a property of the machine and the
  moment each name was created rather than of the volume, so it is never guessed: `Verbatim`,
  the default, hands the bytes back untouched. Five single-byte pages are built in — 437,
  850, 852, 865, and 866 — and `Custom` reaches any other. Naming one is also what makes an
  uninterpretable byte a cosmetic remark rather than a conformance deviation a strict read
  stops at.

- **The `ferrosys` binary carries every family.** The library is modular so a program that
  wants one filesystem compiles one; the binary is the deliberate exception, because someone
  running `detect` or `inspect` on an unknown image wants it identified whatever it turns out
  to be. `detect` names a FAT volume by its type, `inspect` describes one through the same
  family-tagged envelope an ext image gets, and `extract` reads one back out — as an archive,
  as a directory tree, as one file's bytes, as a listing, or as one path's metadata.
- **`format -t fat12|fat16|fat32`** writes a FAT volume, from an empty one or from a tar
  archive or directory tree. It takes this family's own identity, `--volume-id`, as eight hex
  digits in the bare form or the dashed one every tool prints; a 32-bit serial is a separate
  option rather than four bytes cut from a UUID, because a value silently narrowed is a value
  the caller did not choose. `--label` goes through the FAT rules — eleven upper-cased bytes —
  and a label the field cannot hold is refused rather than truncated.

  `--accept-loss` is what a FAT format has that an ext one does not: a comma-separated list
  of the properties the build may lose, or `all`. Without it a build that would drop anything
  fails and names the entry and the property. A tree walked off a host always loses two —
  `change-time`, which the format has no field for, and `time-precision`, since it records a
  write time to two seconds and an access time to the day — and loses nothing else if it is
  root-owned with `0644` files and `0755` directories, which is exactly what a read fills in.
  `--assume-owner` and `--assume-modes` set that point of comparison, so both ends of a round
  trip agree about what survived.
- **An option belonging to one family is refused for another, by name.** `--journal` on a
  FAT format and `--groups` on a FAT image are questions with no answer, and a run handed a
  result silently missing what it asked for would never know. `-t` is read before any of them
  is judged, so its position on the line does not matter.
- **`fat::FormatPlan::volume_bytes`** — the size the destination becomes, which is the size
  the format was asked for. It is not always the filesystem's own size: where the planner
  shortens a FAT12 filesystem out of the disputed cluster range, the sectors it gives up
  stay in the destination and lie past the filesystem's end.
- **`fat::FormatError::MediaDescriptorUndefined`** and
  **`fat::FormatError::DirectoryOverflowsItsClusters`** — see *Fixed*.
- **`fat::ondisk::FsInfo::TRAIL_OFFSET`** — where the information sector's trailing
  signature sits, so a caller checking the field names the offset once.
- **`HostError::UnstableXattrs`** — a path whose extended attributes changed faster than
  they could be read. Reading one means asking the kernel for its size and then for that
  many bytes, and a value that grew in between is asked for again; a path that keeps
  changing across every attempt is a tree being edited while it is walked. It carries the
  path, the attribute whose value would not settle or `None` when it was the list of names
  itself, and how many times the read was attempted, so a caller can tell a tree to settle
  and walk again apart from a fault it can do nothing about.

### Changed

- **`Allocator::new` returns a `Result`.** A used-block bitmap that does not fit a `usize` is
  refused rather than silently truncated to a vector that reports every block used.
- **`FsTree` gains a required method, `check_file_size`.** An implementor outside this crate
  answers it from whatever cap its own reader was given; the two here answer from
  `Limits::max_file_bytes`.
- **`ferrosys extract` caps a file's declared size whether or not it is asked to.** The
  default is sixteen times the length of the filesystem being read, which no ordinary file
  approaches. The library still defaults to no cap, which is right for a caller that knows
  what it opened; the tool is most often pointed at an image someone else produced, and the
  scenario `Limits::max_file_bytes` exists for was its out-of-the-box behaviour.
  `--max-file-bytes` names a different cap for an image holding a legitimately sparser file,
  and a run stopped by the default says on the standard error where the cap came from.

- **`inspect`'s table, JSON, and SARIF output is a family-tagged envelope.** A head that
  means the same thing whatever the image holds — family, variant, size, allocation unit,
  identifier, and the findings — then a body named for the family, which for an ext image
  is the superblock, the feature words, and the group descriptors it carried before. Every
  field an ext report carried is still there, relocated rather than lost: the profile is
  the head's `variant`, and the scan is the head's `findings`. The emitted schema version
  moves to `2` in both the tool's documents and the library's findings document, and a
  later family adds a body rather than reshaping the envelope.
- **`Timestamp` is a wall-clock instant and nothing more**, at the crate root. How an
  instant reaches the disk is the family's business, so ext4's split across the seconds and
  "extra" fields moves into `ext::ondisk` beside every other ext encoding.
- **Detection tries families in a stated order.** A family whose images carry a distinctive
  multi-byte magic at a fixed offset is classified first; one whose magic is weak enough to
  collide, or that has none, is classified only by checking a whole header for internal
  consistency, and runs after every family in the first tier.
- **`ArchiveError::Read` and `HostError::Read` carry a `TreeError`** — the shared
  classification of a read failure — rather than ext's own `ReadError`. A caller that needs
  the family's typed error opens that family's reader directly.
- **`Limits::max_anomalies` is `Limits::max_findings`**, and `ScanReport::MAX_ANOMALIES` is
  `FindingReport::MAX_FINDINGS`.
- **`detect`'s JSON names the sub-classification `variant`,** the word `inspect`'s head uses
  for the same thing. One tool answering "which family, and which of it" under two
  vocabularies is a consumer's problem for no gain.
- **`extract --list` and `--stat` report a field the family has no notion of by omitting it.**
  A FAT entry carries no `inode` and no `links`; a zero or a one there would be the tool
  answering a question the format never asked. Both documents gain a `synthesized` list —
  always present, empty or not — naming what the report filled in rather than read, in the
  same words `--accept-loss` takes. An ext entry is unchanged but for that empty list.
- **`format --json` leads with `family` and `variant`,** so a receipt says which filesystem
  was written from the same two fields whichever one was asked for. The ext receipt's
  `profile` field is the head's `variant`.
- **Every `as_str` is a `const fn`**, so the name of a severity, a category, a property, a
  direction, or a family is available in a constant. They all compute the same way — one
  match arm per variant, returning a literal — and now all say so.
- **`Limits::max_walk_entries` bounds a single read as well as a whole-tree walk.** Where a
  family gathers one structure into a list — a FAT directory's entries, or a cluster chain
  collected by `fat::Reader::chain` — the caller's cap governs that list too, so an image far
  larger than the memory reading it is bounded at each read rather than only across the tree.
  Reaching it is a `WalkTooLarge` rather than a shortened list.
- **A FAT directory is read a region at a time and never held whole.** What one
  `fat::Reader::read_dir` allocates is the entries it produces plus a single cluster,
  whatever the directory's chain does.
- **`fat::format` and `fat::format_to` produce exactly the size they were asked for.**
  Where the planner shortens the *filesystem* out of the disputed FAT12/FAT16 cluster range,
  the destination keeps the sectors it gave up and they lie past the filesystem's end, which
  is what the slack at the end of a partition looks like. The boot sector's `total_sectors`
  is what says where the filesystem stops, so no driver reads into them.
- **The guards between a FAT plan and the bytes it becomes hold in every build.** A
  directory's capacity, a table batch's placement, a file's declared length, the ascending
  order the table writer binary-searches, and every boot-sector field the format narrows
  were debug assertions and are now unconditional. Each guards a failure the finished bytes
  cannot show — a later write covers an earlier overflow, and a truncation is silent by
  construction — so checking them only in a debug build checked them nowhere a consumer runs.

### Removed

- **`ScanReport::to_json`, `to_sarif`, and `to_table`**, and `Anomaly::to_json`. Rendering
  belongs to the shared frame, where it is written once: `ScanReport::to_report()` projects
  into a `FindingReport` and the same three methods are there. `ext::read::SCAN_SCHEMA_VERSION`
  is `FINDINGS_SCHEMA_VERSION` at the root for the same reason.

### Fixed

- **A file's bytes were read through a symbolic link on arm, aarch64, m68k, powerpc and
  powerpc64.** A range named by a path is opened when the file is placed, and that open sets
  `O_NOFOLLOW` so a name a walk recorded as a regular file cannot become a link before the
  bytes are read. The flag was spelled as one number for all of Linux; those architectures
  define their own, and the number used means `O_LARGEFILE` there — a bit every open already
  implies, so the kernel accepted it, ignored it, and followed the link. Whatever the link
  pointed at reached the image as the file's contents, with no error and nothing in the
  fidelity report.
  The value is now per architecture, a target outside the families it names does not compile
  rather than guess, and a unit test opens a real link on whatever target the suite runs on.
- **The ext reader dropped a directory entry whose name no directory can hold, and said
  nothing.** A name carrying a path separator or a NUL — impossible on a kernel-checked
  filesystem, so present only by craft — was skipped where the walk built paths. The entry
  and its whole subtree vanished from a listing, an archive, and an extraction, which
  reported the files it did write and exited zero. A scan reported it, but an extraction
  does not scan, so for the one command that writes the tree somewhere the silent omission
  was the only signal. The test is now applied where bytes become a name, in `read_dir`:
  a strict read refuses with `ext::ReadError::HostileName`, a lenient one leaves the entry
  out and keeps the good ones beside it, and a scan still finds one anywhere in the image.
  The FAT reader already worked this way; the two families now answer alike.
- **Two guards on the bytes the ext writer emits were compiled out of the build a consumer
  installs.** `encode_block` checked that its entry records and values had not crossed with
  a `debug_assert!` *after* the write that would have crossed them, and `write_entry`
  recorded a stored name longer than 255 bytes by truncating it through `as u8` — a smaller
  wrong length written into an image. Both are unconditional now, and the block-size bound
  is stated before a cursor moves, in the same terms `encode_inline` has always used for
  its region.
- **The planner produced sizes whose metadata overwrote itself.** The contiguous run that
  opens every group carrying a superblock copy — the superblock, the descriptor table, and
  the reserved descriptor blocks — must fit inside one block group, because the next group
  opens with its own copy. Nothing compared the two. At 1 TiB with a 1 KiB block, the primary
  occupied blocks `[1, 8450)` and group 1's backup superblock sat at block 8193, inside it:
  `plan_layout` returned `Ok`, `format` returned `Ok`, and the image was unmountable. Refused
  now, as `mke2fs` refuses it by reaching for a layout this crate does not write.
- **Extracting a filesystem destroyed every file capability it carried, and called the
  extraction faithful.** Extended attributes were written before ownership, and changing an
  owner strips `security.capability` — the kernel raises `ATTR_KILL_PRIV` on every `chown` of
  a non-directory whether or not the ids change. So the attribute was written and then
  removed, and because `fsetxattr` had succeeded, nothing was reported. A Debian rootfs came
  out with no capabilities on any binary and a report saying nothing was lost. The order is
  now ownership, mode, attributes, times, which is the only order both this and the POSIX ACL
  rule allow. **A directory's extended attributes were never written at all**, which the same
  pass fixed.
- **The FAT reader followed the copy of the allocation table the volume says is dead.**
  `BPB_ExtFlags` bit 7 means only one table is live and bits 0-3 say which; the bits saying
  which were read and discarded. On such a volume the mirror check is also suppressed, so the
  disagreement that would have been an integrity finding was not reported — a strict open
  followed by an extraction returned the wrong tree and the wrong file bytes, and succeeded.
- **`rewrite_identity` built one entry per claimed block group before reading a byte.** The
  group count comes from two superblock fields nothing validates, and reaches `u32::MAX`: a
  1 MiB image drove 158 MiB of allocation, or 1.5 seconds of spinning, or an offset
  multiplication that overflowed. Bounded by the image's own length now, with checked
  arithmetic.
- **A tar archive with a multi-byte PAX time fraction panicked the parser.** Nine
  *characters* were taken and their length measured in *bytes*, and the subtraction happened
  before the parse that would have rejected the input. A 2,560-byte archive was enough. In a
  release build it wrapped and produced an arbitrary nanosecond value that reached the
  on-disk timestamp.
- **A superblock with a zero `s_blocks_per_group` or `s_inodes_per_group` scanned clean.**
  The first made the group count zero, so every scan loop ran no times; the second let the
  loops run and examined no inode in any of them, on a filesystem where `inode_raw` then
  answered `NoSuchInode` for every number. `is_clean()` returned true for both. `e2fsck`
  refuses both, and so does opening now.
- **A `walk` descended a root that was not a directory.** Every other descent was guarded.
  An inode 2 with a regular-file mode and a large `i_size` sent the walk to build a block map
  at the full logical size — tens of gigabytes from a small image — before there was an entry
  to read.
- **Image bytes reached the terminal unescaped.** A FAT directory may be named
  `\x1b[2J\x1b[1;1Hno findings\x1b[0m`, and `inspect` spliced finding details into stdout
  verbatim — an operator saw a forged clean report from a command that exited zero. Errors
  naming a path did the same on stderr. Every name that enters a message or a finding detail
  is now escaped where it is interpolated, which is the last point anything can tell it from
  the words around it. The rule covers both classes a terminal acts on and reaches every
  surface a name leaves by:
  - **Control characters and the bidirectional formatting characters.** The second class is
    category `Cf` rather than `Cc`, so `char::is_control` does not name it, and `U+202E`
    alone displays the rest of a line reversed — `photo\u{202e}gnp.exe` reads as
    `photo exe.png`. A JSON document escaped the first class and not the second, and its
    `<key>_hex` companion was absent for such a name, because a direction override is valid
    UTF-8 and the lossy rendering equalled the bytes.
  - **A path off the host, not only one out of an image.** A tree pointed at by
    `format --from-dir` is an unpacked tarball or a container layer, and whoever built it
    chose the names in it. `HostError` rendered those paths with `Path::display`, which does
    nothing about either class — the same forged output, through the other input surface.
  - **One implementation, not four.** The escaping rules lived in four near-duplicate
    copies, which is how the JSON writers came to be missing an arm the human renderers had.
    They are now `printable` and `push_json_string` in the library, and the tool uses those.
- **`i_blocks` and `i_file_acl` were read with their high halves joined on regardless of the
  features that define them.** Without `huge_file` the two bytes above `i_blocks_lo` are
  ext2's `l_i_frag` and `l_i_fsize`; without `64bit`, the two above `i_file_acl` are
  `i_pad1`. Read as high halves they changed what an inode *is*: a fast symlink on a foreign
  ext2 image classified as slow, and its inline target was walked as a block map.
- **A file over 2 TiB on ext2 or ext3 serialized a wrapped block count.** Without `huge_file`
  — which `validate()` refuses on a non-extent set — `i_blocks` is 32 bits and stops at two
  tebibytes, while a classic map at a 4 KiB block reaches 4.004. Accepted, and written with a
  wrapped low half beside a high half the feature words deny.
- **An empty directory-entry name was not treated as hostile, in either family.** The path
  built from one is the directory's own with a trailing separator, so two such siblings
  produced two walk entries at identical paths, and an archive rendered one as a member
  ending in `/` — which every tar reader takes for a directory, colliding with the real entry
  of that name and changing its type.
- **`Limits` did not reach the reads it was documented to bound.** `max_walk_entries` now
  governs a single ext directory where it is read, rather than after the whole listing was
  gathered — and that listing reads each of a mapping's physical blocks once, so a directory
  pointing every slot at one block no longer yields its entries a million times. A slow
  symlink's target is bounded by `PATH_MAX`, which is a structural ceiling a regular file's
  contents do not have. `max_file_bytes` bounds what an extraction *writes*, which is where
  a claimed `i_size` was being spent on disk. A walked path is bounded in both families.
  One extended-attribute region can no longer yield more value bytes than the region holds.
  A FAT directory whose chain cycles costs two steps rather than the whole volume's cluster
  count, paid once per directory. An extraction defers a bounded number of directories.
- **A window into an extent-mapped file re-walked the whole tree.** `map_window` documents
  that only the structures the window touches are read, and the extent side read every index
  entry to every leaf on every call — a tree walk per two blocks on the tar path.
- **`fit` read a too-*large* planner refusal as too-small**, so the climb stepped over every
  size that worked and reported the ceiling's failure.
- **A FAT volume could hold two files reachable by one name.** A long name's derived short
  name was checked only against other short names, so `A Long File Name.txt` took
  `ALONGFIL.TXT` and a literal `ALONGFIL.TXT` beside it was pushed to a numeric tail —
  leaving one file unreachable by its own name and the other answering to it.
- **A PAX global header's records were consumed and discarded.** An archive expressing
  ownership, times, or attributes only as archive-wide defaults converted to a filesystem
  that did not carry them, with nothing said. A default this parser would otherwise read per
  member is now refused; one it ignores per member — `git archive`'s `comment` — still opens.
- **`FormatPlan::fit` could finalize a FAT model from a probe that was not the one it
  returned.** Every probe allocates into the shared tree, and the bracket does not promise
  the last one is the winner. A probe now carries only its layout, so the model's counts and
  cluster runs can come only from a settling pass over the winning geometry.
- **Smaller refusals and reports that were wrong about themselves.** `inspect --fail-on` with
  `--quick` is refused rather than accepted inert — together they were a CI gate that looked
  armed and exited zero on a destroyed filesystem — and so is `format --dry-run --atomic`.
  `inspect --groups` is bounded rather than following a claimed group count, and says when a
  listing stopped short. One bad image extracts to the same exit code through `--to-tar` and
  `--to-dir`. `format --from-tar -` caps the one archive path that must be read whole.
  Re-identifying verifies every superblock copy's checksum rather than the primary's alone,
  so a damaged backup is refused instead of laundered into self-consistency. A FAT volume
  label is read from the live entry rather than from a deleted one or one past the end, and
  survives the `0xE5` leading-byte substitution. An unknown `BPB_FSVer` is reported. A full
  FAT32 volume records no next-free hint rather than one naming a cluster it does not have.
  `detect` answers "not ours" when the ext probe runs out of source, instead of ending
  detection for every family. A bad directory-entry reference is policy-gated exactly as a
  hostile name is, so a lenient read keeps the good entries beside it. A file's bytes are
  read at placement time without following a symbolic link swapped in behind the walk.

- **An ext image could send the reader outside itself for its own metadata.** Raw block reads
  were bounded by the length of the source, which on a filesystem occupying a partition or a
  region of a larger file is not the filesystem's boundary — and several references were
  checked against nothing else: a group descriptor's inode table and bitmaps, an extent
  tree's external nodes, and the descriptor table's own placement. A crafted image could
  point group 0's inode table at the block after its final one and supply the *root inode*
  from there, mode and mapping and inline symlink target included, while `scan` reported the
  image clean. Every block-valued reference now passes the filesystem's own bound before any
  i/o, and an inode's whole byte range is bounded rather than the block its table starts in.
  The source's length still bounds a truncated image; the two are separate checks because
  they are separate facts.
- **An extent header whose counts contradict each other was walked as a mapping.** The parse
  bounded itself by `eh_entries` and never consulted `eh_max`, so a node declaring room for
  no entries — or for more than it holds bytes for — was followed, and a scan of it reported
  no finding at all. `e2fsck` calls the same node a corrupt extent header and the kernel
  refuses to read it. The three counts must now agree with each other and with the node:
  `eh_max` holds at least one entry and no more than the node's capacity, and `eh_entries` is
  within it.
- **A directory entry naming an inode the filesystem does not have was handed back.** Nothing
  bounded an entry's inode number against `s_inodes_count`, so a listing carried an entry that
  resolves to nothing, the failure surfaced only when something later tried to resolve it, and
  a whole-image scan reported the corruption not at all. `e2fsck` reports it as an entry with
  an invalid inode number. `read_dir` now refuses such an entry where it reads it, and `scan`
  records a structural directory finding and carries on through the rest of the directory.

- **A FAT long name spelling `..` became a path component, and nothing said so.** The dot
  entries were recognized by their eleven-byte name field and the long-name run was
  reassembled afterwards, so a run spelling `.` or `..` belonged to an ordinary short entry
  and reached the name a caller receives — where `read_dir` handed it back, a walk built a
  path from it, and `ArchiveSink` emitted the traversal-shaped member `./../x`. GNU tar
  refuses a `..` member by default; many tar readers do not. A scan reported the volume
  clean throughout. Fixed with the next entry, which is the same gap from the other side.
- **A FAT name holding a path separator or a NUL was dropped in silence.** The walk skipped
  it and nothing reported it: an entry vanished, a directory took its whole subtree with it,
  and the `ExtractReport` said `written: 0`, `skipped: []`, `Ok(())`. Both shapes are now
  refused where the name is resolved — an error under `ReadPolicy::Strict`, a finding a scan
  collects under `Lenient` — so the four names a directory cannot hold reach no surface of
  the crate: not the entry list, not a walk's paths, and not an archive built from them.
- **The FAT reader did not hold a cluster count to what the type addresses.** A count above
  `FatType::max_clusters()` gives the volume clusters numbered at or above the end-of-chain
  floor, and a chain reaching one was read as ending there — so a file truncated at a cluster
  boundary and the short read came back as success rather than `ChainTooShort`. The reader
  now applies the bound the planner refuses to cross, so both halves of the family agree on
  what a volume of each type is.
- **A FAT12/16 parameter block could derive to `Fat32` with no FAT32 layout.** A 12/16 tail
  whose cluster count landed in the FAT32 band produced `fat_type: Fat32` beside `fat32:
  None` and a non-zero root region — three fields that cannot all be true — and every chain
  on the volume was then followed through 32-bit entries over a table the block sizes for 16.
  `detect` reported `Fat(Fat32)` for it. The shape is refused: the tail says the volume is
  not FAT32, so a count only FAT32 addresses means the two halves of the header describe
  different filesystems. `FatLayout::fat32` is `Some` on exactly the FAT32 layouts, whether
  planned or recovered.
- **An unprivileged extraction failed on a hard link into an unsearchable directory.** A
  second name for a hard-linked node is created by traversing to the first, and a directory
  the image records without owner-search permission could not be traversed once its mode was
  applied — so a well-formed image a privileged run extracts failed for an ordinary user with
  a bare `EACCES` naming the wrong path, leaving a half-written tree behind. Such a directory
  now keeps its handle and its building mode until the whole walk is done, by which time
  there is no name left to reach. Everything else is still finished where the walk leaves it.
- **A hard link the host refuses is now reported rather than being a bare I/O failure.** A
  destination filesystem with no notion of a second name for a node answers `EPERM`, which is
  the host declining what the image asks for exactly as a device node is: it is a
  `HostError::Unprivileged` naming what was missing, or — under
  `DirectorySink::skip_privileged` — a path in `ExtractReport::skipped`.
- **`DirectorySink::new` resolved the destination three times before it held a handle.** The
  emptiness check, the directory check, and the open each resolved the name again, so what
  answered them need not have been what received the tree. The handle is taken first, with
  `O_DIRECTORY` as the directory check, and the listing goes through it.
- **A streaming walk bounded the names it yielded and not the names it found.** Both families
  checked their entry cap as a name came off the stack, so each of a cap's worth of visits
  could push a whole directory's worth of children first — leaving the frontier bounded by
  the cap times a directory's fan-out rather than by the cap, on an image whose directory
  inodes deliberately share their data blocks. Every name discovered now counts against the
  same bound as every name visited. The ext walk also held a whole `Inode` per pending name,
  inline attribute block included; it holds a path and an inode number and reads the inode
  when the name comes up, which is the same one read per name, moved rather than added.
- **The ext reader's structural bounds were derived from the whole source, not from the
  filesystem.** Every bound built on the source's length — the blocks a scan walks, the
  inodes it verifies, the names a walk may find — is a statement about the filesystem, which
  begins at the offset the image was opened at. A 16 MiB partition at the end of a 2 TiB disk
  image was bounded as though it were 2 TiB. The length is measured from that offset now, and
  measured once at open: a source that cannot report its end fails the open rather than
  reporting zero, which had quietly reduced `verify_checksums` to examining no inodes at all.
- **A FAT allocation table's copies were compared through two different reads.** The chain
  walk refuses to read past the end of the copy it is in, because the copies are laid end to
  end and one sector further is the *next* copy's first entry spliced onto a FAT12 entry that
  straddles the boundary. The mirror comparison decided from the offset alone and had no such
  bound, so the two could read different bytes for one entry — a wrong or missing
  `TableMismatch`. Both now take the same rule from one place, with the same ceiling on the
  entry and checked arithmetic on the sector.

- **`cargo doc` failed on the crate in every build that was not `--all-features`.** Four doc
  links named an item behind `fat`, behind `tar`, or behind a family in general from a
  comment that was not gated the same way, so a consumer on default features — or on any
  build missing one of those — got a hard error under `RUSTDOCFLAGS="-D warnings"`, and the
  two `Probe` verdicts only a climbing fit search reaches were dead code wherever `fat` was
  off. A doc link now names only an item that exists wherever the item carrying it does.
  `ci/lint-features.sh` is the gate: it lints the configurations in which something a
  consumer can turn off is off, which is the set `--all-features` cannot cover by
  construction. The default configuration's public surface is pinned as well, beside the
  four that already were.
- **A hand-assembled `SourceEntry` carrying a `system.posix_acl_*` attribute wrote an ACL
  the kernel rejects.** The bytes `getxattr` hands back are the version-2 `posix_acl_xattr`
  form, and an entry a caller built from them reached the inode verbatim; `ext4_acl_from_disk`
  refuses anything whose `a_version` is not 1, so those ACLs were unreadable on a mounted
  image while every other attribute on it read fine. The value is decoded and re-encoded into
  ext4's compact form on the way in, which is the form the archive and directory sources
  always produced — so an image built through either of those is unchanged, and one built
  from entries assembled by hand changes to the bytes that work. A caller feeding the compact
  form directly — what `Acl::encode` produced in 0.3.x — gets a typed `ModelError::Acl` from
  the version check rather than an image that misparses, so the two forms cannot be confused
  in silence.
- **The FAT32 cluster maximum was one too high, so a maximal volume's last cluster was the
  bad-cluster mark.** The highest cluster *number* on a volume is one past its count, and
  `0x0FFFFFF7` is the bad mark — so a count of `0x0FFFFFF6` put an ordinary file's last
  cluster on a value no chain may contain. This crate's own reader refused any link into it,
  and Linux folds the same value to end-of-chain, so a file ending there read short. The
  maximum is `0x0FFFFFF5`, and the property behind it — that `max_clusters() + 1` is an
  ordinary cluster — is now asserted for all three types rather than left implicit in three
  constants.
- **`fat::FormatOptions::media` was unvalidated, so the writer could emit a volume its own
  strict reader and `fsck.fat` both refuse.** The format defines `MEDIA_REMOVABLE` and the
  eight codes from `MEDIA_FIXED` up; anything else is now a
  `FormatError::MediaDescriptorUndefined` raised in planning, before the destination is
  touched, against the same value set the reader enforces.
- **`open`, `open_with`, `FsReader`, and `OpenError` were compiled only where `ext` was**,
  so a build carrying FAT as its only family had no way to reach a reader without naming the
  family — the one thing that surface exists for. They are compiled where any family is.
  `--no-default-features --features fat` is now a configuration the gates build, test, and
  pin the public surface of.
- **`Limits` did not bound what a walk allocated at its peak.** A FAT directory was
  materialized whole before any cap was consulted, so one crafted to chain across the volume
  cost about 1.2× the image's size in memory whatever the caller asked for.
- **A directory's serialized entries are checked against the clusters the plan gave it on
  every write**, and overflow is a `FormatError::DirectoryOverflowsItsClusters` rather than
  a directory laid over the file placed after it and covered by it.
- **A FAT12 mirror divergence in the last cluster's entry was reported as padding.** On that
  width the highest entry can end in the low nibble of a byte, so the padding boundary is the
  entry's span rather than the next entry's offset. Such a divergence is a `TableMismatch` at
  `Severity::Integrity` — fatal under a strict policy — where it was a cosmetic remark.
- **A FAT12 mirror divergence in a shared byte named the wrong entry.** The middle byte of a
  pair belongs to two entries, and the comparison always named the even one — producing a
  mismatch that printed two identical values and would have sent a repair at the wrong
  cluster. Both entries the byte spans are now compared, and the finding names the one that
  differs.
- **A corrupted FSInfo trailing signature was reported clean.** The parser does not require
  the signature because its top half duplicates the boot signature, which a foreign tool may
  have written for its own reasons — an argument that covers two of the four bytes. The other
  two are zero and nothing accounts for a value there, so a scan now remarks on it under
  `Category::InfoSector`.
- **A host nanosecond field far past its range read as the first nanosecond of its second
  rather than the last.** A `--from-dir` walk clamps a nanosecond field no filesystem
  produces instead of letting it reach an encoding that holds thirty bits of it, and a value
  above what a nanosecond field can hold at all took the clamp for the negative end. Both
  ends now clamp to the end they overran, however far past it the value is.

## [0.3.1] - 2026-08-03

A documentation and packaging release. No library or command-line behaviour changes,
and nothing that compiled against `0.3.0` is affected.

### Fixed

- **The `dir` feature was documented as half of what it is.** `0.3.0` added
  `DirectorySink` and `extract --to-dir` beside the existing `DirectorySource`, and the
  feature's own description — in the crate documentation, in the guide's feature table,
  and in the manifest it is declared in — still named a source alone. A feature carries
  its documentation to the registry, so the published description named one direction of
  something that reads and writes in both. The dependency it pulls is described the same
  way: `rustix` supplies the directory, node, ownership, timestamp, and
  extended-attribute calls both ends need, rather than the extended-attribute calls a
  walk alone needs.
- **`ferrosys-cli` declared `ferrosys` twice** — once as a dependency carrying `tar`
  and `dir`, and again as a development dependency carrying `tar`. An integration test
  links a crate's normal dependencies, so the second entry never selected anything the
  first did not already provide. One entry now serves both.

### Changed

- Both crates carry a `homepage`, so a registry links the guide from each crate's page
  rather than leaving the repository as the only route to it.

## [0.3.0] - 2026-08-03

A breaking release on the command line, and additive everywhere else. Three command
lines that used to be accepted are now usage errors, and the library gains a filesystem
sized to its own contents, a filesystem written back out as a directory tree,
re-identification, source composition, a walk-time timestamp clamp, and a pin over the
whole format rather than the feature set alone.

To migrate: `inspect --sarif --groups` becomes `inspect --sarif`; `format --help=x` and
`-hX` become `format --help` and `-h`; and an exhaustive `match` on `EntryKind` or
`FileContent` needs a `_` arm. Nothing else that compiled against `0.2` stops compiling.

### Added

- **`FormatPlan::fit`, `Slack`, and `format --size auto`** — size a filesystem to what goes
  in it rather than being told how large it is. There is no formula for the floor: how much
  room a filesystem has left depends on its group count, its inode tables, the descriptor
  blocks it reserves to grow into, and the journal its size earns, and every one of those
  follows from the size. So the size is searched for — candidate geometries are planned and
  the source *placed* into each one, through the format's own placement pass over a
  destination that keeps nothing, so nothing is estimated alongside the writer. **The size
  returned formats, and one block less does not:** both ends of the search's bracket are
  established by placing, so it closes holding a size that was placed and the size below it
  that was not. `Slack` says what must remain free once the source is written — nothing, a
  byte count, or a share of the filesystem in hundredths of one percent — since the smallest
  filesystem holding a source is one with no room left in it. `FormatPlan::size_bytes`
  reports what was decided, and with `Slack::None` that is the minimum size for the source.
  On the command line, `--size auto` and `--slack 20%` or `--slack 64M`; the search runs in
  the same window as every other planning failure, so a size that cannot be found leaves the
  destination unopened.
- **`DirectorySink`, `ExtractReport`, and `extract --to-dir`** — a filesystem written back
  out as a directory tree on this host, the inverse of `DirectorySource` and
  `format --from-dir`, behind the `dir` feature on Linux. The destination must exist and be
  empty; it takes the filesystem root's own mode, ownership, times, and extended attributes,
  and `/lost+found` is omitted, so what comes out is a tree `--from-dir` reads straight back.
  A file's bytes are streamed a window at a time, and what accumulates over a walk is one
  open handle per directory on the current path.

  **The image is untrusted, and a name in it is not a path to resolve.** Every directory is
  created and then opened, and everything beneath it is created through that open handle by
  its single-component name — checked to be one a directory can hold, so a name carrying a
  separator, a `..`, or a NUL is refused rather than followed. Symbolic links are written
  exactly as recorded, absolute targets included, which is safe because nothing here ever
  follows one.

  A device node needs `CAP_MKNOD`, a recorded owner needs `CAP_CHOWN`, and an extended
  attribute in the `security` or `trusted` namespace is the host's to write, so an
  unprivileged extraction stops at the first of the three and names it — a rootfs quietly
  missing `/dev/null` is a rootfs that boots differently, and one whose `ping` lost its
  `security.capability` is one that no longer runs unprivileged. `skip_privileged`
  (`--skip-privileged`) is the opt-in for a run that wants what it can have, and what it left
  out comes back in the report as `skipped`, `ownership_dropped`, and `xattrs_dropped`. Two
  times no host lets a caller set are the two an extraction cannot carry: an inode's change
  time and its creation time. There is no `--atomic` for a tree, since no rename publishes
  one at once; the empty destination stands in its place.
- **`rewrite_identity`, `IdentityChange`, and `ferrosys identity`** — change what an
  existing image is known by: its UUID (`s_uuid`), its volume label (`s_volume_name`),
  and the seed its metadata checksums derive from. Every superblock copy is written —
  the primary and each group's backup — along with the journal's own record of the UUID,
  so no copy is left claiming the old identity. A log declaring `csum_v2` or `csum_v3`
  carries a crc32c over its whole superblock, and `s_uuid` is inside what that word covers,
  so it is recomputed with it: Linux sets `csum_v3` on the journal of any `metadata_csum`
  filesystem the first time it mounts one, which makes a checksummed log the ordinary case
  for any image that has ever been used. Each copy is patched in place rather than
  re-serialized, so it keeps every field this crate does not model. Nothing is written
  until every copy has been read and every check has passed, so a refusal leaves the image
  untouched. A filesystem carrying `metadata_csum` without `metadata_csum_seed` seeds every
  checksum it holds from the UUID itself, so a UUID change there is refused;
  `set_checksum_seed` records the seed the current UUID implies and turns
  `metadata_csum_seed` on, after which the UUID moves and every existing checksum stays
  valid.
- **`LayeredSource`** — several sources composed into one, where a later layer's entry
  replaces an earlier layer's at the same path. Layers may be of different kinds and are
  consumed as they are added. A path present in more than one layer takes the last layer's
  entry whole, attributes included; a directory named again keeps its contents, so a
  configuration layer is additive; and replacing a directory with something that is not one
  drops the entries beneath it, which would otherwise have nowhere to live. Paths are
  compared as the model compares them, so `/etc/hostname` and `//etc//hostname` are one
  path. There is no deletion marker: a layer states what is present.
- **Three pin documents, split by why each one changes** — `FormatOptions::policy_pin`
  (`ferrosys-policy-pin 1`), `FormatOptions::identity_pin` (`ferrosys-identity-pin 1`), and
  `FormatPlan::geometry_pin` (`ferrosys-geometry-pin 1`). Each is self-contained and
  separately versioned, so a caller records the ones it wants without slicing a section out
  of a larger document.

  The **policy** pin is the contract: the feature set plus the grow reservation, inode
  count, reserved share, error behavior, journal size, hash algorithm and signedness, and
  whether timestamps are clamped. Nothing in it varies with the image, so a builder writing
  many images from one set of constants gets one policy pin for all of them — an empty diff
  between two images' recorded pins means they were built the same way. Where
  `FeatureSet::pin` covers five fields, this covers every option that is a property of the
  build, `errors` included, which reaches neither the feature words nor the geometry and so
  was recorded nowhere.

  The **identity** pin holds the UUID, format time, hash seed, volume label, and the
  clamped time — the fields that are meant to differ per image, kept apart so they do not
  make every policy comparison non-empty. Each is also a superblock field, so a caller that
  can open the image it built need not record this at all.

  The **geometry** pin holds what the size decided: block and inode counts, the group
  table, the reserved GDT blocks, and the journal's realized length. The per-group
  placements are one line — the group count and a `crc32c` over every field of every group —
  so the document stays a fixed size on a filesystem with millions of groups while a
  placement that moves still changes it. Pinned at a fixed reference size it catches what a
  policy pin cannot: a change to the formula behind an option whose name did not change,
  which is what `GrowReservation::Max` did when it moved every block after the descriptor
  table without moving a single input.
- **`DirectorySource::times_from_modification`** — put each walked entry's modification
  time in place of its access and change times. Reading a tree moves its access times and
  staging one moves its change times, so without this a build's bytes depend on what the
  host has done to the tree since. The modification time moves only when a file's contents
  do. This is the clamp for a build that needs reproducible bytes *and* per-file
  modification times; `FormatOptions::fixed_time` is the clamp for one that forces every
  inode to a single time instead.
- **`extract --to-tar FILE --atomic`** — write the archive to a sibling temporary file
  and rename it over the destination once the walk is complete. A walk can refuse
  part-way (a socket, an inode that does not read, an ACL that does not decode) and the
  destination is created and truncated before it starts, so without this a failed
  extract replaces an existing archive with a fragment. `format --atomic` already did
  this for images; the two now share one mechanism. The flag applies to `--to-tar FILE`,
  the only mode with a destination to rename into, and is refused elsewhere rather than
  accepted and ignored.

### Changed

- **`inspect --sarif --groups` is a usage error.** SARIF is a findings log with nowhere
  to render a group table, so the pair used to read every descriptor and discard the
  result — and a descriptor that failed to read aborted the run before any SARIF was
  emitted, letting an inert flag suppress the document a pipeline asked for.
  `--sarif --json` and `--sarif --quick` were already refused.
- **An option that takes no value refuses one everywhere.** `format --help=x` and `-hX`
  printed help or reported "not an option"; both now report that the option takes no
  value, as `--json=yes` already did.
- **A value error names every form the option accepts.** `--grow huge` names `none` and
  `max` beside the byte-count grammar, `--journal fast` names `auto` beside the block
  count, and a `--time` outside the field's range is reported as out of range rather than
  as text that is not a number.
- **Terminal rendering escapes the backslash and the bidirectional controls.** A name,
  target, or attribute value now renders to exactly one input — a name holding the four
  characters `\x1b` no longer renders identically to one holding the escape byte — and
  `U+202E` and its relatives are escaped rather than left to reverse the rest of the
  line. JSON output is unchanged; it carried the exact bytes already.
- **The `format --size` too small for a journal hint names a flag combination the tool
  accepts.** It offered `-O ^has_journal`, which the default profile refuses because
  `orphan_file` needs a journal; it now offers `-O ^has_journal,^orphan_file`.
- **`ferrosys-cli` no longer depends on the `tar` crate.** It writes archives through the
  library's `ArchiveSink`, which takes a plain writer, so the dependency was unused.
- **Placing a file no longer copies it.** Block chunks borrow the source and only a final
  short chunk is padded into a block of its own, so peak memory while placing a file is
  the file rather than twice the file — which is what `format_to` documents. The bytes
  written are identical.
- **`EntryKind` and `FileContent` are `#[non_exhaustive]`.** Both are enums a source
  builds from and a caller reads, and both will gain variants; marked, adding one is
  additive. Construction is unaffected — every existing variant is built exactly as
  before — and only an exhaustive `match` outside the crate needs a `_` arm.

### Fixed

- **A file past what a classic block map reaches is refused rather than written short.**
  An ext2 or ext3 file spans twelve direct pointers and three levels of indirect blocks —
  `12 + p + p² + p³` blocks for `p = block_size / 4`, which is 16.06 GiB at a 1024-byte
  block and 4.004 TiB at the 4096-byte default. Past that the map ran out of words and the
  file's tail was neither mapped nor written, while its size claimed the whole length and
  the format reported success. It is now `FormatError::FileTooLargeForBlockMap`, the
  block-mapped twin of the bound the extent path already had. Only a feature set without
  `extent` reaches it, and only a file or an explicit `--journal` size past the reach.
- **An inode count spread thinly over many groups no longer plans a filesystem with no
  inodes.** A group's inode count is rounded to a multiple of eight, and a per-group share
  below that step rounded to none at all — so `format -b 1024 -N 16` on a 32 MiB filesystem
  planned `s_inodes_per_group = 0` and then failed reporting that the source needed more
  inodes than the filesystem had. A group now holds at least eight, which is where `mke2fs`
  holds it too, so the geometry stays byte-identical and the filesystem is one every tool
  can divide by. `InodeCount::Count` documents that a count spread this thinly realizes
  eight times the group count.
- **`--atomic` creates its temporary file rather than opening whatever is there.** The name
  is a sibling of the destination and a process id, so it is derivable; the open now fails
  if the name exists at all and never follows a symbolic link, where before it would have
  truncated and written through one.
- **`rec_len_to_disk` saturates on a length past the field.** A record never exceeds its
  block, so a length of 65536 or more with a smaller block size is not a record; it now
  saturates rather than truncating to a smaller wrong value, matching `min_rec_len`. No
  caller in the crate reaches it.

## [0.2.0] - 2026-07-25

A breaking release, and mostly one thing: closing the places where a later addition
would have had to break again. Positional parameter lists become parameter structs,
tuple error variants gain named fields, the types that grow gain `#[non_exhaustive]`,
and the `ext` glob re-export names each item it carries. A dependant on
`ferrosys = "0.1"` keeps building against `0.1.0` until it opts in.

To migrate: `plan_layout(&PlanRequest)`, `journal::build_superblock(&JournalParams)`,
`Reader::open_with(src, &OpenOptions)` for `Reader::open_at`, `Checksummer::scheme`
for `Checksummer::enabled`, `EntryKind::File(FileContent)` for a `Vec<u8>` payload,
and `ExtentLeaf::to_bytes` returning a `Result`. An exhaustive `match` on an error
needs a `_` arm, and `FormatOptions`, `ModelConfig`, and `FeatureSet` are built from a
constructor or a baseline constant rather than a struct literal.

### Added

- **`DirectorySource`, behind the new `dir` feature** (Linux) — a filesystem built from
  a host directory tree, which is what `mke2fs -d` does: modes, ownership, all three
  times to the nanosecond, symlinks (recorded, never followed), hard links coalesced by
  inode, device, FIFO and socket nodes, and extended attributes with their POSIX ACLs.
  Entries sort by path and attributes by name, so one tree always walks to one entry
  list, whatever order the host's directories are read in; the times on that list are the
  host's, including the access times a walk of an atime-keeping host moves as it reads.
  Each file's bytes are read as that file is placed, so peak memory is the largest single
  file. `owner(uid, gid)` replaces host ownership, for a build that does not run as root.
  Failures are a typed `HostError`. Adds one dependency, `rustix`.
- **`FormatPlan`** — the fallible half of a format as a value. `FormatPlan::new` parses
  the source, plans the geometry, builds and checks the inode model, and sizes the
  journal; `layout()` and `used_inodes()` report what the write will realize, and
  `write_to` writes it. `format` and `format_to` both route through it.
- **Streaming reads** — `Reader::read_into` reads a range a window at a time,
  `read_data_to` streams a whole file to any `Write`, and `walk_with` walks the tree
  lazily, handing each entry to a callback that may read as it walks and whose own error
  type comes straight back out.
- **`ArchiveSink`, behind the `tar` feature** — a filesystem written back out as a tar
  archive, streaming each member's body. Ownership, modes, nanosecond times, symlinks,
  hard links, device and FIFO nodes, extended attributes, and POSIX ACLs travel in PAX
  records, so an archive that round-trips through `ArchiveSource` describes the same
  filesystem at both ends.
- **`ArchiveSource::from_path`** — leaves each member's bytes in the archive until that
  file is placed, so a format's peak memory is the largest member rather than the sum of
  them all. Byte-identical to `from_reader`. Every declared body is checked present
  before a single file is placed, so a truncated or crafted archive fails at parse; the
  descriptor stays open, so replacing the archive by rename is safe.
- **`FileContent` and `FileRange`** — a regular entry's contents as owned bytes or as a
  range of a host file read at placement, both usable in one entry list.
  `FileRange::at_path` reopens at each read, which is what lets a source name a range in
  each of a hundred thousand files; `FileRange::new` shares one descriptor. The length
  is known without reading, so the `large_file` check names the offending path before
  any bytes are read.
- **Feature-word coherence, both ways** — the formatter refuses a feature set that
  cannot describe what it would write, naming the conflict and the entry: extended
  attributes without `ext_attr`, a regular file of 2 GiB or more without `large_file`,
  and `resize_inode` at a 4096-byte block without `large_file`. The reader reports the
  same disagreements in a foreign image as anomalies, along with the hash-index flag on
  something that is not a directory (`ReadError::IndexFlagOnNonDirectory`).
- **`detect_with(src, &DetectOptions)`** — classifies a filesystem beginning at an
  offset within the source, and classifies leniently, so an image with a quirk a strict
  read would refuse still answers. `detect` is unchanged.
- **A `serde` feature**, off by default — `Serialize` for `Anomaly`, `ScanReport`,
  `Severity`, `Category`, `Location`, `Layout`, `GroupLayout`, `BlockRange`,
  `FeatureSet`, `Profile`, and the three feature words, which serialize as the raw
  on-disk word each wraps. Serialization only; `to_json` and `to_sarif` stay the
  schema-versioned canonical form.
- **`OpenOptions` and `Limits`** — where the filesystem begins in the source, the policy
  to hold it to, caps on what one read may allocate, and a `metadata_csum` seed to
  verify against when an image's stored seed and UUID no longer agree. The defaults
  impose nothing, so any image this crate wrote reads back whole. `max_file_bytes`
  bounds the logical-to-physical mapping a read builds as well as the buffer it returns.
- **A scan's findings cap** — `Limits::max_anomalies`, defaulting to
  `ScanReport::MAX_ANOMALIES`, and `ScanReport::is_truncated`, reported as `truncated`
  in JSON, a closing line in the table, and a SARIF `toolExecutionNotifications` entry,
  each naming the cap that actually applied. A truncated report is a floor:
  `worst_severity` and `has_fatal` under-report, and `is_clean` is `false` whatever the
  report holds.
- **`FeatureSet::pin`** — the whole feature set as one canonical, versioned document:
  every feature word twice over, as exact bits and as readable names, plus the block and
  inode sizes a name list omits, so a layout change becomes a diff a person reads. With
  it: `EMPTY`, the base to replay a recorded name list back through `with_feature`;
  `LATEST`, which tracks what a current `mke2fs` writes for ext4 and may change in any
  release, where `DEFAULT` is fixed and is the value to pin an on-disk contract to (equal
  today); `with_block_size`, `with_inode_size`, `has_ext_attr`, `has_large_file`; and
  `ext::feature::LARGE_FILE_MIN_SIZE`.
- **Parameter objects for the pipeline's inputs** — `PlanRequest`, with
  `FormatOptions::plan_request` deriving it from a format's options; `JournalParams`;
  `ModelConfig::new`, which derives the sizes and the feature answers from one
  `FeatureSet`; and `CsumScheme`, which answers separately whether metadata objects
  carry a checksum field and whether the uninit block-group semantics apply.
- **`ext::read::SCAN_SCHEMA_VERSION`** and a `schema` field at the head of the JSON a
  `ScanReport` renders: a downstream parser depends on a shape no Rust signature
  describes, so the shape names its own version.
- `HashVersion::name` and a `Display` impl; `ext::read::MIN_DIRENT_LEN` and
  `ext::read::MAX_SYMLINK_HOPS`, each naming the value a `ReadError` fires at.
- New error cases: `ReadError::FileTooLarge`; `ArchiveError::{Read, Compressed,
  Unrepresentable, XattrNameUnrepresentable}`; `FormatError::{FilesystemTooSmallForJournal,
  JournalDoesNotFit}`; `HostError::RepeatedDirectory`, naming both paths when two of them
  reach one directory — a bind mount under the root, which a walk would otherwise follow
  until the host runs out of memory; and a `reserved_gdt_blocks` field on
  `GeometryError::TooSmall`.
- **On the command line** — `format --from-dir DIR`, `--owner UID:GID`, `--dry-run`
  (the geometry the command would realize, without opening the destination at all), and
  `--atomic` (write to a sibling temporary file and rename it over the destination once
  the image is whole); `extract --stat PATH [--json]`, reporting everything one path's
  inode records, and `extract --max-file-bytes N`; `detect [--offset N] [--json]` as a
  fourth subcommand; free block and inode counts in the format summary and its JSON
  receipt; and a hint naming the option at fault — `--grow`, `-t ext2`, `--journal` —
  where a default rather than the caller caused the failure.

### Changed

- **`GrowReservation::Max` spends at most a sixty-fourth of the filesystem on growth
  headroom.** Filling the resize inode's map costs a fixed 1024 blocks at a 4096-byte
  block whatever the filesystem's size — a quarter of a 16 MiB one, which put every
  filesystem below 16 MiB out of reach at the defaults. `Max` is now `min(map ceiling,
  descriptor ceiling, total_blocks / 64)`: byte-identical at 256 MiB and above, where
  those 1024 blocks *are* a sixty-fourth, and proportional below it, so a 16 MiB image
  reserves 64 blocks and still grows to 520 GiB. An explicit `UpTo` target is an intent
  and is never reduced.
- **A read past `Limits::max_file_bytes` is `ReadError::FileTooLarge`, not a
  truncation**, naming the size and the bound. A caller extracting a tree would
  otherwise write a silently incomplete file and see success.
- **A format's every decision is made before the destination is opened** — source
  parsed, geometry planned, model built and checked, journal sized, all through
  `FormatPlan`. A run that cannot succeed leaves the file that was there exactly as it
  was. `--atomic` is the opt-in for the stronger contract, and not the default, because
  a rename replaces the inode: the destination's mode, ownership, ACLs, and any extra
  hard links would silently change.
- **Every public item has exactly one path.** The layer modules under `ext` no longer
  re-export what the flat `ext` namespace carries: the flat namespace holds the types,
  the errors, and the pipeline's entry points, and a layer holds only what is not lifted
  — its constants, the on-disk structures, and machinery like `ExtentNodeBlock` and
  `TreeShape`. `ext::alloc`, `ext::archive`, `ext::csum`, `ext::dir`,
  `ext::materialize`, and `ext::source` had nothing left and are gone. The `ext` module
  also names every re-export rather than globbing, so each item's publicness is a
  decision; the surface is unchanged, and held to a committed snapshot that says so.
- **`#[non_exhaustive]` on the shapes that grow** — every public error enum (`AclError`,
  `AllocError`, `ArchiveError`, `DirError`, `ExtentError`, `FeatureError`,
  `FormatError`, `GeometryError`, `ModelError`, `ParseError`, `ReadError`) and every
  data-carrying variant within them; the values a caller only reads (`Layout`,
  `GroupLayout`, `Anomaly`, `Location`, `Category`, `Entry`, `WalkEntry`, `FsModel`,
  `ModelInode`, `DirChild`, `JournalSuperblock`, `DirBlock`, `ExtentTree`, `TreeShape`);
  the inputs `FormatOptions`, `ModelConfig`, and `FeatureSet`; the policy enums
  `GrowReservation`, `InodeCount`, `JournalSize`, and `HashVersion`, at the enum level
  only, so every variant stays constructible; and `SuperBlock`, `Inode`, and
  `GroupDescriptor`, whose Rust literal closes — construction goes through `Default` (or
  `Inode::empty`) plus field assignment — while their byte layout, `read_from`,
  `write_to`, and `SIZE`, is untouched. The closed domains stay exhaustive: `Severity`
  is an ordered scale a policy threshold is set over, `Profile` names a complete
  lineage, and `ErrorBehavior`, `FileType`, and `AclQualifier` are closed by the format
  or by POSIX.
- **Error variants that carried a tuple now carry named fields**, so a payload gains
  context as a patch. `ReadError::Io` and `DetectError::Io` also carry the
  `std::io::ErrorKind`, so a truncated image and an unreadable one can be told apart
  without matching on the message text.
- **`Checksummer` and `DirLayout` are sealed.** Both are seams this crate swaps between
  its own implementations, and a substitute that compiled but computed the wrong
  checksum would produce an image this crate calls checksummed and no checker accepts.
  `Source` stays open — it is the extension point.
- **`EntryKind::File` carries a `FileContent`** rather than a `Vec<u8>`, and
  `TreeBuilder::file`'s bound moved from `impl Into<Vec<u8>>` to
  `impl Into<FileContent>`. `FileContent` converts from `Vec<u8>`, `String`, `&[u8]`,
  `&[u8; N]`, `&str`, and `FileRange`, so every argument the old bound accepted still
  compiles.
- `ExtentLeaf::to_bytes` returns a `Result`, refusing a run `ee_len` does not encode
  rather than writing bytes that read back as a different run.
- **A scan's memory is bounded by the bytes the source holds** rather than by what an
  image's inodes claim: a directory's block map is bounded by the blocks the image has,
  each block is judged once however many logical offsets name it, and a report holds at
  most its anomaly cap. The hostile-name check walks a directory's blocks itself, so a
  directory holding a malformed record is still checked for a name carrying `/` or a NUL.
- **`Source::into_entries` returns a `Vec`, and that is a decision.** Inode numbers are
  assigned in sorted path order, which is what makes two formats of one entry list
  byte-identical, so the model materializes and sorts the whole list whatever a source
  hands over. The bound is the entry count, not the bytes, since a file's contents may
  stay a `FileContent::Range` until it is placed.
- **`format_to`'s memory contract is corrected** — it holds the entry list and every
  owned file's bytes for the whole run, not one file at a time.
  `ArchiveSource::from_path` is what makes the smaller peak available.
- **The three CLI documents open with the same `schema` field.** `format --json` and
  `extract --list --json` used `version` while `inspect --json` used `schema`.
- **`--from-tar`'s help describes the named-file case**, rather than reporting
  `--from-tar -`'s in-memory peak as if it applied to a named file too and steering
  callers off the lazy path. A compressed archive is named as such — `gzip`, `zstd`,
  `xz`, `bzip2`, `lz4`, `lzma`, `lzop`, or `compress` — rather than reported as
  malformed tar.
- **The CLI's error enum no longer carries what belongs to the library.** `AclError` and
  the unrepresentable-entry cases moved into `ArchiveError`; the exit-code map unwraps
  `ArchiveError::Read` and `ArchiveError::Acl` to 4, a verdict about the image, while a
  socket or an unwritable attribute name stays 8, the request that cannot be carried out.
- `format` reports an image larger than the platform addresses as
  `FormatError::ImageTooLargeInMemory` instead of sizing its buffer from the low bits of
  the count; `format_to` streams an image of any size.
- The inode-bitmap checksum covers `(inodes_per_group + 7) / 8` bytes, as
  `ext4_inode_bitmap_csum_set` does, on both the writing and the reading side.
- A PAX timestamp carries a fraction larger than a second into the seconds, so a foreign
  inode's thirty-bit fraction renders as the instant it names.
- `ferrosys inspect` reports "at least *n* anomalies" when the scan stopped at its cap.

### Fixed

- **`Reader::walk` is bounded.** Distinct directory inodes may map the same data blocks,
  so a crafted image could describe an unbounded number of names from a handful of
  blocks. The walk is held to the number of names the source has room to hold — a bound
  no well-formed image reaches — and reaching it is `ReadError::WalkTooLarge` rather
  than a short list a caller would extract and see succeed.
- **`ferrosys-cli` builds on every platform it is installed on.** The directory source
  `--from-dir` walks with is Linux's, and the binary reached it unconditionally, so
  `cargo install ferrosys-cli` off Linux ended at the compiler rather than at a message.
  `--from-dir` is the one thing scoped to the platform that carries it — there the
  option names itself as unavailable and exits 8 — and `format --from-tar`, `inspect`,
  `extract`, and `detect` are the same everywhere. A CI job checks macOS, Windows, and a
  32-bit target.
- **`GroupDescriptor::read_from` and `write_to` refuse a `desc_size` below `SIZE_32`.**
  Both address every field within the first 32 bytes, so a smaller width names no
  descriptor the format has; it is `ParseError::InvalidField` rather than an index past
  the buffer. No image reaches this — the reader's own `s_desc_size` bound is stricter —
  but a consumer calling the on-disk layer directly supplies both values itself.
- **`extent::node_capacity`, `extent::tail_offset`, and `ondisk::dx_limit` are total** —
  each answers zero where the structure does not fit in the caller-supplied size, rather
  than wrapping into a count that would index outside the block it describes.
- **An extended attribute's `e_value_size` is added under a checked width.** The field
  is the image's own claim and spans the whole `u32` range; where `usize` is 32 bits
  wide the sum that locates the end of the value wraps, and a wrapped end names a range
  inside the region that would read back as the attribute's bytes. It is
  `ParseError::InvalidField`.
- **A tar member's header declares the length its body will run to.** `ArchiveSink`
  states what the reader yields for an inode rather than what the inode's size field
  claims. The two agree for every file a block map reaches; past the
  2^32-logical-block ceiling — 16 TiB at a 4 KiB block — the field is the larger, and a
  header promising more than the body carries mis-frames the archive for a reader that
  trusts it.

## [0.1.0] - 2026-07-21

Initial release of the `ferrosys` library and the `ferrosys` command line.

### Added

- **ext2, ext3, and ext4 support** — one formatter and one reader across the
  lineage, from the classic direct/indirect block map to extent trees of any
  depth. A profile selects a family's baseline feature set, and individual
  features layer on top.
- **Resize-safe geometry** — superblock and group-descriptor backups and reserved
  group-descriptor-table blocks, sized by a grow reservation, so an image grows in
  place without relocating its descriptor table. Block sizes of 1024, 2048, and
  4096 bytes.
- **Byte-reproducible output** — the UUID, directory-hash seed, and timestamps are
  inputs, so the same inputs write the same image every time.
- **Full fidelity** — regular files, directories, symlinks, hard links, and
  character / block device, FIFO, and socket nodes, each with ownership, mode
  bits, and access, change, and modification times at nanosecond precision;
  extended attributes and POSIX ACLs, inline and in an external block; metadata
  checksums (`metadata_csum`); a format-time jbd2 journal (`has_journal`); and an
  orphan file (`orphan_file`).
- **Hash-indexed directories** (`dir_index`) — a directory that outgrows one block
  gains an htree ordered by the half-MD4, TEA, or legacy name hash, with the hash
  and the byte signedness of names recorded in the image.
- **Tunable geometry** — inode count by exact value or bytes-per-inode density,
  reserved super-user space as a percentage to two decimal places, and a volume
  label, each defaulting to what the image size implies.
- **A robust reader** — bounds-checks every field into typed errors, reads foreign
  images other tools wrote, resolves paths through symbolic links against the
  image's own root, and scans a whole image into typed anomalies rendered as JSON,
  SARIF, or a table.
- **Streaming output** — `format_to` writes an image to any seekable destination,
  touching only the blocks the filesystem uses, so the file stays sparse and the
  image can exceed memory. Block addressing is 64-bit, for filesystems past 16 TiB.
- **A tar / PAX archive source** (the `tar` feature) — builds a filesystem from a
  tar archive with its PAX timestamps, `SCHILY.xattr.*` attributes, and
  `SCHILY.acl.*` ACL records.
- **The `ferrosys` command line** — `format` writes a filesystem, `inspect`
  reports on one and says whether it is sound, and `extract` reads the contents
  back out as a tar archive, one file's bytes, or a listing. Exit codes mirror
  `e2fsck`'s.

[0.5.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.5.0
[0.4.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.4.0
[0.3.1]: https://github.com/gregordinary/ferrosys/releases/tag/v0.3.1
[0.3.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.3.0
[0.2.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.2.0
[0.1.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.1.0
