# Changelog

All notable changes to ferrosys are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is below `1.0`, the minor version is the breaking axis: a
breaking change bumps the minor, and the patch covers backward-compatible fixes.

## [0.3.0] - 2026-08-02

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
  so no copy is left claiming the old identity. Each copy is patched in place rather than
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

[0.3.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.3.0
[0.2.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.2.0
[0.1.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.1.0
