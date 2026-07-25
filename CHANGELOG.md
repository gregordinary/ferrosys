# Changelog

All notable changes to ferrosys are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is below `1.0`, the minor version is the breaking axis: a
breaking change bumps the minor, and the patch covers backward-compatible fixes.

## [0.2.0] - 2026-07-25

This release breaks API, so the minor moves: a dependant on `ferrosys = "0.1"` keeps
building against `0.1.0` until it opts in.

Most of it is one thing — closing the places where a future addition would have had to
be a breaking change. A positional parameter list, an exhaustive struct, a tuple error
variant, and a glob re-export all share the property that growing them breaks a
dependant, and each is cheap to reshape now and expensive after the surface is depended
on.

The breaks are `plan_layout`'s and `journal::build_superblock`'s signatures,
`Reader::open_at` becoming `Reader::open_with`, `Checksummer::enabled` becoming
`Checksummer::scheme`, `EntryKind::File`'s payload, `ExtentLeaf::to_bytes`'s return
type, the error variants that changed from tuple to named fields, and the types that
gained `#[non_exhaustive]`. Every one has a named replacement below. A caller that
matches an error exhaustively needs a `_` arm, and one that builds `FormatOptions`,
`ModelConfig`, or `FeatureSet` from a struct literal builds it from a constructor or a
baseline constant instead.

### Added

- **`DirectorySource`, behind the new `dir` feature** — a filesystem built from a directory
  tree on this machine, which is what `mke2fs -d` does and what an image builder needs. The
  directory becomes the filesystem root; modes, ownership, all three times to the
  nanosecond, symlinks (recorded, never followed), hard links coalesced by inode, device,
  FIFO and socket nodes, and extended attributes with their POSIX ACLs (translated from the
  version-2 form the syscall boundary speaks into the compact form ext stores) all come
  across. Entries sort by path and attributes by name, so the same tree walks to the same
  image whatever order the host listed its directories in. Each file's bytes are read as
  that file is placed and no descriptor is held in between, so the tree may hold any number
  of files and peak memory is the largest single one. `owner(uid, gid)` replaces the host's
  ownership throughout, which is what a build that does not run as root needs. The feature
  adds one dependency, `rustix`, for the two extended-attribute calls the standard library
  has no equivalent of, and is present on Linux. Failures are a typed `HostError`.
- **`FormatPlan`** — the fallible half of a format as a value. `FormatPlan::new` parses the
  source, plans the geometry, builds and checks the inode model, and sizes the journal;
  what it returns can only be written. `layout()` and `used_inodes()` report what the write
  will realize before a byte is written, and `write_to` writes it. `format` and `format_to`
  both route through it, so there is one derivation of a layout rather than two, and the
  destination of a format is not opened until everything that can fail has succeeded.
- **A reader that never has to hold a file.** `Reader::read_into(&inode, offset, buf)`
  reads a range, mapping a window of the file at a time; `read_data_to(&inode, writer)`
  streams a whole file to any `Write` a window at a time; and `walk_with(|reader, entry|
  …)` walks the tree lazily, handing each entry to a callback that receives the reader and
  so may read as it walks. `walk_with` is generic over the callback's error type, so a
  consumer's own failure comes straight back out.
- **`ArchiveSink`**, behind the `tar` feature — a filesystem written back out as a tar
  archive, streaming each member's body rather than buffering it. `ArchiveSink::new(w)
  .write_tree(&mut reader)` carries ownership, modes, times to the nanosecond, symlinks,
  hard links, device and FIFO nodes, extended attributes, and POSIX ACLs in PAX records, so
  an archive that makes the round trip through `ArchiveSource` describes the same
  filesystem at both ends.
- **`detect_with(src, &DetectOptions)`**, which classifies a filesystem beginning at an
  offset within the source — a partition inside a whole-disk image, or a region a carver
  located — and classifies leniently, so an image with a quirk a strict read would refuse
  still answers. `detect` is unchanged.
- **A `serde` feature**, off by default, adding `Serialize` to the values a consumer embeds
  in a document of its own: `Anomaly`, `ScanReport`, `Severity`, `Category`, `Location`,
  `Layout`, `GroupLayout`, `BlockRange`, `FeatureSet`, `Profile`, and the three feature
  words, which serialize as the raw on-disk word each wraps. Serialization only — these are
  values a scan or a planner produces, never reconstructed from a document. The crate's own
  `to_json` and `to_sarif` emitters are unaffected and stay the schema-versioned canonical
  form.
- **`FileRange::at_path`**, a range named by path and opened at each read rather than
  holding a descriptor. It is what lets a source name a range in each of a hundred thousand
  separate files; `FileRange::new` still carries a shared open descriptor, which is what an
  archive source wants.
- `ReadError::FileTooLarge`, `ArchiveError::{Read, Compressed, Unrepresentable,
  XattrNameUnrepresentable}`, `FormatError::{FilesystemTooSmallForJournal,
  JournalDoesNotFit}`, and a `reserved_gdt_blocks` field on `GeometryError::TooSmall`.
- **On the command line:** `format --from-dir DIR` and `--owner UID:GID`; `format
  --dry-run`, which reports the geometry the command would realize without opening the
  destination at all; `format --atomic`, which writes to a sibling temporary file and
  renames it over the destination once the image is whole; `extract --stat PATH [--json]`,
  reporting everything one path's inode records, extended attributes and decoded ACLs
  included; `extract --max-file-bytes N`; `detect [--offset N] [--json]` as a fourth
  subcommand; free block and inode counts in the format summary and its JSON receipt, so a
  format's overhead is visible; and a hint naming the option at fault — `--grow`, `-t
  ext2`, `--journal` — on the failures that are a default's doing rather than the caller's.

- **Feature-word coherence, both ways.** The formatter refuses a feature set that
  cannot describe what it would write, naming the conflict and the entry it is
  about: extended attributes without `ext_attr`, a regular file of 2 GiB or more
  without `large_file`, and `resize_inode` at a 4096-byte block without
  `large_file` — where the resize inode is itself a file that large. The reader
  reports the same disagreements in an image it did not write, as anomalies over
  `i_file_acl` without `ext_attr`, a large regular file without `large_file`, a
  hash-indexed directory without `dir_index`, and — a separate fault, filed against the
  inode rather than a directory — the hash-index flag on something that is not a directory
  at all (`ReadError::IndexFlagOnNonDirectory`).
- **`ArchiveSource::from_path`**, which opens a tar archive and leaves each member's
  bytes on disk until that file is placed. A format's peak memory becomes the largest
  single member rather than the sum of them all — for a rootfs archive, the difference
  between gigabytes and megabytes. It writes byte-identical images to `from_reader`,
  which is unchanged and still takes any stream. The archive is checked to hold every
  body it declares before a single file is placed, including a member whose declared size
  no block boundary can represent, so a truncated or crafted archive fails at parse rather
  than part-way through an image. The archive must not be modified in place until the
  format finishes; the descriptor is held open, so replacing it by rename is safe, and an
  in-place truncation that does reach the format names the path and the range it could not
  read.
- **`FileContent`** and **`FileRange`**, the contents of a regular source entry: owned
  bytes, or a range of a host file read at placement. Both coexist in one entry list, so
  a caller may take an archive-backed list and replace one entry's contents with bytes
  it computed. The length is known without reading, so the `large_file` check still
  names the offending path before any bytes are read. `FileContent::read` returns a
  `Cow<'_, [u8]>`, so an owned entry is borrowed rather than copied and a format never
  holds two copies of one file; a failed range read names the path, the offset, and the
  length, since `FormatError::Io` is transparent and that message is the whole of what a
  caller sees.
- **`FeatureSet::pin`**, the whole feature set as one canonical, versioned document to
  record and compare — every feature word twice over, as exact bits and as readable
  names, plus the block and inode sizes a feature-name list omits. Recording it turns a
  layout change into a diff a person reads rather than changed image bytes nobody
  notices.
- **`FeatureSet::EMPTY`**, a set with no features: the base to replay a recorded list of
  feature names back through `with_feature`, which is how a pin's readable half is
  checked against its exact half.
- **`FeatureSet::LATEST`**, which tracks what a current `mke2fs` writes for ext4 and may
  change in any release. `DEFAULT` is documented as fixed and is the value to pin an
  on-disk contract to; `LATEST` is the opt-in for parity with the current tool. They are
  equal today.
- **`FeatureSet::with_block_size`** and **`with_inode_size`**.
- `FeatureSet::has_ext_attr`, `FeatureSet::has_large_file`, and
  `ext::feature::LARGE_FILE_MIN_SIZE`, the size at which a regular file needs
  `large_file`.
- **`PlanRequest`**, the geometry planner's inputs as one value, with
  `FormatOptions::plan_request` deriving it from a format's options.
- **`OpenOptions`** and **`Limits`** for the reader: where the filesystem begins in the
  source, the policy to hold it to, caps on what one read may allocate, and a
  `metadata_csum` seed to verify against when an image's stored seed and UUID no longer
  agree. The limits default to imposing nothing, so an image of any size this crate
  wrote reads back whole at the default settings. `max_file_bytes` bounds the
  logical-to-physical mapping a read builds as well as the buffer it returns — the
  mapping is eight bytes per logical block against one byte per byte returned, so it is
  the larger of the two on the crafted `i_size` the cap exists for.
- **`CsumScheme`**, which names which checksums a filesystem carries and answers the two
  questions a caller has — whether metadata objects carry a checksum field, and whether
  the uninit block-group semantics apply — separately, because a third scheme the format
  defines answers them differently.
- **`JournalParams`**, the journal superblock's inputs as one value.
- `Limits::max_anomalies`, the findings cap a scan runs under, defaulting to
  `ScanReport::MAX_ANOMALIES`; and `ScanReport::is_truncated`, with `truncated` in the
  JSON report, a closing line in the table, and a SARIF `toolExecutionNotifications`
  entry. Both notices name the cap that actually applied, not the default constant. A
  truncated report is a floor: `worst_severity` and `has_fatal` under-report, and
  `is_clean` is `false` whatever the report holds, since a scan that stopped short never
  saw enough to call an image clean.
- **`ext::read::SCAN_SCHEMA_VERSION`**, and a `schema` field at the head of the JSON a
  `ScanReport` renders. A downstream parser depends on the emitted shape and no Rust
  signature describes it, so the shape names its own version.
- **`HashVersion::name`** and a `Display` impl, so the on-disk name lives with the type
  rather than in each tool that prints it.
- **`ext::read::MIN_DIRENT_LEN`**, the bound `Reader::walk` derives from the source's
  length, and **`ext::read::MAX_SYMLINK_HOPS`**, the link budget a path resolution
  spends. Both name the value a `ReadError` fires at.
- Every constant is reached through the layer module that defines it, never the flat `ext`
  namespace: a constant is a detail of the layer whose contract it states, and the layers
  hold nearly forty of them. The flat namespace carries the types, the errors, and the
  pipeline's entry-point functions — each by exactly one path.
- `ModelConfig::new`, which derives the block and inode sizes and the three
  feature answers from one `FeatureSet` — the derivation a caller would otherwise
  wire field by field, where a wrong answer judges a source against a filesystem
  the writer is not about to emit.

### Changed

- **`GrowReservation::Max` no longer spends more than a sixty-fourth of the filesystem on
  growth headroom.** Filling the resize inode's map costs a fixed 1024 blocks at a
  4096-byte block whatever the filesystem's size — negligible on a large image and a
  quarter of a 16 MiB one, which put every filesystem below 16 MiB out of reach at the
  defaults. `Max` is now `min(map ceiling, descriptor ceiling, total_blocks / 64)`
  — one block in sixty-four. At 256 MiB and above the map's 1024 blocks *are* a
  sixty-fourth, so the reservation is byte-identical to before; below that it is
  proportional, and a 16 MiB image reserves 64 blocks and still grows to 512 GiB. The clamp
  applies to `Max` alone: an explicit `UpTo` target is an intent and is never reduced.
- **A read past `Limits::max_file_bytes` is an error, not a truncation.** It is
  `ReadError::FileTooLarge`, naming the size and the bound. A truncated file that looked
  whole was the worse outcome by far: a caller extracting a tree would write it out, see
  success, and carry a silently incomplete file forward.
- **Every public item has exactly one path.** The layer modules under `ext` no longer
  re-export what the flat `ext` namespace carries: types, errors, and the pipeline's entry
  points are reached flat, and a layer module holds only what is not lifted — its
  constants, the on-disk structures, and machinery like `ExtentNodeBlock`, `TreeShape`, and
  the model's own inode representation. `ext::alloc`, `ext::archive`, `ext::csum`,
  `ext::dir`, `ext::materialize`, and `ext::source` had nothing left and are gone. A caller
  reaching a type through its layer module reaches it flat instead; rustdoc lists each item
  once, and there is one idiom rather than two that both compile.
- **A format's every decision is made before the destination is opened.** The source is
  parsed, the geometry planned, the inode model built and checked, and the journal sized —
  all of it through `FormatPlan` — before the file is created or truncated. A run that
  cannot succeed leaves the file that was there exactly as it was. This is `mke2fs`'s
  contract, and `--atomic` is the opt-in for the stronger one: not atomic by default,
  because a rename replaces the inode, so the destination's mode, ownership, ACLs, and any
  extra hard links would silently change.
- **The three CLI documents open with the same `schema` field.** `format --json` and
  `extract --list --json` used `version` while `inspect --json`'s scan block used `schema`
  — three consumers, three names for one idea.
- **`--from-tar`'s help text told the truth about the wrong case.** It described the
  in-memory peak of `--from-tar -` as if it applied to a named file too, steering callers
  away from the lazy path the tool has had all along. A compressed archive is now named as
  such — `gzip`, `zstd`, `xz`, `bzip2`, `lz4`, `lzma`, `lzop`, or `compress` — rather than
  reported as malformed tar.
- **The CLI's error enum no longer carries what belongs to the library.** `AclError` and
  the unrepresentable-entry cases moved into `ArchiveError`; the exit-code map unwraps
  `ArchiveError::Read` and `ArchiveError::Acl` to 4 (a verdict about the image) while a
  socket or an unwritable attribute name stays 8 (the request cannot be carried out).
- **`Source::into_entries` returns a `Vec`, and that is a decision.** Inode numbers are
  assigned in sorted path order, which is what makes two formats of one tree byte-identical,
  so the model materializes and sorts the whole list whatever a source hands over — an
  iterator would be collected on arrival rather than streamed. The trait's documentation now
  says so, along with the bound: the cost is the entry count, not the bytes, since a file's
  contents may be a `FileContent::Range` until it is placed.

- **`plan_layout(&PlanRequest)`** replaces the five positional arguments. Every geometry
  knob is now a field, so one the planner grows reaches a caller as something they may
  ignore rather than as an argument they must pass.
- **`Reader::open_with(src, &OpenOptions)`** replaces `Reader::open_at(src, base,
  policy)`. `Reader::open(src)` is unchanged.
- **`journal::build_superblock(&JournalParams)`** replaces its three positional
  arguments.
- **`Checksummer::scheme() -> CsumScheme`** replaces `Checksummer::enabled() -> bool`.
  The trait is also **sealed**, as is `DirLayout`: both are seams this crate swaps
  between its own implementations, not extension points, and a substitute that compiled
  but computed the wrong checksum would produce an image this crate calls checksummed
  and no checker accepts. `Source` stays open — it is the extension point.
- **`EntryKind::File`** carries a `FileContent` rather than a `Vec<u8>`. A caller that
  matches on the variant reads a `FileContent`. `TreeBuilder::file`'s bound moved from
  `impl Into<Vec<u8>>` to `impl Into<FileContent>`; `FileContent` converts from `Vec<u8>`,
  `String`, `&[u8]`, `&[u8; N]`, `&str`, and `FileRange`, so every argument the old bound
  accepted still compiles.
- `ExtentLeaf::to_bytes` returns a `Result`, refusing a run `ee_len` does not
  encode rather than writing bytes that read back as a different run.
- `ModelConfig` carries `ext_attr` and `large_file`, the two feature answers the
  model needs to judge a source's entries, and is built through
  `ModelConfig::new`.
- Every public error enum — `AclError`, `AllocError`, `ArchiveError`, `DirError`,
  `ExtentError`, `FeatureError`, `FormatError`, `GeometryError`, `ModelError`,
  `ParseError`, `ReadError` — is `#[non_exhaustive]`, as are `Category`,
  `FormatOptions`, and `ModelConfig`. These are the shapes that grow as the
  implementation learns to tell more failures apart and takes more knobs, so
  growing them no longer breaks a dependant. The closed domains are left
  exhaustive: `Severity` is an ordered scale a policy threshold is set over,
  `Profile` names a complete lineage, and `ErrorBehavior`, `FileType`, and
  `AclQualifier` are closed by the format or by POSIX.
- **Error variants that carried data in a tuple now carry named fields**, and every
  data-carrying variant is `#[non_exhaustive]`, so an error payload gains context as a
  patch. `ReadError::Io` and `DetectError::Io` additionally carry the
  `std::io::ErrorKind`, so a truncated image and an unreadable one can be told apart
  without matching on the message text.
- **`#[non_exhaustive]` on the types this crate produces and a caller only reads**:
  `Layout`, `GroupLayout`, `Anomaly`, `Location`, `Entry`, `WalkEntry`, `FsModel`,
  `ModelInode`, `DirChild`, `JournalSuperblock`, `DirBlock`, `ExtentTree`, `TreeShape`;
  the input-policy enums `GrowReservation`, `InodeCount`, `JournalSize`, and
  `HashVersion`, at the enum level only, so every variant stays constructible; and
  `SuperBlock`, `Inode`, and `GroupDescriptor`, whose Rust literal is now closed while
  their byte layout — `read_from`, `write_to`, `SIZE` — is untouched. Construction goes
  through `Default` (or `Inode::empty`) plus field assignment.
- **`FeatureSet` is `#[non_exhaustive]`.** The baseline constants and
  `with_feature(&str, bool)` are unchanged and remain the way a set is built; the new
  `EMPTY` and the two size builders cover what the attribute would otherwise have closed
  off.
- **The `ext` module names every re-export.** A glob made anything marked `pub` for one
  module's convenience into public API the moment it was written; each item's publicness
  is now a decision. The surface is unchanged by this — it is held to a committed
  snapshot that says so.
- **`format_to`'s memory contract is corrected.** The documented peak — one file's bytes
  at a time — did not match the code, which holds the entry list and every owned file's
  bytes for the whole run. The documentation states what is actually held and why, and
  `ArchiveSource::from_path` is what makes the smaller peak available.
- A scan's memory is bounded by the bytes the source holds rather than by what an
  image's inodes claim: a directory's block map is bounded by the blocks the image
  has, each of a directory's blocks is judged once however many logical offsets
  name it, and a report holds at most `ScanReport::MAX_ANOMALIES` findings.
- The hostile-name check walks a directory's blocks itself, so a directory holding
  a malformed record is still checked for a name carrying `/` or a NUL.
- The inode-bitmap checksum covers `(inodes_per_group + 7) / 8` bytes, as
  `ext4_inode_bitmap_csum_set` does, on both the writing and the reading side.
- `format` reports an image larger than the platform addresses as
  `FormatError::ImageTooLargeInMemory` instead of sizing its buffer from the low
  bits of the count. `format_to` streams an image of any size.
- A PAX timestamp carries a fraction larger than a second into the seconds, so a
  foreign inode's thirty-bit fraction renders as the instant it names.
- `ferrosys inspect` reports "at least *n* anomalies" when the scan stopped at its
  cap.

### Fixed

- `Reader::walk` is bounded. Distinct directory inodes may map the same data blocks, so
  a crafted image could describe an unbounded number of names from a handful of blocks.
  The walk is held to the number of names the source has room to hold — a bound no
  well-formed image reaches — and reaching it is `ReadError::WalkTooLarge` rather than a
  short list, because a caller extracting a tree from a truncated walk would write an
  incomplete one and see success.

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

[0.2.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.2.0
[0.1.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.1.0
