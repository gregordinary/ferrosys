# Changelog

All notable changes to ferrosys are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is below `1.0`, the minor version is the breaking axis: a
breaking change bumps the minor, and the patch covers backward-compatible fixes.

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
  reserves 64 blocks and still grows to 512 GiB. An explicit `UpTo` target is an intent
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

[0.2.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.2.0
[0.1.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.1.0
