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

- **Feature-word coherence, both ways.** The formatter refuses a feature set that
  cannot describe what it would write, naming the conflict and the entry it is
  about: extended attributes without `ext_attr`, a regular file of 2 GiB or more
  without `large_file`, and `resize_inode` at a 4096-byte block without
  `large_file` — where the resize inode is itself a file that large. The reader
  reports the same disagreements in an image it did not write, as anomalies over
  `i_file_acl` without `ext_attr`, a large regular file without `large_file`, and
  a hash-indexed directory without `dir_index`.
- **`ArchiveSource::from_path`**, which opens a tar archive and leaves each member's
  bytes on disk until that file is placed. A format's peak memory becomes the largest
  single member rather than the sum of them all — for a rootfs archive, the difference
  between gigabytes and megabytes. It writes byte-identical images to `from_reader`,
  which is unchanged and still takes any stream. The archive must not be modified in
  place until the format finishes; the descriptor is held open, so replacing it by
  rename is safe.
- **`FileContent`** and **`FileRange`**, the contents of a regular source entry: owned
  bytes, or a range of a host file read at placement. Both coexist in one entry list, so
  a caller may take an archive-backed list and replace one entry's contents with bytes
  it computed. The length is known without reading, so the `large_file` check still
  names the offending path before any bytes are read.
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
  `LARGE_FILE_MIN_SIZE`, the size at which a regular file needs `large_file`.
- **`PlanRequest`**, the geometry planner's inputs as one value, with
  `FormatOptions::plan_request` deriving it from a format's options.
- **`OpenOptions`** and **`Limits`** for the reader: where the filesystem begins in the
  source, the policy to hold it to, caps on what one read may allocate, and a
  `metadata_csum` seed to verify against when an image's stored seed and UUID no longer
  agree. The limits default to imposing nothing, so an image of any size this crate
  wrote reads back whole at the default settings.
- **`CsumScheme`**, which names which checksums a filesystem carries and answers the two
  questions a caller has — whether metadata objects carry a checksum field, and whether
  the uninit block-group semantics apply — separately, because a third scheme the format
  defines answers them differently.
- **`JournalParams`**, the journal superblock's inputs as one value.
- `ScanReport::MAX_ANOMALIES` and `ScanReport::is_truncated`, with `truncated`
  in the JSON report, a closing line in the table, and a SARIF
  `toolExecutionNotifications` entry.
- **`SCAN_SCHEMA_VERSION`**, and a `schema` field at the head of the JSON a `ScanReport`
  renders. A downstream parser depends on the emitted shape and no Rust signature
  describes it, so the shape names its own version.
- **`HashVersion::name`** and a `Display` impl, so the on-disk name lives with the type
  rather than in each tool that prints it.
- **`MIN_DIRENT_LEN`**, the bound `Reader::walk` derives from the source's length.
- `ModelConfig::new`, which derives the block and inode sizes and the three
  feature answers from one `FeatureSet` — the derivation a caller would otherwise
  wire field by field, where a wrong answer judges a source against a filesystem
  the writer is not about to emit.

### Changed

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
- **`EntryKind::File`** carries a `FileContent` rather than a `Vec<u8>`.
  `TreeBuilder::file` accepts anything that converts into one, so a `Vec<u8>` still
  works unchanged.
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
