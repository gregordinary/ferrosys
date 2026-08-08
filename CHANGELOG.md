# Changelog

All notable changes to ferrosys are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is below `1.0`, the minor version is the breaking axis: a
breaking change bumps the minor, and the patch covers backward-compatible fixes.

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

[0.4.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.4.0
[0.3.1]: https://github.com/gregordinary/ferrosys/releases/tag/v0.3.1
[0.3.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.3.0
[0.2.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.2.0
[0.1.0]: https://github.com/gregordinary/ferrosys/releases/tag/v0.1.0
