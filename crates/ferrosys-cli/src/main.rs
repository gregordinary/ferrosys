//! `ferrosys` — write, inspect, and read back ext2/3/4 filesystems, FAT12/16/32 volumes,
//! exFAT volumes, and btrfs filesystems.
//!
//! The binary is a shell around the `ferrosys` library: it parses a command line,
//! opens files, and renders results. Every decision about what a filesystem *is* belongs
//! to the library.
//!
//! # Every family, always
//!
//! The library is modular — a consumer that wants one filesystem compiles one — and this
//! binary is the deliberate exception: it compiles in every family the library has, so
//! someone running `detect` or `inspect` on an unknown image gets it identified whatever it
//! turns out to be. A family missing here would not be a smaller build; it would be a wrong
//! answer from a shipping command.
//!
//! # Exit codes
//!
//! The codes mirror `e2fsck`'s, and the line between 4 and 8 is whether an opinion about
//! a filesystem could be formed at all:
//!
//! - `0` — the command did what it was asked, and any filesystem it read is sound.
//! - `4` — a filesystem was read and it is bad.
//! - `8` — the command could not be carried out: the host got in the way, the bytes given
//!   are not a filesystem any compiled-in family reads, or an option named a concept the
//!   image's family does not have.
//! - `16` — the command line could not be understood.
//!
//! # Streams
//!
//! The standard output carries exactly one artifact per run: a report, a listing, a tar
//! stream, or one file's bytes. Everything else — progress, warnings, errors, the summary
//! a format prints — goes to the standard error, so the output of a run is always
//! something a pipe can consume whole. The output is flushed explicitly and the result
//! checked, so a closed or full pipe fails the run rather than truncating it in silence.
//!
//! # Determinism
//!
//! Everything an image's bytes depend on is an input the tool is given. A format's identity
//! is required — the UUID for ext, a volume serial number for FAT and for exFAT, and the
//! filesystem id for btrfs — its time is required for every family whose format records one
//! (or comes from `SOURCE_DATE_EPOCH`), and ext's hash seed defaults to the UUID's bytes. So
//! two runs given the same inputs write the same bytes, always.

// The tool inherits the library's bar: there is no `unsafe` here, ever.
#![forbid(unsafe_code)]

mod args;
mod dest;
mod detect;
mod extract;
mod format;
mod identity;
mod inspect;
mod json;
mod parse;
mod render;

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use ferrosys::{DetectError, OpenError, TreeError};
// The directory source `--from-dir` walks with, and the failures it reports, exist on the
// platform the library builds it for. Every other command and option is the same
// everywhere; `format::from_dir` is where the difference is confined.
use ferrosys::ArchiveError;
#[cfg(any(target_os = "linux", target_os = "android"))]
use ferrosys::HostError;
use ferrosys::ext::{FormatError, GeometryError, IdentityError, ReadError, Severity};

use crate::args::{Command, Topic, UsageError};

/// The exit codes, mirroring `e2fsck`'s.
pub mod exit {
    /// The command did what it was asked.
    pub const OK: u8 = 0;
    /// A filesystem was read, and it is bad.
    pub const IMAGE_BAD: u8 = 4;
    /// The command could not be carried out at all.
    pub const OPERATIONAL: u8 = 8;
    /// The command line could not be understood.
    pub const USAGE: u8 = 16;
}

/// A run that did not finish, and the exit code that reports it.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The command line could not be understood.
    #[error(transparent)]
    Usage(#[from] UsageError),
    /// A file could not be opened, read, or written.
    #[error("{what}: {source}")]
    Io {
        /// What was being read or written.
        what: String,
        /// The failure.
        #[source]
        source: io::Error,
    },
    /// The destination of a format is not a regular file.
    ///
    /// Formatting writes only the blocks the filesystem uses and extends the destination
    /// to its full size with a single byte at the end, so every byte it does not write
    /// must already read as zero. A freshly created or truncated regular file satisfies
    /// that; a block device does not, and formatting one would leave whatever it held
    /// interleaved with the new filesystem.
    #[error(
        "{0}: not a regular file — a format writes only the blocks the filesystem uses, \
         so every other byte of the destination must already read as zero"
    )]
    NotARegularFile(String),
    /// No compiled-in family recognized the image, so there is nothing to classify it as.
    #[error("{path}: {source}")]
    NotDetected {
        /// The file that was opened.
        path: String,
        /// What detection made of it.
        #[source]
        source: DetectError,
    },
    /// The bytes are not an ext filesystem: no superblock could be read from them, so
    /// there is nothing to have an opinion about.
    #[error("{path}: not an ext filesystem: {source}")]
    NotExt {
        /// The file that was opened.
        path: String,
        /// What the reader made of it.
        #[source]
        source: ReadError,
    },
    /// `identity` was pointed at a sound filesystem of another family.
    ///
    /// Its own verdict rather than a read failure: the volume is fine, and the command
    /// rewrites fields another family does not have — so the classification is the one
    /// every verb gives a request it cannot carry out, not "a filesystem was read and it
    /// is bad".
    #[error("{path}: holds {holds}, and identity rewrites the identity of an ext filesystem")]
    IdentityNotExt {
        /// The file that was opened.
        path: String,
        /// What the image holds, in the word `detect` prints for it.
        holds: &'static str,
    },
    /// The bytes are not a filesystem any compiled-in family reads, or a family recognized
    /// them and its reader then refused them.
    ///
    /// Distinct from [`NotExt`](Self::NotExt) in what it says: that one is one family's
    /// verdict, and this is every family's.
    #[error("{path}: {source}")]
    NotAFilesystem {
        /// The file that was opened.
        path: String,
        /// What opening it produced.
        #[source]
        source: OpenError,
    },
    /// An option naming a concept the image's family does not have.
    ///
    /// Reported rather than passed over. A run that asked for something and was handed a
    /// report silently missing it has been told the image holds none of that thing, which is
    /// a different claim from the question not applying to this family at all.
    #[error("{option} does not apply to a {family} filesystem: {reason}")]
    NotForFamily {
        /// The option as it was typed.
        option: &'static str,
        /// The family the image turned out to hold.
        family: &'static str,
        /// Why the two do not meet.
        reason: &'static str,
    },
    /// The library classified a family this build of the tool cannot work with.
    ///
    /// The binary compiles in every family the library has, so nothing in this workspace
    /// produces it; a newer library linked against an older tool would.
    #[error(
        "the image holds a filesystem this build of the tool does not handle — the library \
         recognized it and this command has nothing to do with it"
    )]
    UnsupportedFamily,
    /// Re-identifying an image failed.
    #[error("{path}: {source}")]
    Identity {
        /// The image that was being rewritten.
        path: String,
        /// What refused it.
        #[source]
        source: ferrosys::ext::IdentityError,
    },
    /// Writing an ext filesystem failed.
    #[error(transparent)]
    ExtFormat(#[from] FormatError),
    /// Writing a FAT volume failed.
    ///
    /// A variant of its own rather than one shared with the line above: what a format can
    /// refuse is the family's own list, and the two lists have almost nothing in common —
    /// one is journals and feature words and the other is cluster counts and properties a
    /// directory entry cannot hold.
    #[error(transparent)]
    FatFormat(#[from] ferrosys::fat::FormatError),
    /// Writing an exFAT volume failed.
    ///
    /// A third variant for the reason the second one is a variant: the two families lose the
    /// same properties and share the accounting for it, and there the resemblance stops. What
    /// each format can refuse is a list of its own — a FAT volume runs out of a 32-bit length
    /// field and an eleven-byte name, and an exFAT volume runs out of clusters.
    #[error(transparent)]
    ExFatFormat(#[from] ferrosys::exfat::FormatError),
    /// Writing a btrfs filesystem failed.
    ///
    /// A fourth variant for the reason the third one is a variant, and this family widens the
    /// point rather than repeating it: what a btrfs format can refuse is a geometry no chunk
    /// set fits in, a tree a leaf cannot hold, a record larger than a tree block, and a
    /// metadata reservation the trees outgrew — none of which any of the three above has a
    /// word for.
    #[error(transparent)]
    BtrfsFormat(#[from] ferrosys::btrfs::FormatError),
    /// The source archive could not be read.
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    /// The source directory tree could not be walked.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[error(transparent)]
    Host(#[from] HostError),
    /// `--from-dir` was given on a platform that has no directory source to walk with.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[error(
        "--from-dir is not available on this platform: walking a tree records Linux inode \
         metadata and Linux extended attributes, so the directory source is built on Linux \
         alone. --from-tar reads an archive anywhere"
    )]
    NoDirectorySource,
    /// `--to-dir` was given on a platform that has no directory sink to write with.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[error(
        "--to-dir is not available on this platform: writing a tree out sets Linux inode \
         metadata and Linux extended attributes, so the directory sink is built on Linux \
         alone. --to-tar writes the same contents as an archive anywhere"
    )]
    NoDirectorySink,
    /// The image could not be read as far as it had to be.
    #[error("reading the image: {0}")]
    ImageIo(String),
    /// A path the filesystem does not have.
    #[error("no such path in the filesystem: {}", String::from_utf8_lossy(.0))]
    NoSuchPath(Vec<u8>),
    /// A filesystem was read, and it is bad.
    #[error("the filesystem is malformed: {0}")]
    Image(#[source] ReadError),
    /// A filesystem was read through the extraction surface, and it is bad.
    ///
    /// The classification is the shared one: whether the bytes are wrong, whether the image
    /// uses something this build does not follow, or whether a caller's limit stopped the
    /// read. The family's own message rides along inside it.
    #[error("the filesystem is malformed: {0}")]
    Tree(#[source] TreeError),
    /// The scan found what the caller asked to be told about.
    #[error(
        "the filesystem holds {}{count} {}, the worst of them {}",
        if *truncated { "at least " } else { "" },
        if *count == 1 { "finding" } else { "findings" },
        worst.as_str()
    )]
    Verdict {
        /// How many findings the scan produced.
        count: usize,
        /// The severity of the most serious one.
        worst: Severity,
        /// Whether the scan stopped at its cap with the image unfinished, which makes the
        /// count and the severity a floor rather than the whole account.
        truncated: bool,
    },
    /// `--cat` named something that is not a regular file.
    #[error("{}: not a regular file", String::from_utf8_lossy(.0))]
    NotAFile(Vec<u8>),
}

impl Error {
    /// The option that resolves this failure, where one does.
    ///
    /// A geometry a filesystem cannot hold and a journal it has no room for are both
    /// failures of a *default* rather than of anything the caller typed, so the message
    /// alone leaves them with nothing to change. The hint names the option that decides the
    /// thing at fault. Every other failure names its own cause and gets none.
    fn hint(&self) -> Option<String> {
        match self {
            // The growth reservation is part of group 0's overhead, and on a small
            // filesystem it can be most of it. `--grow` is what decides it.
            Error::ExtFormat(FormatError::Geometry(GeometryError::TooSmall {
                reserved_gdt_blocks,
                ..
            })) if *reserved_gdt_blocks > 0 => Some(format!(
                "{reserved_gdt_blocks} of those blocks are growth headroom: `--grow none` \
                 reserves none, and `--grow SIZE` reserves only what growing to SIZE needs"
            )),
            // `orphan_file` is part of the default profile and requires a journal, so
            // `-O ^has_journal` on its own is refused at parse time. Both spellings here
            // are ones the tool accepts.
            Error::ExtFormat(FormatError::FilesystemTooSmallForJournal { minimum, .. }) => {
                Some(format!(
                    "a journal needs {minimum} blocks of its own: `-t ext2` builds a \
                     filesystem without one, as does `-O ^has_journal,^orphan_file`"
                ))
            }
            Error::ExtFormat(FormatError::JournalDoesNotFit { .. }) => Some(
                "`--journal N` sets the log's size in filesystem blocks, and `-t ext2` \
                 builds without one"
                    .to_string(),
            ),
            _ => None,
        }
    }

    /// The exit code this failure reports.
    fn exit_code(&self) -> u8 {
        match self {
            Error::Usage(_) => exit::USAGE,
            // A malformed filesystem is an opinion formed about one; everything else here
            // is a failure to form one at all.
            Error::Image(_) | Error::Verdict { .. } => exit::IMAGE_BAD,
            // The same line one level up: what the extraction surface says about the bytes
            // is a verdict about the filesystem, and what it says about reading them is not.
            Error::Tree(TreeError::Io { .. }) => exit::OPERATIONAL,
            Error::Tree(_) => exit::IMAGE_BAD,
            // Writing an archive out of an image reads that image, so some of what an
            // archive failure carries is a verdict about the filesystem: a structure that
            // cannot be read, and a stored ACL that does not decode, are the image's faults.
            // A socket, an unwritable attribute name, and a destination that cannot be
            // written are not — the filesystem is sound and the request cannot be carried
            // out.
            Error::Archive(ArchiveError::Read(e)) => match e {
                TreeError::Io { .. } => exit::OPERATIONAL,
                _ => exit::IMAGE_BAD,
            },
            Error::Archive(ArchiveError::Acl { .. }) => exit::IMAGE_BAD,
            // Re-identifying splits the same way. A superblock that does not check and a
            // backup copy that is not one are verdicts about the image; a UUID that would
            // invalidate the checksums, and a seed asked for where it does nothing, are
            // verdicts about the *request* — the filesystem is sound and the change cannot
            // be made — so they read as a command that could not be carried out.
            Error::Identity { source, .. } => match source {
                IdentityError::Read(ReadError::Io { .. }) | IdentityError::Io(_) => {
                    exit::OPERATIONAL
                }
                IdentityError::Read(_)
                | IdentityError::BackupNotASuperblock { .. }
                | IdentityError::SuperblockChecksumMismatch { .. } => exit::IMAGE_BAD,
                _ => exit::OPERATIONAL,
            },
            // Extraction to a host tree splits along the same line as extraction to an
            // archive, and it must split the same way: one image extracted two ways cannot
            // be a bad filesystem through `--to-tar` and an operational failure through
            // `--to-dir`. A structure that cannot be read is the image's fault, and so is a
            // name no well-formed filesystem holds — the library says as much where it
            // raises it. Everything else is the host refusing: no privilege, no room, a
            // destination that is not empty, an owner this platform cannot name.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Error::Host(HostError::Read { source, .. }) => match source {
                TreeError::Io { .. } => exit::OPERATIONAL,
                _ => exit::IMAGE_BAD,
            },
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Error::Host(HostError::HostileName { .. }) => exit::IMAGE_BAD,
            // A tree that cannot be walked and a platform with no walk to run are both
            // failures to carry the command out, so both land here; only one of them
            // exists in any one build.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Error::Host(_) => exit::OPERATIONAL,
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            Error::NoDirectorySource | Error::NoDirectorySink => exit::OPERATIONAL,
            Error::Io { .. }
            | Error::NotARegularFile(_)
            | Error::NotDetected { .. }
            | Error::NotExt { .. }
            | Error::IdentityNotExt { .. }
            | Error::NotAFilesystem { .. }
            | Error::NotForFamily { .. }
            | Error::UnsupportedFamily
            | Error::ExtFormat(_)
            | Error::FatFormat(_)
            | Error::ExFatFormat(_)
            | Error::BtrfsFormat(_)
            | Error::Archive(_)
            | Error::ImageIo(_)
            | Error::NoSuchPath(_)
            | Error::NotAFile(_) => exit::OPERATIONAL,
        }
    }

    /// An I/O failure against a named file.
    fn io(what: impl AsRef<Path>, source: io::Error) -> Self {
        Error::Io {
            what: what.as_ref().display().to_string(),
            source,
        }
    }
}

/// A read that failed after the filesystem opened.
///
/// The filesystem was there to be read, so a structural failure is the image's: it is
/// what a bad image looks like. A failure of the host's (the source could not be read) or
/// of the caller's (a path the filesystem does not have) is neither, and says nothing
/// about whether the filesystem is sound.
fn from_read(e: ReadError) -> Error {
    match e {
        ReadError::Io { message, .. } => Error::ImageIo(message),
        ReadError::NotFound { path, .. } | ReadError::NotADirectory { path, .. } => {
            Error::NoSuchPath(path)
        }
        other => Error::Image(other),
    }
}

/// The same, for a read of a FAT volume.
///
/// The line falls in the same place — the host, the caller, or the image — and the third case
/// goes through the shared classification rather than through a variant of its own, because
/// what this tool does with a malformed filesystem does not depend on which family it is.
fn from_fat_read(e: ferrosys::fat::ReadError) -> Error {
    use ferrosys::fat::ReadError as FatError;
    match e {
        FatError::Io { message, .. } => Error::ImageIo(message),
        FatError::NotFound { path, .. } | FatError::NotADirectory { path, .. } => {
            Error::NoSuchPath(path)
        }
        other => Error::from(TreeError::from(other)),
    }
}

/// The same again, for a read of an exFAT volume.
///
/// One of these per family rather than a generic over them, and the reason is the third arm: a
/// malformed ext filesystem reaches [`Error::Image`], which carries that family's own error,
/// where the others go through the shared `TreeError`. A function covering all of them would
/// take the split as a parameter, which is the whole of what each of these says.
fn from_exfat_read(e: ferrosys::exfat::ReadError) -> Error {
    use ferrosys::exfat::ReadError as ExFatError;
    match e {
        ExFatError::Io { message, .. } => Error::ImageIo(message),
        ExFatError::NotFound { path, .. } | ExFatError::NotADirectory { path, .. } => {
            Error::NoSuchPath(path)
        }
        other => Error::from(TreeError::from(other)),
    }
}

/// And for a read of a btrfs filesystem.
///
/// One arm more than its neighbours have, because this family resolves a path through symbolic
/// links and the others do not: a chain that does not end is a statement about the path that was
/// asked for rather than about the filesystem, so it reads as a path that names nothing rather
/// than as an image that is malformed.
fn from_btrfs_read(e: ferrosys::btrfs::ReadError) -> Error {
    use ferrosys::btrfs::ReadError as BtrfsError;
    match e {
        BtrfsError::Io { message, .. } => Error::ImageIo(message),
        BtrfsError::NotFound { path, .. }
        | BtrfsError::NotADirectory { path, .. }
        | BtrfsError::SymlinkLoop { path, .. } => Error::NoSuchPath(path),
        other => Error::from(TreeError::from(other)),
    }
}

/// A failure the extraction surface reported, as this tool classifies it.
///
/// Written as a conversion rather than a function because it is what lets a walk carry this
/// tool's own error type: `FsTree::walk_tree` takes any error a `TreeError` converts into, so
/// a visitor's failure and the filesystem's each reach the caller as themselves.
impl From<TreeError> for Error {
    fn from(e: TreeError) -> Self {
        match e {
            // The host could not read the source, which says nothing about whether the
            // filesystem is sound.
            TreeError::Io { message, .. } => Error::ImageIo(message),
            other => Error::Tree(other),
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    // The one environment value the tool honours, and the only input it does not take on
    // the command line. It supplies `format --time`; nothing else consults it.
    let source_date_epoch = std::env::var_os("SOURCE_DATE_EPOCH");

    match run(argv, source_date_epoch) {
        Ok(()) => ExitCode::from(exit::OK),
        Err(e) => {
            eprintln!("{}: {e}", args::TOOL);
            if let Some(hint) = e.hint() {
                eprintln!("hint: {hint}");
            }
            if matches!(e, Error::Usage(_)) {
                eprintln!("try `{} --help`", args::TOOL);
            }
            ExitCode::from(e.exit_code())
        }
    }
}

/// Parse the command line and carry out what it asked for.
fn run(argv: Vec<OsString>, source_date_epoch: Option<OsString>) -> Result<(), Error> {
    match args::parse(argv, source_date_epoch)? {
        Command::Format(a) => format::run(*a),
        Command::Inspect(a) => inspect::run(a),
        Command::Extract(a) => extract::run(a),
        Command::Detect(a) => detect::run(a),
        Command::Identity(a) => identity::run(a),
        // Help and the version are what the run was asked to produce, so they are the
        // artifact and go to the standard output.
        Command::Help(topic) => emit(help(topic).as_bytes()),
        Command::Version => {
            emit(format!("{} {}\n", args::TOOL, env!("CARGO_PKG_VERSION")).as_bytes())
        }
    }
}

/// Write the run's one artifact to the standard output, flushing it and checking the
/// result — so a closed or full pipe fails the run rather than truncating it in silence.
fn emit(bytes: &[u8]) -> Result<(), Error> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(bytes).map_err(stdout_failed)?;
    out.flush().map_err(stdout_failed)
}

/// The standard output could not be written or flushed.
fn stdout_failed(source: io::Error) -> Error {
    Error::Io {
        what: "standard output".to_string(),
        source,
    }
}

/// The usage text for one topic.
fn help(topic: Topic) -> &'static str {
    match topic {
        Topic::General => GENERAL_HELP,
        Topic::Format => FORMAT_HELP,
        Topic::Inspect => INSPECT_HELP,
        Topic::Extract => EXTRACT_HELP,
        Topic::Detect => DETECT_HELP,
        Topic::Identity => IDENTITY_HELP,
    }
}

const GENERAL_HELP: &str = "\
ferrosys — write, inspect, and read back ext2/3/4, FAT12/16/32, exFAT, and btrfs
filesystems

usage:
  ferrosys format  [options] OUT.img    write a filesystem
  ferrosys inspect [options] IMAGE      report on a filesystem
  ferrosys extract [options] IMAGE      read a filesystem's contents back out
  ferrosys detect  [options] IMAGE      say which filesystem an image holds
  ferrosys identity [options] IMAGE     change what a filesystem is known by

  ferrosys <command> --help             the options one command takes
  ferrosys --version                    the version

filesystems:
  ext2, ext3, ext4      formatted, inspected, and read back
  fat12, fat16, fat32   the same
  exfat                 the same. One word rather than three: the format has one revision
                        and every volume records it, so the family is the finest answer
                        there is
  btrfs                 the same, and one word for a different reason: what varies between
                        two btrfs filesystems is a feature word and a geometry, which are
                        options rather than a variant to name. `format -t` selects which;
                        every command identifies whichever family an image turns out to
                        hold

exit codes (as e2fsck's):
  0   the command did what it was asked
  4   a filesystem was read and it is bad
  8   the command could not be carried out
  16  the command line could not be understood

The standard output carries exactly one artifact per run — a report, a listing, a tar
stream, or one file's bytes. Everything else goes to the standard error.

The tool reads neither the clock nor a random source, so a format's output is a function
of its inputs alone: the same inputs write the same bytes.
";

const FORMAT_HELP: &str = "\
ferrosys format — write an ext2/3/4 filesystem, a FAT12/16/32 volume, an exFAT volume, or
a btrfs filesystem

usage:
  ferrosys format --size SIZE --uuid HEX --time SECS [options] OUT.img
  ferrosys format -t fat32 --size SIZE --volume-id HEX --time SECS [options] OUT.img
  ferrosys format -t exfat --size SIZE --volume-serial HEX [options] OUT.img
  ferrosys format -t btrfs --size SIZE --fsid HEX --time SECS [options] OUT.img

  ferrosys format --size 512M --uuid \"$(uuidgen)\" --time \"$(date +%s)\" rootfs.img

  ferrosys format --size auto --slack 20% --from-dir staging \\
    --uuid \"$(uuidgen)\" --time \"$(date +%s)\" rootfs.img

  ferrosys format -t fat32 --size 512M --volume-id 1A2B-3C4D --label ESP \\
    --time \"$(date +%s)\" --owner 0:0 --accept-loss change-time,time-precision \\
    --from-dir esp-staging esp.img

  ferrosys format -t btrfs --size 8G --fsid \"$(uuidgen)\" --time \"$(date +%s)\" \\
    --subvol \"$(uuidgen):/@\" --subvol \"$(uuidgen):/@home\" --default-subvol /@ \\
    --owner 0:0 --from-dir staging root.img

-t names the filesystem, and each family takes its own identity and its own options; an
option of a family that was not named is refused by name rather than passed over. Naming
no type writes ext4.

An identity is required — and --time with it, for every family whose format records an
instant — because an image's bytes are a function of its inputs alone: the tool reads
neither the clock nor a random source, so the same inputs write the same bytes.
SOURCE_DATE_EPOCH supplies --time when it is set.

required:
  --size SIZE|auto     the filesystem's size: a byte count, optionally suffixed K, M, G,
                       or T — or `auto`, which sizes the filesystem to what goes in it.
                       `auto` finds the smallest filesystem that holds the contents by
                       planning candidate sizes and placing the contents into each, so
                       the size it settles on is one that formats, and one allocation
                       unit less does not. Use --slack to leave room in it
  --uuid HEX           (ext) the filesystem UUID, dashed or bare (32 hex digits). The tool
                       mints none: pipe in `uuidgen`, of whatever version you like
  --volume-id HEX      (fat) the volume serial number, 8 hex digits, dashed or bare —
                       1A2B-3C4D or 1A2B3C4D. This family's identity field, as the UUID is
                       ext's; it is 32 bits, so it is named rather than cut from a UUID
  --volume-serial HEX  (exfat) the same width and a different field of a different format,
                       so a flag of its own: an exFAT volume records a VolumeSerialNumber
                       in both of its boot regions, inside the checksum over each
  --fsid HEX           (btrfs) the filesystem's own id, dashed or bare (32 hex digits) —
                       what `blkid` reports and what a `UUID=` mount names. The same width
                       as ext's and a different field of a different format, so a flag of
                       its own; a btrfs records four more identifiers beside it, under
                       `identity (btrfs)` below
  --time SECS          (ext, fat, btrfs) the filesystem's creation time, in seconds since
                       the epoch. Taken from SOURCE_DATE_EPOCH when the option is absent.
                       A FAT directory entry represents 1980-01-01 through 2107-12-31 at a
                       two-second granularity, so a time outside that is refused for one
                       rather than truncated into a plausible-looking one. An exFAT volume
                       records no time of its own, so for that family the flag is refused
                       rather than accepted and ignored

contents (at most one):
  --from-tar FILE|-    populate the filesystem from a tar archive. A named FILE is left on
                       disk and each member read as its file is placed, so peak memory is
                       the largest single member; `-` reads the standard input, which
                       cannot be sought back over and so is held whole. The archive must
                       be uncompressed — decompress it into `-` with `gunzip -c f.tar.gz |
                       ferrosys format ... --from-tar -`
  --from-dir DIR       populate the filesystem from a directory tree on this machine. DIR
                       itself becomes the filesystem root. An ext filesystem carries all of
                       it: modes, ownership, all three times, symlinks, hard links, device
                       and FIFO nodes, sockets, and extended attributes with their POSIX
                       ACLs; symlinks are recorded, never followed. A FAT volume has a field
                       for almost none of it, and --accept-loss is what says which of them
                       may go. Each file is read as it is placed, so
                       peak memory is the largest single file. Walking a tree records Linux
                       inode metadata and Linux extended attributes, so this option is
                       carried out on Linux alone; --from-tar reads an archive anywhere
  --owner UID:GID      own every entry of a --from-dir tree by this user and group,
                       whatever the host files say. A build that does not run as root
                       usually wants --owner 0:0: without it the image is owned by the
                       user that built it

labelling:
  --label NAME         the volume label: up to 16 bytes on ext, 11 upper-cased bytes of
                       the OEM character set on a FAT, up to 11 UTF-16 code units on an
                       exFAT volume — which is 11 characters rather than 11 bytes for
                       anything outside ASCII, and must be text for the same reason — and
                       up to 255 bytes on a btrfs, which records no encoding for them and
                       so takes them as they come. A label the field cannot hold is refused
                       rather than truncated

filesystem:
  -t, --type ext2|ext3|ext4|fat12|fat16|fat32|exfat|btrfs
                       which filesystem to write (default ext4). For ext it is also the
                       base feature set: -O and the geometry options layer on top, so
                       `-t ext2 -O has_journal` is ext3, and the image is judged by the
                       features it carries rather than the profile it started from. For a
                       FAT it is what the cluster count must derive to — nothing in a FAT
                       volume records its type, so a size that cannot reach the named one
                       is refused rather than written as something else. exFAT names no
                       variant, and takes the size it is given: --size auto is refused for
                       it, because the search behind `auto` is a family's own and this one
                       has none. btrfs names no variant either and has no search either,
                       and what would have been a variant is `geometry (btrfs)` below

identity (btrfs):
  A btrfs records five identifiers where the other three record one, and a filesystem whose
  bytes you can reproduce is one that states all of them. Only --fsid is required; the rest
  are zero unless named, which is a legitimate value and an obviously unset one. Nothing
  here is derived from anything else: a value this tool invented would be a value you could
  not state.

  --metadata-uuid HEX  the id every tree block is stamped with, where it is to differ from
                       --fsid. Setting it is what lets the id a person sees be changed
                       later without rewriting every block, and the filesystem records that
                       state as a feature bit. Unset, the two ids are one
  --chunk-tree-uuid HEX   the chunk tree's own id, repeated in every tree block and every
                       device extent, so that a block belonging to another filesystem says
                       so
  --device-uuid HEX    the device's own id, which the device record and every copy of every
                       chunk name
  --subvolume-uuid HEX the top-level subvolume's own id, which the UUID tree is keyed by

subvolumes (btrfs):
  --subvol [ro:]UUID:PATH
                       make the source directory at PATH the root of a subvolume of its
                       own. Repeatable, and each needs its own UUID — the UUID tree is
                       keyed by it, so two subvolumes sharing one would make a tree with a
                       repeated key. `ro:` in front makes it read-only. The identifier
                       leads and the path is everything after it, so a path may hold a
                       colon. A subvolume root is still a directory: this says how to lay
                       it out, not what it is, so the same source tree feeds every family
                       unchanged
  --default-subvol PATH   which subvolume a mount that was told none lands on, named by
                       the path it was asked for. Without it, a mount lands on the
                       top-level tree every btrfs starts with, which is what `subvolid=5`
                       names

fidelity (fat, exfat):
  --accept-loss LIST   which properties of the source this build may lose: `all`, or a
                       comma-separated list of ownership, permissions, special-bits, kind,
                       extended-attributes, access-time, change-time, modification-time,
                       time-precision, name. Without it a build that would lose anything
                       fails and names the entry and the property.

                       Neither format has a field for an owner, a group, permission bits, a
                       symbolic link, a second name for a file, a device number, or an
                       extended attribute — but a property counts as lost only when the
                       value does not survive, so a root-owned tree of 0644 files and 0755
                       directories loses nothing by those. A tree walked off this host
                       always loses change-time, which neither format has a field for.

                       Where the two differ is how much time survives, and both lose some.
                       A FAT volume stores a write time to two seconds and an access time to
                       the day. exFAT keeps a creation and a modification time to ten
                       milliseconds, and each of its three times with a zone offset, but its
                       access time is two-second granular like FAT's — so a host tree loses
                       time-precision on either format, and loses far less of it here.

                       Properties are named one by one on purpose: accepting the loss of
                       permission bits must not silently accept every symbolic link in the
                       tree disappearing. `all` is the deliberate exception
  --assume-owner U:G   the owner a read of this image will report, which is the point a
                       loss is measured against. Defaults to 0:0
  --assume-modes F:D   the modes a read will report, for a file and for a directory, in
                       octal. Defaults to 644:755. Set these to whatever the extraction
                       will use, so the two ends agree about what survived

  --slack PCT%|SIZE    with --size auto, how much of the filesystem must still be free
                       once the contents are written: `20%` of it, or `64M` of it. Without
                       this, `auto` leaves nothing — the right answer for an image that
                       will only be read, and useless for one that will be written to.
                       The share is of the finished filesystem, so `--slack 20%` is what
                       `df` reports as 80% used. Up to 90%

geometry (ext):
  --block-size N       1024, 2048, or 4096 (the default)
  --inode-size N       a power of two from 128 up to the block size (default 256)
  --inodes N           the inode count, rounded up to fill each group's tables. Overrides
                       the size-driven default
  --bytes-per-inode N  one inode per N bytes of filesystem — the density the count is
                       derived from. This and --inodes share one setting; the last wins
  --reserved-percent P blocks held back for the super-user, from 0 to 50, with up to two
                       decimal places (default 5)
  -O feat,^feat,none   turn features on and off, left to right, over the selected profile.
                       `none` clears every feature. The names are ext's own on-disk ones:
                       64bit, metadata_csum, has_journal, … . filetype names the directory
                       format this tool always writes, so clearing it is refused. Clearing
                       extent drops to the block-mapped ext2/ext3 family, which then carries
                       none of the ext4-layer features (flex_bg, 64bit, metadata_csum, …);
                       -t is the direct way to that base
  --grow none|max|SIZE reserved descriptor blocks, which are what let the filesystem grow
                       online without relocating its descriptor table. They are empty
                       blocks held at the front of the filesystem and cost free space 1:1,
                       and a filesystem that will not grow has no use for them:
                         none   reserve nothing. The smallest image, and still growable
                                offline by an unmounted `resize2fs`
                         SIZE   reserve exactly what growing online to SIZE needs — 3
                                blocks for 32G, 127 for 1T. The precise answer when the
                                largest device the image will be written to is known
                         max    (default) as much as the format allows without spending
                                more than 1/64 of the filesystem on it: the full ~8 TiB
                                reach from 256M up, and a proportional share below that,
                                so a 16M image reserves 64 blocks and still grows to 512G
                       The format summary reports what was reserved and what is left free
  --journal auto|N     the journal's size in filesystem blocks (default: sized from the
                       filesystem). The journal is a real file and costs its size in free
                       space — 4 MiB of a 16 MiB filesystem — so `-t ext2` is the way to
                       build a small filesystem without one
  --errors continue|remount-ro|panic   what the kernel does on a detected filesystem
                       error (`s_errors`): note it and carry on, remount read-only, or
                       panic. Defaults to `continue`, the kernel's own default

geometry (btrfs):
  --sector-size N|auto the smallest addressable unit of file data: a power of two from 4K
                       to 64K, or `auto` (the default), which is 4096. Named rather than
                       taken from this machine's page size, which is what the format's own
                       tooling does and what makes one command line write two different
                       filesystems on two machines
  --node-size N|auto   the size of a tree block: a power of two from the sector size to
                       64K, or `auto` (the default), which is 16K or the sector size where
                       that is larger. It decides how much a leaf holds, and so how large
                       a file may be before it stops fitting inside the metadata
  --metadata-profile single|dup
                       how metadata and system block groups are replicated (default dup).
                       `dup` writes two copies on the one device, which is what protects
                       the trees against a bad sector; `single` writes one and costs half
                       as much space
  --data-profile single|dup
                       the same for data block groups (default single)
  -O feat,^feat,none   turn features on and off, left to right, over what this tool writes
                       when you name none. `none` clears every feature. The names are the
                       ones the format's own tooling takes and `inspect` prints:
                       skinny-metadata, no-holes, extref, free-space-tree,
                       block-group-tree, … . The one most worth naming is
                       `^block-group-tree`, which is how you write a filesystem a kernel
                       older than 6.1 can mount. A feature this tool does not write is
                       refused by name, and so is one whose prerequisites were not asked
                       for — block-group-tree rests on free-space-tree and no-holes, so
                       clearing either of those means clearing it in the same list

determinism (ext):
  --fixed-time SECS    force every inode's times to this value, whatever the source says
  --hash half_md4|tea|legacy       the directory-hash algorithm (default half_md4)
  --hash-signedness signed|unsigned  how a name's bytes are read when hashed. Unsigned by
                       default, which makes the bytes independent of the host
  --hash-seed HEX      the 16-byte directory-hash seed. Defaults to the UUID's bytes

output:
  --json               print the geometry the format realized, as JSON, on the standard
                       output. Without it, a summary goes to the standard error
  --dry-run            report the geometry this command would realize and write nothing.
                       The destination is not opened, created, or truncated — so there is
                       nothing for --atomic to decide, and the two cannot pair

destination:
  --atomic             write the image to a sibling temporary file and rename it over the
                       destination once it is complete, so the destination holds either the
                       image that was there before or the whole new one — never a partial
                       one. Note that it becomes a new file: its mode comes from this
                       process's umask, and any ownership, ACLs, or extra hard links the
                       old file had do not survive. Without it the image is written in
                       place, and a failure part-way through leaves a partial image

The destination must be a regular file. A format writes only the blocks the filesystem
uses, so every byte it does not write must already read as zero — which a block device
does not guarantee, and which is why the file is created or truncated as part of
formatting. That happens only once the archive has parsed and the geometry has planned, so
a run that fails for any other reason leaves the file that was there untouched.
";

const INSPECT_HELP: &str = "\
ferrosys inspect — report on a filesystem

usage:
  ferrosys inspect [options] IMAGE

The image is classified first and then described by whichever family claimed it, so a
report is a family-tagged envelope: a head that means the same thing whatever the image
holds — the family, the variant, the size, the allocation unit, the identifier, and what a
scan found — then a body that is entirely that family's own.

options:
  --offset N           where the filesystem begins within the file, for a partition
                       inside a whole-disk image. A byte count, optionally suffixed K, M,
                       G, or T
  --json               report as JSON rather than as text
  --sarif              report the scan's findings as a SARIF 2.1.0 log, for a static-
                       analysis or forensic pipeline; reports findings alone, not the
                       superblock description, so it needs the scan and cannot pair with
                       --quick
  --groups             (ext) report every block group's descriptor as well. A block group
                       is how an ext filesystem divides itself; a FAT volume has one flat
                       cluster heap, so the option is refused for one rather than passed
                       over
  --quick              report the superblock alone, without scanning the image. There is
                       then no scan for a verdict to read, so it cannot pair with --fail-on
  --fail-on SEVERITY|never
                       the severity at which the scan's findings make the filesystem bad:
                       cosmetic, conformance, integrity (the default), structural, or
                       never. `integrity` faults a filesystem whose own bytes contradict
                       each other; `conformance` also faults one that is valid for its
                       format but not the form this tool writes, which is a check on this
                       tool's own output rather than on the format

The whole image is scanned unless --quick says otherwise, so an image that is bad is
reported as bad (exit 4) rather than merely described. What counts as bad is --fail-on,
which defaults to `integrity`: a filesystem whose own bytes contradict each other fails,
and a valid filesystem that another tool wrote does not. That is the default a CI gate
inherits, and `--fail-on conformance` is the stricter line to draw deliberately.

The four severities mean the same thing for every family; the categories a finding falls
into are each family's own, since a superblock and a boot sector are not the same subsystem
under two names.
";

const EXTRACT_HELP: &str = "\
ferrosys extract — read a filesystem's contents back out

usage:
  ferrosys extract [--offset N] IMAGE --to-tar FILE|-
  ferrosys extract [--offset N] IMAGE --to-dir DIR
  ferrosys extract [--offset N] IMAGE --cat PATH
  ferrosys extract [--offset N] IMAGE --stat PATH [--json]
  ferrosys extract [--offset N] IMAGE --list [--json]

exactly one of:
  --to-tar FILE|-      write the whole tree as a tar archive; `-` writes the standard
                       output. Ownership, modes, times (to the nanosecond), symlinks,
                       hard links, device and FIFO nodes, extended attributes, and POSIX
                       ACLs all survive, carried in PAX records
  --to-dir DIR         write the whole tree into a directory on this host, the inverse of
                       `format --from-dir`. DIR is made if it is not there and must be
                       empty. Everything the archive carries is carried here too, set on
                       the files themselves; DIR takes the filesystem root's own mode,
                       ownership, times, and attributes, and `/lost+found` is not written.
                       A device node needs CAP_MKNOD and a recorded owner needs CAP_CHOWN,
                       so an unprivileged run stops at the first of either unless
                       --skip-privileged is given. Two things no host lets a caller set:
                       an inode's change time and its creation time, so the tree carries
                       the times it was written for those two alone
  --cat PATH           write one file's bytes to the standard output, and nothing else.
                       PATH is a path inside the image, taken as the bytes you typed
  --stat PATH          report everything the filesystem records about one path: its type,
                       mode (octal and symbolic), ownership, size, times, and — where the
                       family records them — its inode number, link count, a device node's
                       numbers, a symlink's target, and its extended attributes with any
                       POSIX ACL decoded. A path naming a symlink describes the link, not
                       its target; --json reports it as JSON
  --list               list the tree; --json lists it as JSON, with each entry's extended
                       attributes and decoded ACLs

options:
  --offset N           where the filesystem begins within the file
  --max-file-bytes N   refuse to read a file larger than N bytes. A file's size is the
                       image's own claim, and a sparse file legitimately dwarfs the
                       filesystem holding it, so nothing structural bounds it: an inode
                       claiming sixteen tebibytes and mapping nothing costs an extraction
                       sixteen tebibytes of zeros from an image of a hundred kilobytes.
                       Defaults to sixteen times the length of the filesystem being read,
                       which no ordinary file approaches; name a size to read one that is
                       legitimately sparser than that. Over the cap the read is an error
                       rather than a short file
  --skip-privileged    with --to-dir, write what this process may rather than failing on
                       what it may not: a device node it cannot create is left out, the
                       tree is owned by this process, and a security or trusted extended
                       attribute it may not set is not set. What was left out is named on
                       the standard error, so an incomplete tree says so
  --atomic             with --to-tar FILE, write the archive to a sibling temporary file
                       and rename it over FILE once the walk is complete, so a walk that
                       fails part-way leaves whatever was at FILE untouched. --to-dir has
                       no equivalent — no rename publishes a whole tree at once — which is
                       why its destination must start empty
  --strict             refuse an image the reader cannot hold to its format, rather than
                       interpreting it best-effort. Extraction writes what it read
                       somewhere, so a filesystem carrying a deviation this reader does not
                       follow produces output that looks complete and is not. Without this
                       the read falls back to a lenient one — which is what makes a damaged
                       or unfamiliar image recoverable at all — and names on the standard
                       error the deviation it decided to interpret through
  --assume-owner U:G   the owner to record where the filesystem records none. Defaults to
                       0:0. An ext filesystem records ownership on every entry, so this
                       changes nothing about one; it is the answer for a FAT volume, which
                       has no field for an owner, where something must be assumed before a
                       host file can be created
  --assume-modes F:D   the permission modes to assume, in octal, for a file and for a
                       directory, where the filesystem records none. Defaults to 644:755.
                       Conservative on purpose: a tree extracted from a format with no
                       permission bits must not land world-writable because nothing was
                       named. What was assumed is reported on the standard error

Reading holds no whole file: --cat streams to the standard output and --to-tar streams each
member into the archive, so a multi-gigabyte file costs a working set rather than its size.

The archive holds a `./` member for the root and skips `/lost+found`, so what comes out
is what `ferrosys format --from-tar` reads back in; --to-dir writes the tree the same way,
so `format --from-dir` reads that one back.

A JSON mode's `mode` field is the permission bits as a decimal number, since JSON has no
octal literal — 509 is 0o775 — and `mode_octal` beside it carries the usual spelling.

Every entry carries a `synthesized` list naming the properties the report filled in rather
than read, in the same words `format --accept-loss` takes — so a property a listing shows
can be typed straight back into a build. A field the family has no notion of at all is
absent instead: a FAT entry carries no `inode` and no `links`, because a zero or a one
there would be this tool answering a question the format never asked.
";

const DETECT_HELP: &str = "\
ferrosys detect — say which filesystem an image holds

usage:
  ferrosys detect [--offset N] [--json] IMAGE

options:
  --offset N           where the filesystem begins within the file, for a partition inside
                       a whole-disk image or a region a carver located. A byte count,
                       optionally suffixed K, M, G, or T
  --json               report as JSON rather than as one word

The answer is one word on the standard output — ext2, ext3, ext4, fat12, fat16, fat32,
exfat, btrfs, or `unrecognized` — so it reads well in a shell test. It is the same word
`format -t` takes.
An unrecognized image exits 8, since there is no filesystem to have an opinion about. One
further word, `unknown`, is the answer when the library classifies a family this build has
no name for: something recognized the image, so calling it unrecognized would be wrong.

This asks what an image *is*, not whether it is sound: an image with a quirk `inspect` would
refuse still classifies here. Use `inspect` to be told whether a filesystem is well-formed.
";

const IDENTITY_HELP: &str = "\
ferrosys identity — change what an existing ext filesystem is known by

usage:
  ferrosys identity [--uuid HEX] [--label TEXT] [--set-checksum-seed] [--json] IMAGE

options:
  --offset N           where the filesystem begins within the file, for a partition inside
                       a whole-disk image. A byte count, optionally suffixed K, M, G, or T
  --uuid HEX           the new filesystem UUID: 32 hex digits, dashed or bare
  --label TEXT         the new volume label, at most 16 bytes
  --set-checksum-seed  record the seed the current UUID implies and set
                       metadata_csum_seed, so the UUID can change without invalidating the
                       filesystem's metadata checksums
  --json               report what was written as JSON rather than as text

At least one of --uuid, --label, and --set-checksum-seed is required: a run that would
write nothing is a command line that meant to say something.

Every superblock copy is rewritten — the primary and each group's backup — along with the
journal's own record of the UUID, so no copy is left claiming the old identity. Each copy
is patched in place: it keeps every field this change does not name.

Nothing is written until every copy has been read and every check has passed, so a refusal
leaves the image exactly as it was. There is no --atomic: an image is rewritten where it
lies, and a temporary copy would mean writing every byte of it to change sixteen.

A filesystem with metadata_csum and without metadata_csum_seed seeds every checksum it
holds from the UUID itself, so changing the UUID would invalidate all of them at once.
That is refused, and --set-checksum-seed is the way through: it records the seed the
current UUID implies, after which the UUID moves and every existing checksum stays valid.
It sets an incompatible feature, so a kernel that does not know metadata_csum_seed will
not mount the result — which is why it is asked for rather than assumed.
";

#[cfg(test)]
mod tests {
    use super::*;
    use ferrosys::ext::{FormatOptions, Reader, Timestamp, TreeBuilder};

    #[test]
    fn every_failure_names_the_exit_code_it_reports() {
        // The line between 4 and 8: a filesystem was read and found bad, versus no
        // filesystem was read at all.
        assert_eq!(Error::Usage(UsageError::NoCommand).exit_code(), exit::USAGE);
        assert_eq!(
            Error::Image(ReadError::BadDirectory).exit_code(),
            exit::IMAGE_BAD
        );
        assert_eq!(
            Error::Verdict {
                count: 1,
                worst: Severity::Structural,
                truncated: false,
            }
            .exit_code(),
            exit::IMAGE_BAD
        );
        // A report that stopped at its cap says the count is a floor, so the verdict a
        // person reads does not claim to have counted the whole image.
        assert_eq!(
            Error::Verdict {
                count: 10_000,
                worst: Severity::Structural,
                truncated: true,
            }
            .to_string(),
            "the filesystem holds at least 10000 findings, the worst of them structural"
        );
        // One finding is singular: the verdict is a line a person reads.
        assert_eq!(
            Error::Verdict {
                count: 1,
                worst: Severity::Integrity,
                truncated: false,
            }
            .to_string(),
            "the filesystem holds 1 finding, the worst of them integrity"
        );
        assert_eq!(
            Error::NotExt {
                path: "blob".into(),
                source: ReadError::BadJournal
            }
            .exit_code(),
            exit::OPERATIONAL
        );
        assert_eq!(
            Error::NoSuchPath(b"/nowhere".to_vec()).exit_code(),
            exit::OPERATIONAL
        );
    }

    #[test]
    fn a_read_failure_is_the_image_s_only_when_it_is_about_the_image() {
        // A structural failure is what a bad image looks like. Every structural variant
        // takes the same arm, so one of them stands for all.
        assert_eq!(
            from_read(ReadError::BadDirectory).exit_code(),
            exit::IMAGE_BAD
        );
        // ...while the host failing to read, or a path the filesystem does not have, says
        // nothing at all about whether the filesystem is sound. Both are taken from the
        // library rather than assembled here: a literal would prove only that this match
        // arm is spelled the way this test spells it, where a real failure proves the
        // library still reports the variant the arm is for.
        let host_failed = ReadError::from(std::io::Error::other("disk on fire"));
        assert_eq!(from_read(host_failed).exit_code(), exit::OPERATIONAL);

        let time = Timestamp::from_secs(1_700_000_000);
        let image = ferrosys::ext::format(
            TreeBuilder::new(),
            64 << 20,
            FormatOptions::new([0x11; 16], time, [0; 16]),
        )
        .expect("format a minimal image");
        let mut reader =
            Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open the image");
        let absent = reader
            .lookup(b"/nowhere")
            .expect_err("the image has no such path");
        assert_eq!(from_read(absent).exit_code(), exit::OPERATIONAL);
    }

    #[test]
    fn every_help_topic_has_text() {
        for topic in TOPICS {
            let text = help(topic);
            assert!(text.starts_with("ferrosys"), "{topic:?} names the tool");
            assert!(text.contains("usage:"), "{topic:?} states its usage");
        }
        // The help is public prose describing the tool's own surface: the general topic
        // lists every subcommand a user can run, and each subcommand's help names the
        // command it documents. Asserting what the help *is* keeps it honest without
        // naming anything it must not.
        let general = help(Topic::General);
        for (command, topic) in SUBCOMMANDS {
            assert!(
                general.contains(command),
                "the general help lists the `{command}` command"
            );
            assert!(
                help(topic).contains(command),
                "the `{command}` help names its own command"
            );
        }
    }

    /// Every topic there is, and every one that documents a subcommand.
    ///
    /// Held as a `match` over a topic rather than as a hand-written list, because a hand
    /// written list is what let the one topic nothing else reads go unchecked: a topic added
    /// to the enum fails to compile here until it is named in both.
    const TOPICS: [Topic; 6] = [
        Topic::General,
        Topic::Format,
        Topic::Inspect,
        Topic::Extract,
        Topic::Detect,
        Topic::Identity,
    ];

    /// The subcommands a user types, beside the topic that documents each.
    const SUBCOMMANDS: [(&str, Topic); 5] = [
        ("format", Topic::Format),
        ("inspect", Topic::Inspect),
        ("extract", Topic::Extract),
        ("detect", Topic::Detect),
        ("identity", Topic::Identity),
    ];

    #[test]
    fn the_topic_list_above_is_every_topic_the_enum_has() {
        // What makes the two lists complete rather than merely long: the `match` is
        // exhaustive, so a seventh topic stops the build here, and the count is asserted, so
        // a topic dropped from the list stops it too. Nothing under `help` can go unread.
        for topic in TOPICS {
            let named = match topic {
                Topic::General => "general",
                Topic::Format => "format",
                Topic::Inspect => "inspect",
                Topic::Extract => "extract",
                Topic::Detect => "detect",
                Topic::Identity => "identity",
            };
            assert!(!named.is_empty());
        }
        // And every topic but the general one documents a subcommand a user can type.
        assert_eq!(SUBCOMMANDS.len(), TOPICS.len() - 1);
    }
}
