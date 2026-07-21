//! `ferrosys` — write, inspect, and read back ext2/3/4 filesystems.
//!
//! The binary is a shell around the `ferrosys` library: it parses a command line,
//! opens files, and renders results. Every decision about what an ext filesystem *is*
//! belongs to the library.
//!
//! # Exit codes
//!
//! The codes mirror `e2fsck`'s, and the line between 4 and 8 is whether an opinion about
//! a filesystem could be formed at all:
//!
//! - `0` — the command did what it was asked, and any filesystem it read is sound.
//! - `4` — a filesystem was read and it is bad.
//! - `8` — the command could not be carried out: the host got in the way, or the bytes
//!   given are not an ext filesystem, so there is no filesystem to have an opinion
//!   about.
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
//! The tool reads neither the clock nor a random source. A format's UUID is required, its
//! time is required (or comes from `SOURCE_DATE_EPOCH`), and its hash seed defaults to
//! the UUID's bytes — so two runs given the same inputs write the same bytes, always.

// The tool inherits the library's bar: there is no `unsafe` here, ever.
#![forbid(unsafe_code)]

mod args;
mod extract;
mod format;
mod inspect;
mod json;
mod parse;
mod render;

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use ferrosys::ext::{AclError, ArchiveError, FormatError, ReadError, Severity};

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
    /// Writing the filesystem failed.
    #[error(transparent)]
    Format(#[from] FormatError),
    /// The source archive could not be read.
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    /// The image could not be read as far as it had to be.
    #[error("reading the image: {0}")]
    ImageIo(String),
    /// A path the filesystem does not have.
    #[error("no such path in the filesystem: {}", String::from_utf8_lossy(.0))]
    NoSuchPath(Vec<u8>),
    /// A filesystem was read, and it is bad.
    #[error("the filesystem is malformed: {0}")]
    Image(#[source] ReadError),
    /// An entry's stored POSIX ACL is not one: the bytes are in the attribute an ACL
    /// lives in, and they do not decode as an ACL, so there is nothing to write out.
    #[error("{}: its stored ACL is malformed: {source}", String::from_utf8_lossy(.path))]
    BadAcl {
        /// The entry carrying it.
        path: Vec<u8>,
        /// What was wrong with the bytes.
        #[source]
        source: AclError,
    },
    /// The scan found what the caller asked to be told about.
    #[error("the filesystem holds {count} anomalies, the worst of them {}", worst.as_str())]
    Verdict {
        /// How many anomalies the scan found.
        count: usize,
        /// The severity of the most serious one.
        worst: Severity,
    },
    /// An entry a tar archive has no way to hold.
    #[error(
        "{}: a socket, which a tar archive has no entry type for — extracting it would \
         drop it silently",
        String::from_utf8_lossy(.0)
    )]
    Unrepresentable(Vec<u8>),
    /// `--cat` named something that is not a regular file.
    #[error("{}: not a regular file", String::from_utf8_lossy(.0))]
    NotAFile(Vec<u8>),
    /// An extended-attribute name a PAX record's keyword cannot carry faithfully.
    #[error(
        "{}: extended-attribute name {} cannot be written to a PAX record — it holds an \
         '=' or a newline, or is not valid UTF-8",
        String::from_utf8_lossy(.path),
        String::from_utf8_lossy(.name)
    )]
    XattrNameUnrepresentable {
        /// The file whose attribute cannot be written.
        path: Vec<u8>,
        /// The offending attribute name.
        name: Vec<u8>,
    },
}

impl Error {
    /// The exit code this failure reports.
    fn exit_code(&self) -> u8 {
        match self {
            Error::Usage(_) => exit::USAGE,
            // A malformed filesystem is an opinion formed about one; everything else here
            // is a failure to form one at all.
            Error::Image(_) | Error::Verdict { .. } | Error::BadAcl { .. } => exit::IMAGE_BAD,
            Error::Io { .. }
            | Error::NotARegularFile(_)
            | Error::NotExt { .. }
            | Error::Format(_)
            | Error::Archive(_)
            | Error::ImageIo(_)
            | Error::NoSuchPath(_)
            | Error::Unrepresentable(_)
            | Error::XattrNameUnrepresentable { .. }
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
        ReadError::Io(message) => Error::ImageIo(message),
        ReadError::NotFound(path) | ReadError::NotADirectory(path) => Error::NoSuchPath(path),
        other => Error::Image(other),
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
    }
}

const GENERAL_HELP: &str = "\
ferrosys — write, inspect, and read back ext2/3/4 filesystems

usage:
  ferrosys format  [options] OUT.img    write a filesystem
  ferrosys inspect [options] IMAGE      report on a filesystem
  ferrosys extract [options] IMAGE      read a filesystem's contents back out

  ferrosys <command> --help             the options one command takes
  ferrosys --version                    the version

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
ferrosys format — write an ext2, ext3, or ext4 filesystem

usage:
  ferrosys format --size SIZE --uuid HEX --time SECS [options] OUT.img

required:
  --size SIZE          the filesystem's size: a byte count, optionally suffixed K, M, G,
                       or T
  --uuid HEX           the filesystem UUID, dashed or bare (32 hex digits). The tool
                       mints none: pipe in `uuidgen`, of whatever version you like
  --time SECS          the filesystem's creation time, in seconds since the epoch. Taken
                       from SOURCE_DATE_EPOCH when the option is absent

contents:
  --from-tar FILE|-    populate the filesystem from a tar archive; `-` reads the standard
                       input. The archive's contents are held in memory: peak memory is
                       the sum of the bytes of the files it holds

labelling:
  --label NAME         the volume label, up to 16 bytes. A longer one is refused rather
                       than truncated

profile:
  -t, --type ext2|ext3|ext4   the base feature set to write (default ext4). -O and the
                       geometry options layer on top, so `-t ext2 -O has_journal` is ext3.
                       The image is judged by the features it carries, not the profile it
                       started from

geometry:
  --block-size N       1024, 2048, or 4096 (the default)
  --inode-size N       a power of two from 128 up to the block size (default 256)
  --inodes N           the inode count, rounded up to fill each group's tables. Overrides
                       the size-driven default
  --bytes-per-inode N  one inode per N bytes of filesystem — the density the count is
                       derived from. This and --inodes share one setting; the last wins
  --reserved-percent P blocks held back for the super-user, from 0 to 50, with up to two
                       decimal places (default 5)
  -O feat,^feat,none   turn features on and off, left to right, over the selected profile.
                       `none` clears every feature. The names are the on-disk ones:
                       64bit, metadata_csum, has_journal, … . filetype names the directory
                       format this tool always writes, so clearing it is refused. Clearing
                       extent drops to the block-mapped ext2/ext3 family, which then carries
                       none of the ext4-layer features (flex_bg, 64bit, metadata_csum, …);
                       -t is the direct way to that base
  --grow none|max|SIZE how much reserved descriptor headroom to build in, so the
                       filesystem grows online without relocating its descriptor table.
                       Defaults to `max`, the most the format allows
  --journal auto|N     the journal's size in filesystem blocks (default: sized from the
                       filesystem)
  --errors continue|remount-ro|panic   what the kernel does on a detected filesystem
                       error (`s_errors`): note it and carry on, remount read-only, or
                       panic. Defaults to `continue`, the kernel's own default

determinism:
  --fixed-time SECS    force every inode's times to this value, whatever the source says
  --hash half_md4|tea|legacy       the directory-hash algorithm (default half_md4)
  --hash-signedness signed|unsigned  how a name's bytes are read when hashed. Unsigned by
                       default, which makes the bytes independent of the host
  --hash-seed HEX      the 16-byte directory-hash seed. Defaults to the UUID's bytes

output:
  --json               print the geometry the format realized, as JSON, on the standard
                       output. Without it, a summary goes to the standard error

The destination must be a regular file. A format writes only the blocks the filesystem
uses, so every byte it does not write must already read as zero — which a block device
does not guarantee.
";

const INSPECT_HELP: &str = "\
ferrosys inspect — report on an ext filesystem

usage:
  ferrosys inspect [options] IMAGE

options:
  --offset N           where the filesystem begins within the file, for a partition
                       inside a whole-disk image. A byte count, optionally suffixed K, M,
                       G, or T
  --json               report as JSON rather than as text
  --sarif              report the scan's findings as a SARIF 2.1.0 log, for a static-
                       analysis or forensic pipeline; reports findings alone, not the
                       superblock description, so it needs the scan and cannot pair with
                       --quick
  --groups             report every block group's descriptor as well
  --quick              report the superblock alone, without scanning the image
  --fail-on SEVERITY|never
                       the severity at which the scan's findings make the filesystem bad:
                       cosmetic, conformance, integrity (the default), structural, or
                       never. `integrity` faults a filesystem whose own bytes contradict
                       each other; `conformance` also faults one that is valid ext but not
                       the form this tool writes, which is a check on this tool's own output
                       rather than on ext

The whole image is scanned unless --quick says otherwise, so an image that is bad is
reported as bad (exit 4) rather than merely described.
";

const EXTRACT_HELP: &str = "\
ferrosys extract — read an ext filesystem's contents back out

usage:
  ferrosys extract [--offset N] IMAGE --to-tar FILE|-
  ferrosys extract [--offset N] IMAGE --cat PATH
  ferrosys extract [--offset N] IMAGE --list [--json]

exactly one of:
  --to-tar FILE|-      write the whole tree as a tar archive; `-` writes the standard
                       output. Ownership, modes, times (to the nanosecond), symlinks,
                       hard links, device and FIFO nodes, extended attributes, and POSIX
                       ACLs all survive, carried in PAX records
  --cat PATH           write one file's bytes to the standard output, and nothing else.
                       PATH is a path inside the image, taken as the bytes you typed
  --list               list the tree; --json lists it as JSON

options:
  --offset N           where the filesystem begins within the file

The archive holds a `./` member for the root and skips `/lost+found`, so what comes out
is what `ferrosys format --from-tar` reads back in.
";

#[cfg(test)]
mod tests {
    use super::*;

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
                worst: Severity::Structural
            }
            .exit_code(),
            exit::IMAGE_BAD
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
        // A structural failure is what a bad image looks like...
        assert_eq!(
            from_read(ReadError::BadDirectory).exit_code(),
            exit::IMAGE_BAD
        );
        assert_eq!(
            from_read(ReadError::ChecksumMismatch {
                object: "inode",
                index: 12,
                stored: 1,
                computed: 2
            })
            .exit_code(),
            exit::IMAGE_BAD
        );
        // ...while the host failing to read, or a path the filesystem does not have, says
        // nothing at all about whether the filesystem is sound.
        assert_eq!(
            from_read(ReadError::Io("disk on fire".into())).exit_code(),
            exit::OPERATIONAL
        );
        assert_eq!(
            from_read(ReadError::NotFound(b"/nowhere".to_vec())).exit_code(),
            exit::OPERATIONAL
        );
    }

    #[test]
    fn every_help_topic_has_text() {
        for topic in [
            Topic::General,
            Topic::Format,
            Topic::Inspect,
            Topic::Extract,
        ] {
            let text = help(topic);
            assert!(text.starts_with("ferrosys"), "{topic:?} names the tool");
            assert!(text.contains("usage:"), "{topic:?} states its usage");
        }
        // The help is public prose describing the tool's own surface: the general topic
        // lists every subcommand a user can run, and each subcommand's help names the
        // command it documents. Asserting what the help *is* keeps it honest without
        // naming anything it must not.
        let general = help(Topic::General);
        for command in ["format", "inspect", "extract"] {
            assert!(
                general.contains(command),
                "the general help lists the `{command}` command"
            );
            assert!(
                help_for(command).contains(command),
                "the `{command}` help names its own command"
            );
        }
    }

    /// The help topic for a subcommand name, for the property check above.
    fn help_for(command: &str) -> &'static str {
        match command {
            "format" => help(Topic::Format),
            "inspect" => help(Topic::Inspect),
            "extract" => help(Topic::Extract),
            other => panic!("no help topic for {other}"),
        }
    }
}
