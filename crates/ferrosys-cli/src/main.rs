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
//! Everything an image's bytes depend on is an input the tool is given. A format's UUID is
//! required, its time is required (or comes from `SOURCE_DATE_EPOCH`), and its hash seed
//! defaults to the UUID's bytes — so two runs given the same inputs write the same bytes,
//! always.

// The tool inherits the library's bar: there is no `unsafe` here, ever.
#![forbid(unsafe_code)]

mod args;
mod detect;
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

use ferrosys::DetectError;
// The directory source `--from-dir` walks with, and the failures it reports, exist on the
// platform the library builds it for. Every other command and option is the same
// everywhere; `format::from_dir` is where the difference is confined.
#[cfg(any(target_os = "linux", target_os = "android"))]
use ferrosys::ext::HostError;
use ferrosys::ext::{ArchiveError, FormatError, GeometryError, ReadError, Severity};

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
    /// Writing the filesystem failed.
    #[error(transparent)]
    Format(#[from] FormatError),
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
    /// The image could not be read as far as it had to be.
    #[error("reading the image: {0}")]
    ImageIo(String),
    /// A path the filesystem does not have.
    #[error("no such path in the filesystem: {}", String::from_utf8_lossy(.0))]
    NoSuchPath(Vec<u8>),
    /// A filesystem was read, and it is bad.
    #[error("the filesystem is malformed: {0}")]
    Image(#[source] ReadError),
    /// The scan found what the caller asked to be told about.
    #[error(
        "the filesystem holds {}{count} {}, the worst of them {}",
        if *truncated { "at least " } else { "" },
        if *count == 1 { "anomaly" } else { "anomalies" },
        worst.as_str()
    )]
    Verdict {
        /// How many anomalies the scan found.
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
            Error::Format(FormatError::Geometry(GeometryError::TooSmall {
                reserved_gdt_blocks,
                ..
            })) if *reserved_gdt_blocks > 0 => Some(format!(
                "{reserved_gdt_blocks} of those blocks are growth headroom: `--grow none` \
                 reserves none, and `--grow SIZE` reserves only what growing to SIZE needs"
            )),
            Error::Format(FormatError::FilesystemTooSmallForJournal { minimum, .. }) => {
                Some(format!(
                    "a journal needs {minimum} blocks of its own: `-t ext2` builds a \
                     filesystem without one, as does `-O ^has_journal`"
                ))
            }
            Error::Format(FormatError::JournalDoesNotFit { .. }) => Some(
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
            // Writing an archive out of an image reads that image, so some of what an
            // archive failure carries is a verdict about the filesystem: a structure that
            // cannot be read, and a stored ACL that does not decode, are the image's faults.
            // A socket, an unwritable attribute name, and a destination that cannot be
            // written are not — the filesystem is sound and the request cannot be carried
            // out.
            Error::Archive(ArchiveError::Read(e)) => match e {
                ReadError::Io { .. } => exit::OPERATIONAL,
                _ => exit::IMAGE_BAD,
            },
            Error::Archive(ArchiveError::Acl { .. }) => exit::IMAGE_BAD,
            // A tree that cannot be walked and a platform with no walk to run are both
            // failures to carry the command out, so both land here; only one of them
            // exists in any one build.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Error::Host(_) => exit::OPERATIONAL,
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            Error::NoDirectorySource => exit::OPERATIONAL,
            Error::Io { .. }
            | Error::NotARegularFile(_)
            | Error::NotDetected { .. }
            | Error::NotExt { .. }
            | Error::Format(_)
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
    }
}

const GENERAL_HELP: &str = "\
ferrosys — write, inspect, and read back ext2/3/4 filesystems

usage:
  ferrosys format  [options] OUT.img    write a filesystem
  ferrosys inspect [options] IMAGE      report on a filesystem
  ferrosys extract [options] IMAGE      read a filesystem's contents back out
  ferrosys detect  [options] IMAGE      say which filesystem an image holds

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

  ferrosys format --size 512M --uuid \"$(uuidgen)\" --time \"$(date +%s)\" rootfs.img

Both --uuid and --time are required because an image's bytes are a function of its
inputs alone: the tool reads neither the clock nor a random source, so the same inputs
write the same bytes. SOURCE_DATE_EPOCH supplies --time when it is set.

required:
  --size SIZE          the filesystem's size: a byte count, optionally suffixed K, M, G,
                       or T
  --uuid HEX           the filesystem UUID, dashed or bare (32 hex digits). The tool
                       mints none: pipe in `uuidgen`, of whatever version you like
  --time SECS          the filesystem's creation time, in seconds since the epoch. Taken
                       from SOURCE_DATE_EPOCH when the option is absent

contents (at most one):
  --from-tar FILE|-    populate the filesystem from a tar archive. A named FILE is left on
                       disk and each member read as its file is placed, so peak memory is
                       the largest single member; `-` reads the standard input, which
                       cannot be sought back over and so is held whole. The archive must
                       be uncompressed — decompress it into `-` with `gunzip -c f.tar.gz |
                       ferrosys format ... --from-tar -`
  --from-dir DIR       populate the filesystem from a directory tree on this machine. DIR
                       itself becomes the filesystem root. Modes, ownership, all three
                       times, symlinks, hard links, device and FIFO nodes, sockets, and
                       extended attributes with their POSIX ACLs are all carried; symlinks
                       are recorded, never followed. Each file is read as it is placed, so
                       peak memory is the largest single file. Walking a tree records Linux
                       inode metadata and Linux extended attributes, so this option is
                       carried out on Linux alone; --from-tar reads an archive anywhere
  --owner UID:GID      own every entry of a --from-dir tree by this user and group,
                       whatever the host files say. A build that does not run as root
                       usually wants --owner 0:0: without it the image is owned by the
                       user that built it

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

determinism:
  --fixed-time SECS    force every inode's times to this value, whatever the source says
  --hash half_md4|tea|legacy       the directory-hash algorithm (default half_md4)
  --hash-signedness signed|unsigned  how a name's bytes are read when hashed. Unsigned by
                       default, which makes the bytes independent of the host
  --hash-seed HEX      the 16-byte directory-hash seed. Defaults to the UUID's bytes

output:
  --json               print the geometry the format realized, as JSON, on the standard
                       output. Without it, a summary goes to the standard error
  --dry-run            report the geometry this command would realize and write nothing.
                       The destination is not opened, created, or truncated

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
reported as bad (exit 4) rather than merely described. What counts as bad is --fail-on,
which defaults to `integrity`: a filesystem whose own bytes contradict each other fails,
and a valid ext filesystem that another tool wrote does not. That is the default a CI
gate inherits, and `--fail-on conformance` is the stricter line to draw deliberately.
";

const EXTRACT_HELP: &str = "\
ferrosys extract — read an ext filesystem's contents back out

usage:
  ferrosys extract [--offset N] IMAGE --to-tar FILE|-
  ferrosys extract [--offset N] IMAGE --cat PATH
  ferrosys extract [--offset N] IMAGE --stat PATH [--json]
  ferrosys extract [--offset N] IMAGE --list [--json]

exactly one of:
  --to-tar FILE|-      write the whole tree as a tar archive; `-` writes the standard
                       output. Ownership, modes, times (to the nanosecond), symlinks,
                       hard links, device and FIFO nodes, extended attributes, and POSIX
                       ACLs all survive, carried in PAX records
  --cat PATH           write one file's bytes to the standard output, and nothing else.
                       PATH is a path inside the image, taken as the bytes you typed
  --stat PATH          report everything the filesystem records about one path: its type,
                       mode (octal and symbolic), ownership, link count, size, all four
                       times, a device node's numbers, a symlink's target, and its extended
                       attributes with any POSIX ACL decoded. A path naming a symlink
                       describes the link, not its target; --json reports it as JSON
  --list               list the tree; --json lists it as JSON, with each entry's extended
                       attributes and decoded ACLs

options:
  --offset N           where the filesystem begins within the file
  --max-file-bytes N   refuse to read a file larger than N bytes, for an image whose
                       declared sizes have not earned trust: a file's size is the image's
                       own claim, and a sparse file legitimately dwarfs the filesystem
                       holding it, so nothing structural bounds it. Over the cap the read
                       is an error rather than a short file

Reading holds no whole file: --cat streams to the standard output and --to-tar streams each
member into the archive, so a multi-gigabyte file costs a working set rather than its size.

The archive holds a `./` member for the root and skips `/lost+found`, so what comes out
is what `ferrosys format --from-tar` reads back in.

A JSON mode's `mode` field is the permission bits as a decimal number, since JSON has no
octal literal — 509 is 0o775 — and `mode_octal` beside it carries the usual spelling.
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

The answer is one word on the standard output — ext2, ext3, ext4, or `unrecognized` — so it
reads well in a shell test. An unrecognized image exits 8, since there is no filesystem to
have an opinion about.

This asks what an image *is*, not whether it is sound: an image with a quirk `inspect` would
refuse still classifies here. Use `inspect` to be told whether a filesystem is well-formed.
";

#[cfg(test)]
mod tests {
    use super::*;
    use ferrosys::ext::ondisk::Timestamp;
    use ferrosys::ext::{FormatOptions, Reader, TreeBuilder};

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
            "the filesystem holds at least 10000 anomalies, the worst of them structural"
        );
        // One finding is one anomaly: the verdict is a line a person reads.
        assert_eq!(
            Error::Verdict {
                count: 1,
                worst: Severity::Integrity,
                truncated: false,
            }
            .to_string(),
            "the filesystem holds 1 anomaly, the worst of them integrity"
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
        for topic in [
            Topic::General,
            Topic::Format,
            Topic::Inspect,
            Topic::Extract,
            Topic::Detect,
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
        for command in ["format", "inspect", "extract", "detect"] {
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
            "detect" => help(Topic::Detect),
            other => panic!("no help topic for {other}"),
        }
    }
}
