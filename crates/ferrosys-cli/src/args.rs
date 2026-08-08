//! The command line: tokenizing `argv` and reading each subcommand's options.
//!
//! This module is pure. It takes the argument list and the one environment value the
//! tool honours (`SOURCE_DATE_EPOCH`) as inputs and returns a [`Command`] or a
//! [`UsageError`] — it opens no file, reads no clock, and consults no environment of
//! its own, so every path through it is a unit test with no I/O.
//!
//! Arguments are `OsString`s and stay that way. A value is never classified as a flag:
//! whatever token follows an option *is* that option's value, so `--offset -1` yields
//! the text `-1` to the size parser, which refuses it. There is no lookahead and no
//! negative-number special case. A `--` ends the options; every token after it is
//! positional.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use ferrosys::Slack;
use ferrosys::ext::Timestamp;
use ferrosys::ext::{
    ErrorBehavior, FeatureError, FeatureSet, GrowReservation, HashSignedness, HashVersion,
    InodeCount, JournalSize, ReservedRatio, Severity,
};
use ferrosys::fat::{FatTypeRequest, VolumeLabel};
use ferrosys::{AcceptedLoss, Synthesis};

use crate::parse::{self, FsType, ValueError};

/// The bytes of an OS string, and the OS string a slice of those bytes names.
///
/// Splitting `--name=value` cuts an argument at an ASCII byte, and a path *inside* an
/// image is a byte string to begin with, so the parser works in bytes. Both directions
/// are exact on a Unix host, where an OS string is a byte string. Elsewhere an OS string
/// is Unicode and a byte slice names one only when it is valid UTF-8 — which every
/// value but a host path already must be, and a host path on such a host is Unicode
/// anyway.
pub mod os {
    use std::ffi::{OsStr, OsString};

    /// The bytes of `s`.
    #[cfg(unix)]
    pub fn bytes(s: &OsStr) -> &[u8] {
        std::os::unix::ffi::OsStrExt::as_bytes(s)
    }

    /// The bytes of `s`. ASCII bytes survive this encoding unchanged, which is all the
    /// tokenizer cuts on.
    #[cfg(not(unix))]
    pub fn bytes(s: &OsStr) -> &[u8] {
        s.as_encoded_bytes()
    }

    /// The OS string `b` names.
    #[cfg(unix)]
    pub fn string(b: &[u8]) -> Option<OsString> {
        Some(<OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b).to_owned())
    }

    /// The OS string `b` names, or `None` when this platform's OS strings cannot hold
    /// those bytes.
    #[cfg(not(unix))]
    pub fn string(b: &[u8]) -> Option<OsString> {
        std::str::from_utf8(b).ok().map(OsString::from)
    }
}

/// The tool's name in its own messages.
pub const TOOL: &str = "ferrosys";

/// What the command line asked for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Command {
    /// Write a filesystem.
    Format(Box<FormatArgs>),
    /// Report on a filesystem.
    Inspect(InspectArgs),
    /// Read a filesystem's contents back out.
    Extract(ExtractArgs),
    /// Say which filesystem an image holds.
    Detect(DetectArgs),
    /// Change what an existing filesystem is known by.
    Identity(IdentityArgs),
    /// Print usage, for the tool as a whole or for one subcommand.
    Help(Topic),
    /// Print the version.
    Version,
}

/// Which usage text to print.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Topic {
    /// The tool as a whole.
    General,
    /// One subcommand.
    Format,
    /// One subcommand.
    Inspect,
    /// One subcommand.
    Extract,
    /// One subcommand.
    Detect,
    /// One subcommand.
    Identity,
}

/// Where an archive is read from, or written to: a named file, or the standard stream,
/// which the single argument `-` names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Stream {
    /// The process's standard input or standard output.
    Std,
    /// A named file.
    File(PathBuf),
}

impl Stream {
    /// The stream a value names: `-` is the standard one, anything else is a file.
    fn from_value(v: OsString) -> Self {
        if v == OsStr::new("-") {
            Stream::Std
        } else {
            Stream::File(PathBuf::from(v))
        }
    }
}

/// What a format populates the filesystem from. At most one is given; without either the
/// filesystem is empty but for `/lost+found`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Contents {
    /// A tar archive: a named file, or the standard input.
    Tar(Stream),
    /// A directory tree on this host.
    Dir(PathBuf),
}

/// How large the filesystem is: a size named outright, or one found from what goes in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Size {
    /// The byte count `--size` named.
    Bytes(u64),
    /// `--size auto`: the smallest filesystem that holds the contents with the room
    /// `--slack` asks for left free.
    Fit(Slack),
}

/// `ferrosys format`: everything the filesystem's bytes are a function of.
///
/// Every input is here, and nothing else is read: the clock (`time`), the size, the
/// contents (`contents`, `owner`), and — in [`target`](Self::target) — the family to write
/// and everything only that family takes. Two runs given the same values write the same
/// bytes.
///
/// The split is where it is because the fields above it are the questions every family
/// answers and the ones below it are not: an ext filesystem has a UUID, a feature set, and a
/// journal, and a FAT volume has none of the three. Flattening them together would put a
/// dozen fields in front of a caller that mean nothing for the family it named.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FormatArgs {
    /// The file to write. It must be a regular file.
    pub out: PathBuf,
    /// How large the filesystem is.
    pub size: Size,
    /// The filesystem's creation and write time.
    pub time: Timestamp,
    /// What to populate the filesystem from, or `None` for an empty one.
    pub contents: Option<Contents>,
    /// The user and group every entry is owned by, overriding what a walked directory
    /// tree records, or `None` to keep the host's.
    pub owner: Option<(u32, u32)>,
    /// Print the geometry the format realized as JSON.
    pub json: bool,
    /// Write the image to a sibling temporary file and rename it over the destination once
    /// it is complete, so the destination never holds a partial image.
    pub atomic: bool,
    /// Report the geometry the format would realize and write nothing.
    pub dry_run: bool,
    /// Which family to write, and the inputs only that family takes.
    pub target: Target,
}

/// Which family a format writes, and everything only that family takes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Target {
    /// An ext2, ext3, or ext4 filesystem.
    Ext(Box<ExtTarget>),
    /// A FAT12, FAT16, or FAT32 volume.
    Fat(FatTarget),
}

/// What only an ext format takes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtTarget {
    /// The filesystem UUID.
    pub uuid: [u8; 16],
    /// The feature profile, with the block and inode sizes already folded in.
    pub feature: FeatureSet,
    /// What the kernel does on a detected filesystem error (`s_errors`).
    pub errors: ErrorBehavior,
    /// How many inodes to provide.
    pub inodes: InodeCount,
    /// The share of blocks held back for the super-user.
    pub reserved: ReservedRatio,
    /// The volume label (`s_volume_name`), NUL-padded; all zero when unlabelled.
    pub volume_name: [u8; 16],
    /// How much reserved descriptor headroom to build in.
    pub grow: GrowReservation,
    /// How large the journal is.
    pub journal: JournalSize,
    /// A time forced onto every inode, overriding the source's.
    pub fixed_time: Option<Timestamp>,
    /// The directory-hash algorithm.
    pub hash_version: HashVersion,
    /// Whether a name's bytes are hashed as signed or unsigned.
    pub hash_signedness: HashSignedness,
    /// The 16-byte directory-hash seed. Defaults to the UUID's bytes.
    pub hash_seed: [u8; 16],
}

/// What only a FAT format takes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FatTarget {
    /// Which of the three types the geometry must derive to. Nothing in a FAT image records
    /// the type, so this states what the derivation must arrive at rather than what to write
    /// down.
    pub request: FatTypeRequest,
    /// The volume serial number the boot sector records — this family's identity field, as
    /// the UUID is ext's.
    pub volume_id: u32,
    /// The volume label, or `None` for an unnamed volume.
    pub label: Option<VolumeLabel>,
    /// Which properties of the source the build may lose. Empty by default, so a build that
    /// would drop something fails and names it.
    pub accepted_loss: AcceptedLoss,
    /// What a read of the image would fill an owner and a mode with, which is the point a
    /// loss is measured against: a value that survives the round trip was not lost.
    pub synthesis: Synthesis,
}

/// `ferrosys inspect`: what to report on, and what counts as a failing verdict.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InspectArgs {
    /// The image to read.
    pub image: PathBuf,
    /// Where the filesystem begins within it.
    pub offset: u64,
    /// Report as JSON rather than as text.
    pub json: bool,
    /// Report the scan's findings as a SARIF log, and nothing else.
    pub sarif: bool,
    /// Report each block group's descriptor.
    pub groups: bool,
    /// Report the superblock alone, without scanning the image.
    pub quick: bool,
    /// The severity at which the scan's findings make the filesystem bad, or `None` when
    /// nothing does.
    pub fail_on: Option<Severity>,
}

/// `ferrosys detect`: which image to classify, and where the filesystem begins in it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DetectArgs {
    /// The image to classify.
    pub image: PathBuf,
    /// Where the filesystem begins within it.
    pub offset: u64,
    /// Report as JSON rather than as one line of text.
    pub json: bool,
}

/// `ferrosys identity`: what an existing filesystem becomes known by.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityArgs {
    /// The image to rewrite, opened for reading and writing.
    pub image: PathBuf,
    /// The new filesystem UUID, or `None` to leave it.
    pub uuid: Option<[u8; 16]>,
    /// The new volume label, NUL-padded, or `None` to leave it.
    pub volume_name: Option<[u8; 16]>,
    /// Record the seed the current UUID implies and set `metadata_csum_seed`, so a UUID
    /// change leaves the filesystem's metadata checksums valid.
    pub set_checksum_seed: bool,
    /// Report what the rewrite wrote as JSON rather than as text.
    pub json: bool,
}

/// `ferrosys extract`: what to read the filesystem's contents into.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtractArgs {
    /// The image to read.
    pub image: PathBuf,
    /// Where the filesystem begins within it.
    pub offset: u64,
    /// What to produce.
    pub mode: ExtractMode,
    /// The largest file a read will return, or `None` to derive it from the image's own
    /// length. A file past it is an error rather than a truncated one.
    ///
    /// There is no spelling for "no cap", and none is needed: the cap is a size, so a caller
    /// who means to read a sparse file of a given size names that size.
    pub max_file_bytes: Option<u64>,
    /// Write `--to-tar`'s archive to a sibling temporary file and rename it over the
    /// destination once the walk is complete, so the destination never holds a partial
    /// archive.
    pub atomic: bool,
    /// What to record for a property the filesystem being read has no field for.
    ///
    /// Every ext filesystem records ownership, permission bits, and times, so this changes
    /// nothing about an ext image. It is the answer for a format that records none of them,
    /// where something has to be assumed before a host file can be created — and the
    /// defaults are the conservative ones, so a tree extracted with nothing named never
    /// lands more permissive than it was asked to be.
    pub synthesis: Synthesis,
    /// Refuse an image the reader cannot hold to its format, rather than interpreting it
    /// best-effort.
    ///
    /// Extraction writes what it read somewhere, so an image carrying a deviation this
    /// reader does not follow produces output that looks complete and is not. Without this
    /// the read falls back to a lenient one, which is what makes a damaged image
    /// recoverable, and says on the standard error which deviation it decided to interpret
    /// through.
    pub strict: bool,
}

/// The one thing an extract produces. Exactly one is asked for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExtractMode {
    /// Write the whole tree as a tar archive.
    ToTar(Stream),
    /// Write the whole tree into a directory on this host.
    ToDir {
        /// The destination directory.
        path: PathBuf,
        /// Write what an unprivileged process may rather than failing on what it may not.
        skip_privileged: bool,
    },
    /// Write one file's bytes, and nothing else.
    Cat(Vec<u8>),
    /// Report everything one path's inode records, extended attributes included.
    Stat {
        /// The path inside the image.
        path: Vec<u8>,
        /// Report as JSON rather than as text.
        json: bool,
    },
    /// List the tree.
    List {
        /// List as JSON rather than as text.
        json: bool,
    },
}

/// A command line that cannot be understood.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum UsageError {
    /// No subcommand was given.
    #[error("no command given")]
    NoCommand,
    /// The first argument names no subcommand.
    #[error("{0}: not a command")]
    UnknownCommand(String),
    /// An option this subcommand does not take.
    #[error(fmt = fmt_unknown_flag)]
    UnknownFlag {
        /// The subcommand it was given to, or empty when the tokenizer rejected the
        /// token before any subcommand claimed it.
        command: &'static str,
        /// The offending option.
        flag: String,
    },
    /// An option that takes a value was given none.
    #[error("{0} needs a value")]
    MissingValue(String),
    /// An option that takes no value was given one.
    #[error("{0} takes no value")]
    UnexpectedValue(String),
    /// A required option was not given.
    #[error("{command}: {flag} is required")]
    MissingRequired {
        /// The subcommand.
        command: &'static str,
        /// The option that must be given.
        flag: &'static str,
    },
    /// A required argument was not given.
    #[error("{command}: no {what} given")]
    MissingArgument {
        /// The subcommand.
        command: &'static str,
        /// What was expected.
        what: &'static str,
    },
    /// More arguments were given than the subcommand takes.
    #[error("{command}: unexpected argument {value}")]
    UnexpectedArgument {
        /// The subcommand.
        command: &'static str,
        /// The offending argument.
        value: String,
    },
    /// An option's value is not one the option takes.
    #[error("{flag}: {source}")]
    Value {
        /// The option.
        flag: String,
        /// Why its value was refused.
        #[source]
        source: ValueError,
    },
    /// The requested features cannot be written together.
    #[error(transparent)]
    Feature(#[from] FeatureError),
    /// `format` was given two things to populate the filesystem from.
    #[error("format: give at most one of --from-tar or --from-dir")]
    TwoSources,
    /// `--slack` was given to a format whose size was named outright.
    #[error(
        "format: --slack is the room to leave in a filesystem sized to its contents, so \
         it goes with --size auto"
    )]
    SlackWithoutFit,
    /// `--owner` was given to a format with no directory tree to apply it to.
    #[error(
        "format: --owner replaces the ownership a walked directory tree records, so it \
         goes with --from-dir"
    )]
    OwnerWithoutDir,
    /// An option belonging to one family was given to a format writing another.
    ///
    /// Refused rather than passed over: an ext filesystem has no volume serial number and a
    /// FAT volume has no journal, so a line naming both has said two things that cannot both
    /// be honoured, and carrying on would write an image built differently from the one that
    /// was asked for.
    #[error("format: {flag} is an option of the {family} family, and this format writes {named}")]
    FlagNotForFamily {
        /// The offending option, as it is spelled.
        flag: &'static str,
        /// The family the option belongs to.
        family: &'static str,
        /// The filesystem the command line named.
        named: &'static str,
    },
    /// `extract` was told to produce nothing, or more than one thing.
    #[error("extract: give exactly one of --to-tar, --to-dir, --cat, --stat, or --list")]
    ExtractMode,
    /// `--skip-privileged` was given to an extract that writes no tree it could apply to.
    #[error("extract: --skip-privileged applies to --to-dir")]
    SkipPrivilegedWithoutDir,
    /// `--json` was given to an extract that produces bytes, which have no JSON form.
    #[error("extract: --json applies to --list and --stat")]
    JsonWithoutReport,
    /// `--atomic` was given to an extract that writes no file it could rename into place.
    #[error("extract: --atomic applies to --to-tar FILE")]
    AtomicWithoutFile,
    /// `format --atomic` decides how the destination is replaced, and `--dry-run` never
    /// opens one.
    #[error("format: --atomic decides how the destination is replaced, and --dry-run writes none")]
    AtomicWithDryRun,
    /// `inspect` was given both `--json` and `--sarif`, two different output formats.
    #[error("inspect: --sarif and --json are different output formats; give one")]
    SarifWithJson,
    /// `inspect --sarif` reports scan findings, which `--quick` skips.
    #[error("inspect: --sarif reports scan findings, which --quick skips")]
    SarifWithQuick,
    /// `inspect --sarif` reports scan findings, and has no place to put a group table.
    #[error("inspect: --sarif reports scan findings; --groups has no place in one")]
    SarifWithGroups,
    /// `inspect --fail-on` is a verdict on the scan, which `--quick` skips — so together
    /// they are a gate that cannot fire.
    #[error("inspect: --fail-on is a verdict on the scan, which --quick skips")]
    FailOnWithQuick,
    /// A value this platform cannot name a file with.
    #[error("{0}: the value is not text this platform can name a file with")]
    NotAFilename(String),
}

/// Render [`UsageError::UnknownFlag`], omitting the `command:` prefix when the command
/// is empty — the tokenizer rejects a malformed token before any subcommand claims it,
/// and a leading `: ` would read as a stray colon under the tool-name prefix.
fn fmt_unknown_flag(
    command: &str,
    flag: &str,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    if command.is_empty() {
        write!(f, "{flag}: not an option")
    } else {
        write!(f, "{command}: {flag}: not an option")
    }
}

/// A single argument, classified.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Arg {
    /// `--name`, or `--name=value` with its value attached.
    Long(String, Option<OsString>),
    /// `-n`, or `-nvalue` with its value attached.
    Short(char, Option<OsString>),
    /// A token that introduces nothing.
    Positional(OsString),
}

/// The argument list, consumed left to right.
struct Args {
    rest: std::vec::IntoIter<OsString>,
    /// Set by `--`: every token after it is positional, whatever it looks like.
    ended: bool,
}

impl Args {
    fn new(argv: Vec<OsString>) -> Self {
        Self {
            rest: argv.into_iter(),
            ended: false,
        }
    }

    /// The next argument, classified — unless `--` has ended the options, after which
    /// everything is positional.
    fn next(&mut self) -> Result<Option<Arg>, UsageError> {
        let Some(token) = self.rest.next() else {
            return Ok(None);
        };
        if self.ended {
            return Ok(Some(Arg::Positional(token)));
        }
        let bytes = os::bytes(&token);
        if bytes == b"--" {
            self.ended = true;
            return self.next();
        }
        if let Some(rest) = bytes.strip_prefix(b"--") {
            // The name is what precedes the first `=`; the value is the rest of the
            // token, whatever bytes it holds.
            let (name, value) = match rest.iter().position(|&b| b == b'=') {
                Some(i) => (&rest[..i], Some(&rest[i + 1..])),
                None => (rest, None),
            };
            let name = flag_name(name).ok_or_else(|| UsageError::UnknownFlag {
                command: "",
                flag: token.to_string_lossy().into_owned(),
            })?;
            let value = match value {
                Some(v) => Some(os::string(v).ok_or_else(|| {
                    UsageError::NotAFilename(token.to_string_lossy().into_owned())
                })?),
                None => None,
            };
            return Ok(Some(Arg::Long(name, value)));
        }
        // A lone `-` is a value naming the standard stream, not an option.
        if bytes.len() > 1 && bytes[0] == b'-' {
            let letter = char::from(bytes[1]);
            if !letter.is_ascii_alphabetic() {
                return Err(UsageError::UnknownFlag {
                    command: "",
                    flag: token.to_string_lossy().into_owned(),
                });
            }
            let value = if bytes.len() > 2 {
                Some(os::string(&bytes[2..]).ok_or_else(|| {
                    UsageError::NotAFilename(token.to_string_lossy().into_owned())
                })?)
            } else {
                None
            };
            return Ok(Some(Arg::Short(letter, value)));
        }
        Ok(Some(Arg::Positional(token)))
    }

    /// The value of the option just returned: the one attached to it, or the next token
    /// verbatim. The token is taken without being classified, so a value that looks like
    /// an option is still that option's value.
    fn value(&mut self, flag: &str, attached: Option<OsString>) -> Result<OsString, UsageError> {
        match attached {
            Some(v) => Ok(v),
            None => self
                .rest
                .next()
                .ok_or_else(|| UsageError::MissingValue(flag.to_string())),
        }
    }

    /// Refuse a value on an option that takes none, so `--json=yes` is a mistake caught
    /// rather than a `yes` silently discarded.
    fn no_value(flag: &str, attached: Option<OsString>) -> Result<(), UsageError> {
        match attached {
            None => Ok(()),
            Some(_) => Err(UsageError::UnexpectedValue(flag.to_string())),
        }
    }
}

/// A long option's name: ASCII, as every option this tool defines is. A name that is not
/// is not one of ours, and is reported as the unknown option it is.
fn flag_name(bytes: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(bytes).ok()?;
    name.is_ascii().then(|| name.to_string())
}

/// Attach an option's name to the reason its value was refused.
fn value_err(flag: &str) -> impl Fn(ValueError) -> UsageError + '_ {
    move |source| UsageError::Value {
        flag: flag.to_string(),
        source,
    }
}

/// Parse a whole command line: the arguments past the program name, and the value of
/// `SOURCE_DATE_EPOCH`, which supplies `format --time` when that option is absent.
///
/// # Errors
///
/// A [`UsageError`] if the arguments name no command, name an option no command takes,
/// omit a required one, or give one a value it cannot hold.
pub fn parse(
    argv: Vec<OsString>,
    source_date_epoch: Option<OsString>,
) -> Result<Command, UsageError> {
    let mut args = Args::new(argv);
    let Some(first) = args.next()? else {
        return Err(UsageError::NoCommand);
    };
    match first {
        Arg::Positional(name) if name == OsStr::new("format") => {
            format(&mut args, source_date_epoch)
        }
        Arg::Positional(name) if name == OsStr::new("inspect") => inspect(&mut args),
        Arg::Positional(name) if name == OsStr::new("extract") => extract(&mut args),
        Arg::Positional(name) if name == OsStr::new("detect") => detect(&mut args),
        Arg::Positional(name) if name == OsStr::new("identity") => identity(&mut args),
        Arg::Positional(name) if name == OsStr::new("help") => Ok(Command::Help(Topic::General)),
        // An attached value is refused rather than dropped, here as everywhere: `--help=x`
        // asks for something this option cannot do, and answering it with help would be
        // answering a different question than the one asked.
        Arg::Long(name, attached) if name == "help" => {
            Args::no_value("--help", attached)?;
            Ok(Command::Help(Topic::General))
        }
        Arg::Long(name, attached) if name == "version" => {
            Args::no_value("--version", attached)?;
            Ok(Command::Version)
        }
        Arg::Short('h', attached) => {
            Args::no_value("-h", attached)?;
            Ok(Command::Help(Topic::General))
        }
        Arg::Short('V', attached) => {
            Args::no_value("-V", attached)?;
            Ok(Command::Version)
        }
        Arg::Positional(name) => Err(UsageError::UnknownCommand(
            name.to_string_lossy().into_owned(),
        )),
        Arg::Long(name, _) => Err(UsageError::UnknownFlag {
            command: TOOL,
            flag: format!("--{name}"),
        }),
        Arg::Short(letter, _) => Err(UsageError::UnknownFlag {
            command: TOOL,
            flag: format!("-{letter}"),
        }),
    }
}

/// `ferrosys format [options] OUT`.
fn format(args: &mut Args, source_date_epoch: Option<OsString>) -> Result<Command, UsageError> {
    const CMD: &str = "format";
    let mut out: Option<PathBuf> = None;
    let mut size: Option<u64> = None;
    // Whether the size is to be found from the contents (`--size auto`) rather than named.
    let mut fit = false;
    let mut slack: Option<Slack> = None;
    let mut uuid: Option<[u8; 16]> = None;
    let mut volume_id: Option<u32> = None;
    let mut time: Option<i64> = None;
    let mut from_tar: Option<Stream> = None;
    let mut from_dir: Option<PathBuf> = None;
    let mut owner: Option<(u32, u32)> = None;
    // The family and everything only one family takes are composed once the whole line is
    // read (below), not applied in place as options arrive. So the base type (`-t`), the size
    // overrides, and the `-O` deltas take effect in a fixed order — type seeds, sizes
    // override, `-O` lists layer on last — rather than in the order they happen to appear.
    // This is the order `mke2fs -t … -O …` composes in, and it is what makes `-t`
    // position-independent for the family it names as much as for the features it seeds.
    let mut fs_type: Option<FsType> = None;
    let mut block_size: Option<u32> = None;
    let mut inode_size: Option<u16> = None;
    let mut feature_ops: Vec<OsString> = Vec::new();
    let mut errors = ErrorBehavior::default();
    let mut inodes = InodeCount::default();
    let mut reserved = ReservedRatio::default();
    // The label as typed. It is validated once the family is known: an ext label is sixteen
    // bytes of anything and a FAT label is eleven in the OEM character set, so the same
    // argument is two different values and neither can be built before `-t` is read.
    let mut label: Option<Vec<u8>> = None;
    let mut grow = GrowReservation::default();
    let mut journal = JournalSize::Auto;
    let mut fixed_time: Option<i64> = None;
    let mut hash_version = HashVersion::default();
    let mut hash_signedness = HashSignedness::default();
    let mut hash_seed: Option<[u8; 16]> = None;
    let mut accepted_loss = AcceptedLoss::NONE;
    let mut synthesis = Synthesis::new();
    let mut json = false;
    let mut atomic = false;
    let mut dry_run = false;
    // Every option seen that belongs to one family alone, so naming one with the other
    // family's type is refused by name rather than passed over. Recorded rather than checked
    // on the spot, because `-t` may come after the option it disqualifies.
    let mut family_only: Vec<(&'static str, &'static str)> = Vec::new();

    while let Some(arg) = args.next()? {
        match arg {
            Arg::Long(name, attached) => {
                let flag = format!("--{name}");
                match name.as_str() {
                    "help" => {
                        Args::no_value(&flag, attached)?;
                        return Ok(Command::Help(Topic::Format));
                    }
                    // `auto` is the one value that is not a byte count: it asks for the
                    // size to be found from the contents rather than named. The two are one
                    // setting, so the last `--size` given wins whichever form it takes.
                    "size" => {
                        let value = args.value(&flag, attached)?;
                        if value == "auto" {
                            (size, fit) = (None, true);
                        } else {
                            size = Some(parse::size(&value).map_err(value_err(&flag))?);
                            fit = false;
                        }
                    }
                    "slack" => {
                        slack = Some(
                            parse::slack(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "uuid" => {
                        family_only.push(("--uuid", "ext"));
                        uuid = Some(
                            parse::hex16(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    // A FAT volume's identity: a 32-bit serial number, not a 128-bit UUID.
                    // Each family names its own rather than one flag being truncated into
                    // whatever the format has room for.
                    "volume-id" => {
                        family_only.push(("--volume-id", "fat"));
                        volume_id = Some(
                            parse::hex32(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "time" => {
                        time = Some(
                            parse::seconds(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "from-tar" => from_tar = Some(Stream::from_value(args.value(&flag, attached)?)),
                    "from-dir" => from_dir = Some(PathBuf::from(args.value(&flag, attached)?)),
                    "owner" => {
                        owner = Some(
                            parse::owner(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    // The base type names the family and seeds whatever that family
                    // composes from. `--type` and `-t` name the same thing, and the last one
                    // given wins. `-O` and the size options layer on top of it when the
                    // feature set is composed below.
                    "type" => {
                        fs_type = Some(
                            parse::fs_type(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "block-size" => {
                        family_only.push(("--block-size", "ext"));
                        block_size = Some(
                            parse::count_u32(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "inode-size" => {
                        family_only.push(("--inode-size", "ext"));
                        let v = parse::count_u32(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                        inode_size = Some(u16::try_from(v).map_err(|_| UsageError::Value {
                            flag: flag.clone(),
                            source: ValueError::OutOfRange(v.to_string()),
                        })?);
                    }
                    // The two inode knobs share one setting, last one wins: `--inodes` names
                    // the count outright, `--bytes-per-inode` names the density it derives
                    // from. Either overrides the size-driven default.
                    "inodes" => {
                        family_only.push(("--inodes", "ext"));
                        let count = parse::count_u32(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                        inodes = InodeCount::Count(count);
                    }
                    "bytes-per-inode" => {
                        family_only.push(("--bytes-per-inode", "ext"));
                        inodes = parse::bytes_per_inode(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "reserved-percent" => {
                        family_only.push(("--reserved-percent", "ext"));
                        reserved = parse::reserved_percent(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    // A label is bytes, not text — an ext field holds sixteen of them and
                    // the reader reports whatever is there — so it is taken as the argument's
                    // bytes, as a path inside the image is. What fits is the family's
                    // question, asked once `-t` is known.
                    "label" => {
                        let value = args.value(&flag, attached)?;
                        label = Some(os::bytes(&value).to_vec());
                    }
                    // Which properties of the source the build may lose. A FAT directory
                    // entry has no field for an owner, a mode, a symbolic link, a second
                    // name, a device number, or an extended attribute, so a tree carrying any
                    // of them is refused until the caller has said which may go.
                    "accept-loss" => {
                        family_only.push(("--accept-loss", "fat"));
                        accepted_loss = parse::accepted_loss(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    // The point a loss is measured against: what a read of the image would
                    // fill an owner and a mode with. A value that survives the round trip was
                    // not lost, so these are what make a root-owned, conventionally moded
                    // tree go into a FAT image faithfully.
                    "assume-owner" => {
                        family_only.push(("--assume-owner", "fat"));
                        let (uid, gid) = parse::owner(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                        synthesis = synthesis.owner(uid, gid);
                    }
                    "assume-modes" => {
                        family_only.push(("--assume-modes", "fat"));
                        let (file, dir) = parse::modes(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                        synthesis = synthesis.modes(file, dir);
                    }
                    "grow" => {
                        family_only.push(("--grow", "ext"));
                        grow =
                            parse::grow(&args.value(&flag, attached)?).map_err(value_err(&flag))?;
                    }
                    "journal" => {
                        family_only.push(("--journal", "ext"));
                        journal = parse::journal(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "errors" => {
                        family_only.push(("--errors", "ext"));
                        errors = parse::error_behavior(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "fixed-time" => {
                        family_only.push(("--fixed-time", "ext"));
                        fixed_time = Some(
                            parse::seconds(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "hash" => {
                        family_only.push(("--hash", "ext"));
                        hash_version = parse::hash_version(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "hash-signedness" => {
                        family_only.push(("--hash-signedness", "ext"));
                        hash_signedness = parse::hash_signedness(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "hash-seed" => {
                        family_only.push(("--hash-seed", "ext"));
                        hash_seed = Some(
                            parse::hex16(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "json" => {
                        Args::no_value(&flag, attached)?;
                        json = true;
                    }
                    "atomic" => {
                        Args::no_value(&flag, attached)?;
                        atomic = true;
                    }
                    "dry-run" => {
                        Args::no_value(&flag, attached)?;
                        dry_run = true;
                    }
                    _ => {
                        return Err(UsageError::UnknownFlag { command: CMD, flag });
                    }
                }
            }
            // `-O` and `-t` are read here but applied below, once the whole line is known:
            // the base profile seeds the set and every `-O` list layers on top, left to
            // right, so two `-O`s compose and the last element to name a feature wins.
            Arg::Short('O', attached) => {
                family_only.push(("-O", "ext"));
                feature_ops.push(args.value("-O", attached)?);
            }
            Arg::Short('t', attached) => {
                fs_type =
                    Some(parse::fs_type(&args.value("-t", attached)?).map_err(value_err("-t"))?);
            }
            Arg::Short('h', attached) => {
                Args::no_value("-h", attached)?;
                return Ok(Command::Help(Topic::Format));
            }
            Arg::Short(letter, _) => {
                return Err(UsageError::UnknownFlag {
                    command: CMD,
                    flag: format!("-{letter}"),
                });
            }
            Arg::Positional(value) => {
                if out.is_some() {
                    return Err(UsageError::UnexpectedArgument {
                        command: CMD,
                        value: value.to_string_lossy().into_owned(),
                    });
                }
                out = Some(PathBuf::from(value));
            }
        }
    }

    // The time comes from the option, or from SOURCE_DATE_EPOCH, and from nowhere else:
    // the tool does not read the clock, so an absent time is a missing input rather than
    // "now".
    let time = match time {
        Some(t) => t,
        None => match source_date_epoch {
            Some(v) => parse::seconds(&v).map_err(value_err("SOURCE_DATE_EPOCH"))?,
            None => {
                return Err(UsageError::MissingRequired {
                    command: CMD,
                    flag: "--time (or SOURCE_DATE_EPOCH)",
                });
            }
        },
    };
    // The family, and with it which of the options above apply at all. `-t` names it and
    // ext4 is what an unnamed one means, which is what keeps every ext command line that
    // worked before working unchanged.
    let fs_type = fs_type.unwrap_or_default();
    // An option belonging to the family that was not named is refused rather than passed
    // over. Silently ignoring `--journal` on a FAT format would report a volume built the
    // way it was asked for when it was not.
    for (flag, family) in &family_only {
        if *family != fs_type.family() {
            return Err(UsageError::FlagNotForFamily {
                flag,
                family,
                named: fs_type.name(),
            });
        }
    }
    // `--size auto` and a named size are one setting; `--slack` modifies only the first,
    // since a size that was named has no room to find.
    let size = match (size, fit) {
        (_, true) => Size::Fit(slack.unwrap_or_default()),
        (Some(bytes), false) => {
            if slack.is_some() {
                return Err(UsageError::SlackWithoutFit);
            }
            Size::Bytes(bytes)
        }
        (None, false) => {
            return Err(UsageError::MissingRequired {
                command: CMD,
                flag: "--size",
            });
        }
    };
    let out = out.ok_or(UsageError::MissingArgument {
        command: CMD,
        what: "output file",
    })?;
    // One source of contents, or none. Two would be a merge, which nothing here decides
    // the rules for.
    let contents = match (from_tar, from_dir) {
        (None, None) => None,
        (Some(stream), None) => Some(Contents::Tar(stream)),
        (None, Some(path)) => Some(Contents::Dir(path)),
        (Some(_), Some(_)) => return Err(UsageError::TwoSources),
    };
    // An archive carries its own ownership and an empty filesystem has nothing to own, so
    // an override with nothing to override is a mistake caught rather than ignored.
    if owner.is_some() && !matches!(contents, Some(Contents::Dir(_))) {
        return Err(UsageError::OwnerWithoutDir);
    }
    // `--atomic` is about how the destination is replaced, and `--dry-run` never opens one:
    // the run reports the plan and returns before the destination is touched. Together they
    // are a flag that decides nothing, refused for the same reason as every other inert
    // pairing — an accepted flag that changes nothing reads as one that worked.
    if atomic && dry_run {
        return Err(UsageError::AtomicWithDryRun);
    }
    // Now that the family is settled, build what only it takes.
    let target = match fs_type {
        FsType::Ext(profile) => {
            // Compose the feature set: the base profile seeds it (ext4 when no `-t` was
            // given), the size options override, and the `-O` lists layer on last, left to
            // right. A combination that must never reach disk is a request that cannot be
            // honoured, so it is refused here, by the name of the conflict, rather than deep
            // in the planner.
            let mut feature = profile.feature_set();
            if let Some(block_size) = block_size {
                feature.block_size = block_size;
            }
            if let Some(inode_size) = inode_size {
                feature.inode_size = inode_size;
            }
            for op in &feature_ops {
                feature = parse::features(feature, op).map_err(value_err("-O"))?;
            }
            feature.validate()?;

            let uuid = uuid.ok_or(UsageError::MissingRequired {
                command: CMD,
                flag: "--uuid",
            })?;
            let volume_name = match &label {
                Some(bytes) => parse::label(bytes).map_err(value_err("--label"))?,
                None => [0u8; 16],
            };
            Target::Ext(Box::new(ExtTarget {
                uuid,
                feature,
                errors,
                inodes,
                reserved,
                volume_name,
                grow,
                journal,
                fixed_time: fixed_time.map(Timestamp::from_secs),
                hash_version,
                hash_signedness,
                // The seed defaults to the UUID's bytes: an identity the caller already
                // supplied, rather than one the tool would have to invent from a random
                // source it does not have.
                hash_seed: hash_seed.unwrap_or(uuid),
            }))
        }
        FsType::Fat(request) => {
            let volume_id = volume_id.ok_or(UsageError::MissingRequired {
                command: CMD,
                flag: "--volume-id",
            })?;
            let label = match &label {
                Some(bytes) => Some(
                    VolumeLabel::from_bytes(bytes)
                        .map_err(|e| value_err("--label")(ValueError::from(e)))?,
                ),
                None => None,
            };
            Target::Fat(FatTarget {
                request,
                volume_id,
                label,
                accepted_loss,
                synthesis,
            })
        }
    };

    Ok(Command::Format(Box::new(FormatArgs {
        out,
        size,
        time: Timestamp::from_secs(time),
        contents,
        owner,
        json,
        atomic,
        dry_run,
        target,
    })))
}

/// `ferrosys inspect [options] IMAGE`.
fn inspect(args: &mut Args) -> Result<Command, UsageError> {
    const CMD: &str = "inspect";
    let mut image: Option<PathBuf> = None;
    let mut offset = 0u64;
    let mut json = false;
    let mut sarif = false;
    let mut groups = false;
    let mut quick = false;
    // Integrity by default: a filesystem is bad when its own bytes contradict each other —
    // a checksum that does not match what it covers — or when a structure the reader must
    // follow cannot be. That is the line between a filesystem that is sound and one that
    // is not.
    //
    // The threshold below it, `conformance`, means something else: valid ext4, but not the
    // form *this* tool writes. A filesystem another formatter made is exactly that, and it
    // is not thereby broken. Faulting it would make `inspect` a check on its own output
    // rather than on ext4, so `conformance` is an opt-in self-check and not the default.
    let mut fail_on = Some(Severity::Integrity);
    // Whether the threshold above was *asked for*, which the value alone cannot say: the
    // default and an explicit `--fail-on integrity` are the same `Some(Integrity)`. The
    // pairing check below needs to tell them apart, because refusing the default would refuse
    // every `--quick` run there is.
    let mut fail_on_given = false;

    while let Some(arg) = args.next()? {
        match arg {
            Arg::Long(name, attached) => {
                let flag = format!("--{name}");
                match name.as_str() {
                    "help" => {
                        Args::no_value(&flag, attached)?;
                        return Ok(Command::Help(Topic::Inspect));
                    }
                    "offset" => {
                        offset =
                            parse::size(&args.value(&flag, attached)?).map_err(value_err(&flag))?;
                    }
                    "fail-on" => {
                        fail_on = parse::fail_on(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                        fail_on_given = true;
                    }
                    "json" => {
                        Args::no_value(&flag, attached)?;
                        json = true;
                    }
                    "sarif" => {
                        Args::no_value(&flag, attached)?;
                        sarif = true;
                    }
                    "groups" => {
                        Args::no_value(&flag, attached)?;
                        groups = true;
                    }
                    "quick" => {
                        Args::no_value(&flag, attached)?;
                        quick = true;
                    }
                    _ => {
                        return Err(UsageError::UnknownFlag { command: CMD, flag });
                    }
                }
            }
            Arg::Short('h', attached) => {
                Args::no_value("-h", attached)?;
                return Ok(Command::Help(Topic::Inspect));
            }
            Arg::Short(letter, _) => {
                return Err(UsageError::UnknownFlag {
                    command: CMD,
                    flag: format!("-{letter}"),
                });
            }
            Arg::Positional(value) => {
                if image.is_some() {
                    return Err(UsageError::UnexpectedArgument {
                        command: CMD,
                        value: value.to_string_lossy().into_owned(),
                    });
                }
                image = Some(PathBuf::from(value));
            }
        }
    }

    let image = image.ok_or(UsageError::MissingArgument {
        command: CMD,
        what: "image",
    })?;
    // SARIF is a findings dialect: it projects the scan, not the description JSON and text
    // report. So it selects a different output format from --json, it needs the scan
    // --quick would skip, and it has nowhere to render the group table --groups asks for.
    // The last is refused rather than ignored for the same reason as the first two: an
    // accepted flag that changes nothing reads as one that worked, and here it would also
    // let a descriptor read error abort a run before any SARIF was emitted — the inert
    // flag suppressing the very document the caller asked for.
    if sarif && json {
        return Err(UsageError::SarifWithJson);
    }
    if sarif && quick {
        return Err(UsageError::SarifWithQuick);
    }
    if sarif && groups {
        return Err(UsageError::SarifWithGroups);
    }
    // `--fail-on` is a verdict on the scan, and `--quick` is the flag that skips the scan.
    // Together they are a gate that looks armed and cannot fire: a CI step reading
    // `--quick --fail-on structural` exits zero on a filesystem whose bytes are destroyed.
    // That is the one inert pairing with a consequence, so it is refused like the rest.
    if quick && fail_on_given {
        return Err(UsageError::FailOnWithQuick);
    }
    Ok(Command::Inspect(InspectArgs {
        image,
        offset,
        json,
        sarif,
        groups,
        quick,
        fail_on,
    }))
}

/// `ferrosys detect [options] IMAGE`.
fn detect(args: &mut Args) -> Result<Command, UsageError> {
    const CMD: &str = "detect";
    let mut image: Option<PathBuf> = None;
    let mut offset = 0u64;
    let mut json = false;

    while let Some(arg) = args.next()? {
        match arg {
            Arg::Long(name, attached) => {
                let flag = format!("--{name}");
                match name.as_str() {
                    "help" => {
                        Args::no_value(&flag, attached)?;
                        return Ok(Command::Help(Topic::Detect));
                    }
                    "offset" => {
                        offset =
                            parse::size(&args.value(&flag, attached)?).map_err(value_err(&flag))?;
                    }
                    "json" => {
                        Args::no_value(&flag, attached)?;
                        json = true;
                    }
                    _ => {
                        return Err(UsageError::UnknownFlag { command: CMD, flag });
                    }
                }
            }
            Arg::Short('h', attached) => {
                Args::no_value("-h", attached)?;
                return Ok(Command::Help(Topic::Detect));
            }
            Arg::Short(letter, _) => {
                return Err(UsageError::UnknownFlag {
                    command: CMD,
                    flag: format!("-{letter}"),
                });
            }
            Arg::Positional(value) => {
                if image.is_some() {
                    return Err(UsageError::UnexpectedArgument {
                        command: CMD,
                        value: value.to_string_lossy().into_owned(),
                    });
                }
                image = Some(PathBuf::from(value));
            }
        }
    }

    let image = image.ok_or(UsageError::MissingArgument {
        command: CMD,
        what: "image",
    })?;
    Ok(Command::Detect(DetectArgs {
        image,
        offset,
        json,
    }))
}

/// `ferrosys identity [options] IMAGE`.
fn identity(args: &mut Args) -> Result<Command, UsageError> {
    const CMD: &str = "identity";
    let mut image: Option<PathBuf> = None;
    let mut uuid: Option<[u8; 16]> = None;
    let mut volume_name: Option<[u8; 16]> = None;
    let mut set_checksum_seed = false;
    let mut json = false;

    while let Some(arg) = args.next()? {
        match arg {
            Arg::Long(name, attached) => {
                let flag = format!("--{name}");
                match name.as_str() {
                    "help" => {
                        Args::no_value(&flag, attached)?;
                        return Ok(Command::Help(Topic::Identity));
                    }
                    "uuid" => {
                        uuid = Some(
                            parse::hex16(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    // The label is the argument's bytes, as it is for a format: a label is
                    // a byte field on disk rather than text.
                    "label" => {
                        let value = args.value(&flag, attached)?;
                        volume_name =
                            Some(parse::label(os::bytes(&value)).map_err(value_err(&flag))?);
                    }
                    "set-checksum-seed" => {
                        Args::no_value(&flag, attached)?;
                        set_checksum_seed = true;
                    }
                    "json" => {
                        Args::no_value(&flag, attached)?;
                        json = true;
                    }
                    _ => {
                        return Err(UsageError::UnknownFlag { command: CMD, flag });
                    }
                }
            }
            Arg::Short('h', attached) => {
                Args::no_value("-h", attached)?;
                return Ok(Command::Help(Topic::Identity));
            }
            Arg::Short(letter, _) => {
                return Err(UsageError::UnknownFlag {
                    command: CMD,
                    flag: format!("-{letter}"),
                });
            }
            Arg::Positional(value) => {
                if image.is_some() {
                    return Err(UsageError::UnexpectedArgument {
                        command: CMD,
                        value: value.to_string_lossy().into_owned(),
                    });
                }
                image = Some(PathBuf::from(value));
            }
        }
    }

    let image = image.ok_or(UsageError::MissingArgument {
        command: CMD,
        what: "image",
    })?;
    // A run that would write nothing is a command line that meant to say something and
    // did not, so it is a usage error rather than a silent success.
    if uuid.is_none() && volume_name.is_none() && !set_checksum_seed {
        return Err(UsageError::MissingRequired {
            command: CMD,
            flag: "--uuid, --label, or --set-checksum-seed",
        });
    }
    Ok(Command::Identity(IdentityArgs {
        image,
        uuid,
        volume_name,
        set_checksum_seed,
        json,
    }))
}

/// `ferrosys extract [options] IMAGE`.
fn extract(args: &mut Args) -> Result<Command, UsageError> {
    const CMD: &str = "extract";
    let mut image: Option<PathBuf> = None;
    let mut offset = 0u64;
    let mut to_tar: Option<Stream> = None;
    let mut to_dir: Option<PathBuf> = None;
    let mut skip_privileged = false;
    let mut cat: Option<Vec<u8>> = None;
    let mut stat: Option<Vec<u8>> = None;
    let mut list = false;
    let mut json = false;
    let mut max_file_bytes: Option<u64> = None;
    let mut atomic = false;
    let mut strict = false;
    let mut synthesis = Synthesis::new();

    while let Some(arg) = args.next()? {
        match arg {
            Arg::Long(name, attached) => {
                let flag = format!("--{name}");
                match name.as_str() {
                    "help" => {
                        Args::no_value(&flag, attached)?;
                        return Ok(Command::Help(Topic::Extract));
                    }
                    "offset" => {
                        offset =
                            parse::size(&args.value(&flag, attached)?).map_err(value_err(&flag))?;
                    }
                    "to-tar" => to_tar = Some(Stream::from_value(args.value(&flag, attached)?)),
                    "to-dir" => to_dir = Some(PathBuf::from(args.value(&flag, attached)?)),
                    "skip-privileged" => {
                        Args::no_value(&flag, attached)?;
                        skip_privileged = true;
                    }
                    // A path inside the image is a byte string, not text: it is taken as
                    // the bytes the argument holds, and never rendered through a
                    // character encoding on the way in.
                    "cat" => {
                        let value = args.value(&flag, attached)?;
                        cat = Some(os::bytes(&value).to_vec());
                    }
                    // A path inside the image, taken as bytes for the same reason `--cat`'s
                    // is: a name in a filesystem is a byte string, not text.
                    "stat" => {
                        let value = args.value(&flag, attached)?;
                        stat = Some(os::bytes(&value).to_vec());
                    }
                    "max-file-bytes" => {
                        max_file_bytes = Some(
                            parse::size(&args.value(&flag, attached)?).map_err(value_err(&flag))?,
                        );
                    }
                    "list" => {
                        Args::no_value(&flag, attached)?;
                        list = true;
                    }
                    "json" => {
                        Args::no_value(&flag, attached)?;
                        json = true;
                    }
                    "atomic" => {
                        Args::no_value(&flag, attached)?;
                        atomic = true;
                    }
                    "strict" => {
                        Args::no_value(&flag, attached)?;
                        strict = true;
                    }
                    // What to assume where the filesystem records nothing. Named "assume"
                    // rather than "set", because a value here never overrides what an image
                    // does hold.
                    "assume-owner" => {
                        let (uid, gid) = parse::owner(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                        synthesis = synthesis.owner(uid, gid);
                    }
                    "assume-modes" => {
                        let (file, dir) = parse::modes(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                        synthesis = synthesis.modes(file, dir);
                    }
                    _ => {
                        return Err(UsageError::UnknownFlag { command: CMD, flag });
                    }
                }
            }
            Arg::Short('h', attached) => {
                Args::no_value("-h", attached)?;
                return Ok(Command::Help(Topic::Extract));
            }
            Arg::Short(letter, _) => {
                return Err(UsageError::UnknownFlag {
                    command: CMD,
                    flag: format!("-{letter}"),
                });
            }
            Arg::Positional(value) => {
                if image.is_some() {
                    return Err(UsageError::UnexpectedArgument {
                        command: CMD,
                        value: value.to_string_lossy().into_owned(),
                    });
                }
                image = Some(PathBuf::from(value));
            }
        }
    }

    let image = image.ok_or(UsageError::MissingArgument {
        command: CMD,
        what: "image",
    })?;
    // Exactly one artifact per run: the standard output carries a tar stream, a file's
    // bytes, one path's metadata, or a listing, and the tool is told which.
    let mode = match (to_tar, to_dir, cat, stat, list) {
        (Some(stream), None, None, None, false) => ExtractMode::ToTar(stream),
        (None, Some(path), None, None, false) => ExtractMode::ToDir {
            path,
            skip_privileged,
        },
        (None, None, Some(path), None, false) => ExtractMode::Cat(path),
        (None, None, None, Some(path), false) => ExtractMode::Stat { path, json },
        (None, None, None, None, true) => ExtractMode::List { json },
        _ => return Err(UsageError::ExtractMode),
    };
    // `--skip-privileged` is about the parts of a tree only a privileged process can write,
    // so it belongs to the mode that writes one. Accepting it elsewhere would promise
    // something no other mode does.
    if skip_privileged && !matches!(mode, ExtractMode::ToDir { .. }) {
        return Err(UsageError::SkipPrivilegedWithoutDir);
    }
    // JSON is a rendering of a report, so it goes with the two modes that produce one. A
    // tar stream and a file's bytes are not reports and have no JSON form.
    if json && !matches!(mode, ExtractMode::List { .. } | ExtractMode::Stat { .. }) {
        return Err(UsageError::JsonWithoutReport);
    }
    // `--atomic` is about what a destination holds when a run fails part-way, so it needs
    // a destination. Every other mode writes to the standard output, which has no rename
    // to make it whole, and accepting the flag there would promise something the run
    // cannot do.
    if atomic && !matches!(mode, ExtractMode::ToTar(Stream::File(_))) {
        return Err(UsageError::AtomicWithoutFile);
    }

    Ok(Command::Extract(ExtractArgs {
        image,
        strict,
        offset,
        mode,
        max_file_bytes,
        atomic,
        synthesis,
    }))
}

#[cfg(test)]
mod tests {
    /// What an extraction assumes where the filesystem records nothing.
    #[test]
    fn the_assume_flags_set_what_a_read_invents() {
        // Nothing named is the conservative default: owned by root, and never more
        // permissive than a plain file and a searchable directory.
        match line("extract image.img --list").expect("parses") {
            Command::Extract(a) => assert_eq!(a.synthesis, Synthesis::new()),
            other => panic!("expected extract, got {other:?}"),
        }
        match line("extract image.img --list --assume-owner 1000:100 --assume-modes 600:700")
            .expect("parses")
        {
            Command::Extract(a) => {
                assert_eq!(a.synthesis.uid, 1000);
                assert_eq!(a.synthesis.gid, 100);
                assert_eq!(a.synthesis.file_mode, 0o600);
                assert_eq!(a.synthesis.dir_mode, 0o700);
            }
            other => panic!("expected extract, got {other:?}"),
        }
        // A value neither flag can read is a usage error rather than a silent default,
        // since a default here decides what a whole tree is owned by.
        for bad in [
            "extract image.img --list --assume-owner 1000",
            "extract image.img --list --assume-modes 644",
            "extract image.img --list --assume-modes 10000:755",
        ] {
            assert!(line(bad).is_err(), "{bad} should be a usage error");
        }
    }

    use super::*;
    use ferrosys::Property;
    use ferrosys::ext::Profile;
    use ferrosys::fat::FatType;

    /// Parse a command line written as it would be typed.
    fn line(s: &str) -> Result<Command, UsageError> {
        let argv = s.split(' ').filter(|t| !t.is_empty()).map(OsString::from);
        parse(argv.collect(), None)
    }

    /// The `format` arguments a line parses to, for the cases that must parse.
    fn fmt(s: &str) -> FormatArgs {
        match line(s).expect("the line parses") {
            Command::Format(a) => *a,
            other => panic!("expected format, got {other:?}"),
        }
    }

    /// The ext half of a `format` line, for the cases that must reach the ext family.
    fn ext(s: &str) -> ExtTarget {
        match fmt(s).target {
            Target::Ext(target) => *target,
            other => panic!("expected an ext target, got {other:?}"),
        }
    }

    /// The FAT half of a `format` line, for the cases that must reach the FAT family.
    fn fat(s: &str) -> FatTarget {
        match fmt(s).target {
            Target::Fat(target) => target,
            other => panic!("expected a fat target, got {other:?}"),
        }
    }

    const UUID: &str = "f0e17055-0000-4000-8000-000000000000";
    const UUID_BYTES: [u8; 16] = [
        0xf0, 0xe1, 0x70, 0x55, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn format_takes_its_required_inputs() {
        let text = format!("format --size 512M --uuid {UUID} --time 1700000000 out.img");
        let a = fmt(&text);
        assert_eq!(a.out, PathBuf::from("out.img"));
        assert_eq!(a.size, Size::Bytes(512 << 20));
        assert_eq!(a.time, Timestamp::from_secs(1_700_000_000));
        assert_eq!(a.contents, None);
        assert_eq!(a.owner, None);
        assert!(!a.json);

        // Naming no type writes ext4, so the identity and the feature set are ext's.
        let target = ext(&text);
        assert_eq!(target.uuid, UUID_BYTES);
        // The hash seed defaults to the UUID: an identity the caller supplied, rather
        // than one the tool would have had to invent.
        assert_eq!(target.hash_seed, UUID_BYTES);
        assert_eq!(target.feature, FeatureSet::DEFAULT);
    }

    #[test]
    fn a_size_is_named_or_found_and_slack_belongs_to_the_second() {
        // `auto` is not a byte count and never becomes one here: the size it stands for is
        // decided by the library, from contents this parser never sees.
        let auto = fmt(&format!(
            "format --size auto --uuid {UUID} --time 1 --from-dir staging out.img"
        ));
        assert_eq!(auto.size, Size::Fit(Slack::None));

        for (value, want) in [
            ("20%", Slack::Share(2000)),
            ("1.5%", Slack::Share(150)),
            ("64M", Slack::Bytes(64 << 20)),
            ("0%", Slack::Share(0)),
        ] {
            let a = fmt(&format!(
                "format --size auto --slack {value} --uuid {UUID} --time 1 out.img"
            ));
            assert_eq!(a.size, Size::Fit(want), "--slack {value}");
        }

        // The two forms are one setting, so the last --size wins whichever form it takes.
        let named = fmt(&format!(
            "format --size auto --size 64M --uuid {UUID} --time 1 out.img"
        ));
        assert_eq!(named.size, Size::Bytes(64 << 20));
        let found = fmt(&format!(
            "format --size 64M --size auto --uuid {UUID} --time 1 out.img"
        ));
        assert_eq!(found.size, Size::Fit(Slack::None));

        // A named size has no room to find, so --slack over one is a mistake caught rather
        // than ignored — including when a later --size takes the `auto` away.
        for line_text in [
            format!("format --size 64M --slack 20% --uuid {UUID} --time 1 out.img"),
            format!("format --size auto --slack 20% --size 64M --uuid {UUID} --time 1 out.img"),
        ] {
            assert_eq!(
                line(&line_text).unwrap_err(),
                UsageError::SlackWithoutFit,
                "{line_text}"
            );
        }

        // A share past what the library will search for is refused by name.
        let over = format!("format --size auto --slack 95% --uuid {UUID} --time 1 out.img");
        assert!(
            matches!(
                line(&over),
                Err(UsageError::Value { ref flag, source: ValueError::OutOfRange(_) })
                    if flag == "--slack"
            ),
            "a 95% share should be out of range"
        );
        // And a value that is neither a percentage nor a byte count.
        let bad = format!("format --size auto --slack lots --uuid {UUID} --time 1 out.img");
        assert!(matches!(line(&bad), Err(UsageError::Value { .. })));
    }

    #[test]
    fn format_requires_the_inputs_the_bytes_depend_on() {
        for (line_text, missing) in [
            (
                "format --uuid f0e17055000040008000000000000000 --time 1 o.img",
                "--size",
            ),
            ("format --size 64M --time 1 o.img", "--uuid"),
        ] {
            match line(line_text) {
                Err(UsageError::MissingRequired { flag, .. }) => assert_eq!(flag, missing),
                other => panic!("expected {missing} to be required, got {other:?}"),
            }
        }
        // The time may come from the environment instead, and from nowhere else: there is
        // no clock to fall back on.
        let argv = "format --size 64M --uuid f0e17055000040008000000000000000 o.img";
        assert!(matches!(
            line(argv),
            Err(UsageError::MissingRequired { .. })
        ));
        let from_env = parse(
            argv.split(' ').map(OsString::from).collect(),
            Some(OsString::from("1700000000")),
        );
        match from_env.expect("SOURCE_DATE_EPOCH supplies the time") {
            Command::Format(a) => assert_eq!(a.time, Timestamp::from_secs(1_700_000_000)),
            other => panic!("expected format, got {other:?}"),
        }
        // An option always wins over the environment.
        let both = parse(
            format!("format --size 64M --uuid {UUID} --time 42 o.img")
                .split(' ')
                .map(OsString::from)
                .collect(),
            Some(OsString::from("1700000000")),
        );
        match both.expect("parses") {
            Command::Format(a) => assert_eq!(a.time, Timestamp::from_secs(42)),
            other => panic!("expected format, got {other:?}"),
        }
    }

    #[test]
    fn format_takes_one_source_of_contents() {
        let tar = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 --from-tar rootfs.tar out.img"
        ));
        assert_eq!(
            tar.contents,
            Some(Contents::Tar(Stream::File(PathBuf::from("rootfs.tar"))))
        );
        let dash = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 --from-tar - out.img"
        ));
        assert_eq!(dash.contents, Some(Contents::Tar(Stream::Std)));
        let dir = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 --from-dir staging out.img"
        ));
        assert_eq!(dir.contents, Some(Contents::Dir(PathBuf::from("staging"))));

        // Two sources would be a merge, and nothing here decides the rules for one.
        assert_eq!(
            line(&format!(
                "format --size 64M --uuid {UUID} --time 1 --from-tar r.tar --from-dir d out.img"
            ))
            .unwrap_err(),
            UsageError::TwoSources
        );
    }

    #[test]
    fn format_takes_an_ownership_override_for_a_walked_tree() {
        let a = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 --from-dir staging --owner 0:0 out.img"
        ));
        assert_eq!(a.owner, Some((0, 0)));
        let a = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 --from-dir staging --owner 1000:100 out.img"
        ));
        assert_eq!(a.owner, Some((1000, 100)));

        // An archive carries its own ownership and an empty filesystem has none to
        // override, so the option has nothing to apply to.
        for line_text in [
            format!("format --size 64M --uuid {UUID} --time 1 --owner 0:0 out.img"),
            format!(
                "format --size 64M --uuid {UUID} --time 1 --from-tar r.tar --owner 0:0 out.img"
            ),
        ] {
            assert_eq!(line(&line_text).unwrap_err(), UsageError::OwnerWithoutDir);
        }

        // Both halves are required, and each must fit the on-disk field.
        for bad in ["0", "0:", ":0", "root:root", "-1:0", "4294967296:0"] {
            assert!(
                matches!(
                    line(&format!(
                        "format --size 64M --uuid {UUID} --time 1 --from-dir d --owner {bad} out.img"
                    )),
                    Err(UsageError::Value {
                        source: ValueError::NotAnOwner(_),
                        ..
                    })
                ),
                "--owner {bad} should be a usage error"
            );
        }
    }

    #[test]
    fn format_folds_the_feature_options_together() {
        let a = ext(&format!(
            "format --size 64M --uuid {UUID} --time 1 --block-size 1024 \
             --inode-size 128 -O ^has_journal -O ^orphan_file,^metadata_csum_seed \
             -O ^metadata_csum out.img"
        ));
        assert_eq!(a.feature.block_size, 1024);
        assert_eq!(a.feature.inode_size, 128);
        assert!(!a.feature.has_journal());
        assert!(!a.feature.has_metadata_csum());
        // Two `-O` options compose: the second applies to what the first left.
        assert!(!a.feature.has_orphan_file());
        assert!(a.feature.has_extents(), "the rest of the profile is intact");
    }

    #[test]
    fn format_seeds_the_base_profile() {
        // Each `-t`/`--type` seeds the whole feature set from that profile's baseline.
        let ext2 = ext(&format!(
            "format --size 64M --uuid {UUID} --time 1 -t ext2 out.img"
        ));
        assert_eq!(ext2.feature, FeatureSet::EXT2);
        assert_eq!(Profile::of(ext2.feature), Profile::Ext2);
        let ext3 = ext(&format!(
            "format --size 64M --uuid {UUID} --time 1 --type ext3 out.img"
        ));
        assert_eq!(ext3.feature, FeatureSet::EXT3);
        // Naming no profile selects ext4, so the flag is an override rather than a
        // requirement.
        let ext4 = ext(&format!("format --size 64M --uuid {UUID} --time 1 out.img"));
        assert_eq!(ext4.feature, FeatureSet::DEFAULT);
        assert_eq!(Profile::of(ext4.feature), Profile::Ext4);
    }

    #[test]
    fn the_base_profile_seeds_and_o_layers_on_top_in_any_order() {
        // `-O` composes over the profile whichever came first on the line: the profile is
        // the base, the `-O` deltas layer on last. A journal over the ext2 baseline is ext3.
        let a = ext(&format!(
            "format --size 64M --uuid {UUID} --time 1 -t ext2 -O has_journal out.img"
        ));
        let b = ext(&format!(
            "format --size 64M --uuid {UUID} --time 1 -O has_journal -t ext2 out.img"
        ));
        assert_eq!(
            a.feature, b.feature,
            "the order of -t and -O does not matter"
        );
        assert_eq!(a.feature, FeatureSet::EXT3);
        assert_eq!(Profile::of(a.feature), Profile::Ext3);

        // The size options override the profile's baseline sizes, in any position.
        let sized = ext(&format!(
            "format --size 64M --uuid {UUID} --time 1 --block-size 1024 -t ext2 out.img"
        ));
        assert_eq!(sized.feature.block_size, 1024);
        assert_eq!(Profile::of(sized.feature), Profile::Ext2);

        // A name outside the family is a usage error, not a silent fallback.
        assert!(matches!(
            line(&format!(
                "format --size 64M --uuid {UUID} --time 1 -t ext5 out.img"
            )),
            Err(UsageError::Value { .. })
        ));
    }

    #[test]
    fn a_fat_format_takes_this_family_s_identity_and_its_label() {
        let a = fat("format --size 512M --volume-id 1A2B-3C4D --time 1 -t fat32 esp.img");
        assert_eq!(a.request, FatTypeRequest::Exactly(FatType::Fat32));
        assert_eq!(a.volume_id, 0x1a2b_3c4d);
        assert_eq!(a.label, None, "a volume with no label carries none");
        // Nothing may be lost until the caller has said what may.
        assert!(a.accepted_loss.is_empty());
        // The point a loss is measured against, at the conservative default: a root-owned
        // `0644`/`0755` tree survives, so nothing about it is lost.
        assert_eq!(a.synthesis, Synthesis::new());

        // The label goes through this family's own rules, which upper-case it into the
        // eleven bytes both places that store it hold.
        let named =
            fat("format --size 512M --volume-id 00000001 --time 1 -t fat32 --label esp e.img");
        assert_eq!(
            named.label.expect("a label was given").as_bytes(),
            b"ESP        "
        );
        // Twelve bytes is one more than the field holds, and it is refused rather than
        // truncated — the tool never writes a name the caller did not give it.
        assert!(matches!(
            line(
                "format --size 512M --volume-id 00000001 --time 1 -t fat32 --label ABCDEFGHIJKL e.img"
            ),
            Err(UsageError::Value {
                source: ValueError::NotAFatLabel(_),
                ..
            })
        ));
    }

    #[test]
    fn a_format_refuses_the_other_family_s_options_wherever_the_type_appears() {
        // Each family names its own identity, so neither flag reaches the other. The
        // refusal names the option and both families rather than reporting an unknown flag,
        // which would be wrong: the option exists.
        assert_eq!(
            line("format --size 512M --uuid f0e17055-0000-4000-8000-000000000000 --time 1 -t fat32 o.img")
                .unwrap_err(),
            UsageError::FlagNotForFamily {
                flag: "--uuid",
                family: "ext",
                named: "fat32",
            }
        );
        assert_eq!(
            line(&format!(
                "format --size 512M --volume-id 00000001 --uuid {UUID} --time 1 out.img"
            ))
            .unwrap_err(),
            UsageError::FlagNotForFamily {
                flag: "--volume-id",
                family: "fat",
                named: "ext4",
            }
        );

        // Position does not matter: the whole line is read before the family decides which
        // options applied, so `-t` disqualifies an option that came before it as well as
        // one that came after.
        for text in [
            "format --size 512M --volume-id 00000001 --time 1 -t fat32 --journal 4096 o.img",
            "format --size 512M --volume-id 00000001 --time 1 --journal 4096 -t fat32 o.img",
        ] {
            assert!(
                matches!(
                    line(text).unwrap_err(),
                    UsageError::FlagNotForFamily {
                        flag: "--journal",
                        ..
                    }
                ),
                "{text}"
            );
        }

        // And the identity each family does take is required, by its own name.
        assert_eq!(
            line("format --size 512M --time 1 -t fat32 o.img").unwrap_err(),
            UsageError::MissingRequired {
                command: "format",
                flag: "--volume-id",
            }
        );
        assert_eq!(
            line("format --size 512M --time 1 out.img").unwrap_err(),
            UsageError::MissingRequired {
                command: "format",
                flag: "--uuid",
            }
        );
    }

    #[test]
    fn a_fat_format_takes_the_losses_it_is_told_it_may_take() {
        let a = fat("format --size 512M --volume-id 00000001 --time 1 -t fat32 \
             --accept-loss ownership,permissions --assume-owner 1000:1000 \
             --assume-modes 600:700 o.img");
        assert!(a.accepted_loss.contains(Property::Ownership));
        assert!(a.accepted_loss.contains(Property::Permissions));
        assert!(
            !a.accepted_loss.contains(Property::Kind),
            "a symbolic link still stops the build"
        );
        // The synthesis is what a read would fill in, so naming it here is what makes the
        // two ends of a round trip agree about which values survived.
        assert_eq!(a.synthesis.uid, 1000);
        assert_eq!(a.synthesis.gid, 1000);
        assert_eq!(a.synthesis.file_mode, 0o600);
        assert_eq!(a.synthesis.dir_mode, 0o700);
    }

    #[test]
    fn a_fat_format_finds_its_size_like_any_other_family() {
        // `--size auto` and `--slack` belong to no family: what a candidate is measured in
        // differs between them, and asking for the smallest filesystem that holds a tree
        // does not.
        let args = fmt(
            "format --size auto --slack 20% --volume-id 00000001 --time 1 -t fat32 \
             --from-dir staging o.img",
        );
        assert_eq!(args.size, Size::Fit(Slack::Share(2000)));

        let bare = fmt(
            "format --size auto --volume-id 00000001 --time 1 -t fat16 --from-dir staging o.img",
        );
        assert_eq!(bare.size, Size::Fit(Slack::None));
    }

    #[test]
    fn format_takes_the_sizing_and_label_options() {
        let a = ext(&format!(
            "format --size 256M --uuid {UUID} --time 1 --inodes 5000 \
             --reserved-percent 1.5 --label rootfs out.img"
        ));
        assert_eq!(a.inodes, InodeCount::Count(5000));
        assert_eq!(
            a.reserved,
            ReservedRatio::from_hundredths_of_percent(150).unwrap()
        );
        assert_eq!(&a.volume_name[..6], b"rootfs");
        assert_eq!(a.volume_name[6], 0, "the label is NUL-padded");

        // The two inode knobs share one setting; the last to appear wins.
        let a = ext(&format!(
            "format --size 256M --uuid {UUID} --time 1 --inodes 5000 --bytes-per-inode 65536 out.img"
        ));
        assert_eq!(
            a.inodes,
            InodeCount::BytesPerInode(std::num::NonZeroU64::new(65536).unwrap())
        );

        // The defaults when none are given: size-driven inodes, 5% reserved, no label.
        let a = ext(&format!("format --size 64M --uuid {UUID} --time 1 out.img"));
        assert_eq!(a.inodes, InodeCount::Auto);
        assert_eq!(a.reserved, ReservedRatio::DEFAULT);
        assert_eq!(a.volume_name, [0u8; 16]);
    }

    #[test]
    fn format_takes_the_error_behavior_by_name() {
        // The three `mke2fs -e` names map to the three policies; the default is continue.
        for (name, want) in [
            ("continue", ErrorBehavior::Continue),
            ("remount-ro", ErrorBehavior::RemountReadOnly),
            ("panic", ErrorBehavior::Panic),
        ] {
            let a = ext(&format!(
                "format --size 64M --uuid {UUID} --time 1 --errors {name} out.img"
            ));
            assert_eq!(a.errors, want, "--errors {name}");
        }
        let a = ext(&format!("format --size 64M --uuid {UUID} --time 1 out.img"));
        assert_eq!(a.errors, ErrorBehavior::Continue, "the default is continue");

        // A name outside the set is a usage error, not a silent fallback to the default.
        let err = line(&format!(
            "format --size 64M --uuid {UUID} --time 1 --errors halt out.img"
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            UsageError::Value {
                source: ValueError::NotOneOf { .. },
                ..
            }
        ));
    }

    #[test]
    fn format_refuses_an_over_long_label_and_a_bad_percent() {
        // A label past sixteen bytes is a usage error, not a silent truncation.
        let err = line(&format!(
            "format --size 64M --uuid {UUID} --time 1 --label 0123456789abcdefX out.img"
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            UsageError::Value {
                source: ValueError::LabelTooLong { len: 17 },
                ..
            }
        ));

        // A reserved percentage past 50, or finer than two decimals, or signed, is refused.
        for bad in ["60", "1.234", "-1"] {
            let err = line(&format!(
                "format --size 64M --uuid {UUID} --time 1 --reserved-percent {bad} out.img"
            ))
            .unwrap_err();
            assert!(
                matches!(err, UsageError::Value { .. }),
                "--reserved-percent {bad} should be a usage error"
            );
        }
    }

    #[test]
    fn a_feature_set_that_cannot_reach_disk_is_refused_by_name() {
        // The orphan file's entries are journalled, so dropping the journal alone leaves
        // a filesystem that must never be written. The conflict is named at the command
        // line rather than deep in the planner.
        let err = line(&format!(
            "format --size 64M --uuid {UUID} --time 1 -O ^has_journal out.img"
        ))
        .unwrap_err();
        assert_eq!(
            err,
            UsageError::Feature(FeatureError::OrphanFileWithoutJournal)
        );
    }

    #[test]
    fn a_value_is_never_read_as_an_option() {
        // `--offset -1` gives `-1` to the size parser, which refuses it. Nothing looks
        // ahead at a value to decide whether it is a flag.
        let err = line("inspect --offset -1 image.img").unwrap_err();
        assert!(matches!(
            err,
            UsageError::Value {
                source: ValueError::NotASize(_),
                ..
            }
        ));
        // A value attached with `=` is the same value.
        assert!(matches!(
            line("inspect --offset=-1 image.img").unwrap_err(),
            UsageError::Value { .. }
        ));
    }

    #[test]
    fn double_dash_ends_the_options() {
        // A file named like an option is still a file.
        let a = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 -- --weird.img"
        ));
        assert_eq!(a.out, PathBuf::from("--weird.img"));
    }

    #[test]
    fn double_dash_in_value_position_is_the_options_value() {
        // An option that needs a value takes the next token verbatim, even `--`: it does
        // not end the options there. So `--label -- out.img` gives the label the value
        // `--` and leaves `out.img` the output, matching getopt and the value() rule.
        let text = format!("format --size 64M --uuid {UUID} --time 1 --label -- out.img");
        assert_eq!(fmt(&text).out, PathBuf::from("out.img"));
        let a = ext(&text);
        assert_eq!(&a.volume_name[..2], b"--");
        assert_eq!(a.volume_name[2], 0, "the label is exactly `--`, NUL-padded");
    }

    #[test]
    fn unknown_and_malformed_options_are_usage_errors() {
        assert!(matches!(
            line("format --nonesuch out.img"),
            Err(UsageError::UnknownFlag { .. })
        ));
        assert!(matches!(
            parse(Vec::new(), None),
            Err(UsageError::NoCommand)
        ));
        assert!(matches!(
            line("frobnicate"),
            Err(UsageError::UnknownCommand(_))
        ));
        assert!(matches!(
            line("inspect --offset"),
            Err(UsageError::MissingValue(_))
        ));
        // An option that takes no value is not a place to put one.
        assert!(matches!(
            line("inspect --json=yes image.img"),
            Err(UsageError::UnexpectedValue(_))
        ));
        assert!(matches!(
            line("inspect"),
            Err(UsageError::MissingArgument { .. })
        ));
        assert!(matches!(
            line("inspect a.img b.img"),
            Err(UsageError::UnexpectedArgument { .. })
        ));
    }

    #[test]
    fn a_malformed_token_renders_without_a_stray_command_colon() {
        // The tokenizer rejects a token that is not a well-formed option before any
        // subcommand claims it, so its UnknownFlag carries no command. It renders
        // "-1: not an option", not ": -1: not an option" — which under the tool-name
        // prefix would read "ferrosys: : -1: not an option" with a stray colon.
        let err = line("format -1 out.img").expect_err("a non-alpha short flag is rejected");
        assert_eq!(err.to_string(), "-1: not an option");

        // A well-formed flag a command does not take still names the command.
        let err = line("format --nonesuch out.img").expect_err("an unknown flag is rejected");
        assert_eq!(err.to_string(), "format: --nonesuch: not an option");
    }

    #[test]
    fn inspect_scans_by_default_and_faults_a_filesystem_that_is_unsound() {
        match line("inspect image.img").expect("parses") {
            Command::Inspect(a) => {
                assert!(!a.quick, "a scan is what makes a bad filesystem reportable");
                // Integrity, not conformance: a filesystem another formatter wrote is not
                // this tool's output, and it is not thereby broken.
                assert_eq!(a.fail_on, Some(Severity::Integrity));
                assert_eq!(a.offset, 0);
            }
            other => panic!("expected inspect, got {other:?}"),
        }
        // The threshold moves in every direction: down to the self-check, up so that only
        // a destroyed filesystem is bad, and away entirely so that nothing is.
        match line("inspect --fail-on conformance image.img").expect("parses") {
            Command::Inspect(a) => assert_eq!(a.fail_on, Some(Severity::Conformance)),
            other => panic!("expected inspect, got {other:?}"),
        }
        match line("inspect --fail-on structural image.img").expect("parses") {
            Command::Inspect(a) => assert_eq!(a.fail_on, Some(Severity::Structural)),
            other => panic!("expected inspect, got {other:?}"),
        }
        match line("inspect --fail-on never image.img").expect("parses") {
            Command::Inspect(a) => assert_eq!(a.fail_on, None),
            other => panic!("expected inspect, got {other:?}"),
        }
    }

    #[test]
    fn inspect_sarif_is_a_findings_dialect() {
        // The flag selects the SARIF projection and nothing else changes.
        match line("inspect --sarif image.img").expect("parses") {
            Command::Inspect(a) => {
                assert!(a.sarif);
                assert!(!a.json);
                assert!(!a.quick);
            }
            other => panic!("expected inspect, got {other:?}"),
        }
        // SARIF and JSON are two output formats: asking for both is a usage error, not a
        // silent precedence.
        assert_eq!(
            line("inspect --sarif --json image.img").unwrap_err(),
            UsageError::SarifWithJson
        );
        // SARIF reports the scan's findings, so it cannot pair with the flag that skips the
        // scan.
        assert_eq!(
            line("inspect --sarif --quick image.img").unwrap_err(),
            UsageError::SarifWithQuick
        );
        // Nor with the one that asks for a group table, which a findings log has no place
        // to render. Accepting it would read as having worked while changing nothing.
        assert_eq!(
            line("inspect --sarif --groups image.img").unwrap_err(),
            UsageError::SarifWithGroups
        );
    }

    #[test]
    fn extract_produces_exactly_one_thing() {
        match line("extract --to-tar - image.img").expect("parses") {
            Command::Extract(a) => assert_eq!(a.mode, ExtractMode::ToTar(Stream::Std)),
            other => panic!("expected extract, got {other:?}"),
        }
        match line("extract --cat /etc/hostname image.img").expect("parses") {
            Command::Extract(a) => {
                assert_eq!(a.mode, ExtractMode::Cat(b"/etc/hostname".to_vec()));
            }
            other => panic!("expected extract, got {other:?}"),
        }
        match line("extract --list --json image.img").expect("parses") {
            Command::Extract(a) => assert_eq!(a.mode, ExtractMode::List { json: true }),
            other => panic!("expected extract, got {other:?}"),
        }
        // Nothing, or more than one thing, is a usage error rather than a guess.
        assert_eq!(
            line("extract image.img").unwrap_err(),
            UsageError::ExtractMode
        );
        assert_eq!(
            line("extract --list --cat /x image.img").unwrap_err(),
            UsageError::ExtractMode
        );
        // Bytes have no JSON form.
        assert_eq!(
            line("extract --cat /x --json image.img").unwrap_err(),
            UsageError::JsonWithoutReport
        );
    }

    #[test]
    fn extract_writes_a_tree_and_the_skip_belongs_to_it() {
        match line("extract --to-dir unpacked image.img").expect("parses") {
            Command::Extract(a) => assert_eq!(
                a.mode,
                ExtractMode::ToDir {
                    path: "unpacked".into(),
                    skip_privileged: false,
                }
            ),
            other => panic!("expected extract, got {other:?}"),
        }
        match line("extract --to-dir unpacked --skip-privileged image.img").expect("parses") {
            Command::Extract(a) => assert_eq!(
                a.mode,
                ExtractMode::ToDir {
                    path: "unpacked".into(),
                    skip_privileged: true,
                }
            ),
            other => panic!("expected extract, got {other:?}"),
        }
        // A tree and an archive are two artifacts, and a run produces one.
        assert_eq!(
            line("extract --to-dir d --to-tar t image.img").unwrap_err(),
            UsageError::ExtractMode
        );
        // A tree is not a report, so it has no JSON form; and it is not a file, so there is
        // nothing to rename into place.
        assert_eq!(
            line("extract --to-dir d --json image.img").unwrap_err(),
            UsageError::JsonWithoutReport
        );
        assert_eq!(
            line("extract --to-dir d --atomic image.img").unwrap_err(),
            UsageError::AtomicWithoutFile
        );
        // `--atomic` decides how a destination is replaced, and `--dry-run` opens none. The
        // pair is the same inert-flag mistake, refused rather than passed over.
        assert_eq!(
            line(
                "format --size 16M --uuid f0e17055-0000-4000-8000-000000000000 \
                  --time 1700000000 --dry-run --atomic out.img"
            )
            .unwrap_err(),
            UsageError::AtomicWithDryRun
        );
        // And the one inert pairing with a consequence: a verdict on a scan that was
        // skipped is a CI gate that looks armed and exits zero on a destroyed filesystem.
        assert_eq!(
            line("inspect --quick --fail-on structural image.img").unwrap_err(),
            UsageError::FailOnWithQuick
        );
        // The default threshold is not a request for one, so `--quick` alone still parses.
        assert!(line("inspect --quick image.img").is_ok());
        // Nor is an explicit threshold a problem without `--quick`.
        assert!(line("inspect --fail-on structural image.img").is_ok());
        // And the skip is about writing a tree, so it goes nowhere else.
        for spelling in [
            "extract --to-tar out.tar --skip-privileged image.img",
            "extract --list --skip-privileged image.img",
        ] {
            assert_eq!(
                line(spelling).unwrap_err(),
                UsageError::SkipPrivilegedWithoutDir,
                "{spelling}"
            );
        }
    }

    #[test]
    fn extract_atomic_needs_a_destination_to_rename_into() {
        match line("extract --strict --to-tar out.tar image.img").expect("parses") {
            Command::Extract(a) => assert!(a.strict, "--strict reaches the extract"),
            other => panic!("expected extract, got {other:?}"),
        }
        match line("extract --to-tar out.tar image.img").expect("parses") {
            Command::Extract(a) => assert!(!a.strict, "and is off unless asked for"),
            other => panic!("expected extract, got {other:?}"),
        }
        match line("extract --to-tar out.tar --atomic image.img").expect("parses") {
            Command::Extract(a) => {
                assert_eq!(a.mode, ExtractMode::ToTar(Stream::File("out.tar".into())));
                assert!(a.atomic);
            }
            other => panic!("expected extract, got {other:?}"),
        }
        // The standard output has no rename that could make it whole, and neither has a
        // mode that writes no file. An accepted flag that cannot do what it promises is
        // worse than a refused one.
        for spelling in [
            "extract --to-tar - --atomic image.img",
            "extract --list --atomic image.img",
            "extract --cat /x --atomic image.img",
        ] {
            assert_eq!(
                line(spelling).unwrap_err(),
                UsageError::AtomicWithoutFile,
                "{spelling}"
            );
        }
    }

    #[test]
    fn help_and_version_are_reachable_everywhere() {
        assert_eq!(line("--help").unwrap(), Command::Help(Topic::General));
        assert_eq!(line("-h").unwrap(), Command::Help(Topic::General));
        assert_eq!(line("help").unwrap(), Command::Help(Topic::General));
        assert_eq!(line("--version").unwrap(), Command::Version);
        assert_eq!(line("format --help").unwrap(), Command::Help(Topic::Format));
        assert_eq!(line("inspect -h").unwrap(), Command::Help(Topic::Inspect));
        assert_eq!(
            line("extract --help").unwrap(),
            Command::Help(Topic::Extract)
        );
        // Help wins over the arguments it would otherwise be missing.
        assert_eq!(line("format --help").unwrap(), Command::Help(Topic::Format));
    }

    #[test]
    fn a_path_inside_the_image_is_bytes_not_text() {
        // A path in a filesystem need not be text at all, so `--cat` takes the argument's
        // bytes rather than a string it would first have to decode.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let argv = vec![
                OsString::from("extract"),
                OsString::from("--cat"),
                OsString::from_vec(b"/od\xffd".to_vec()),
                OsString::from("image.img"),
            ];
            match parse(argv, None).expect("parses") {
                Command::Extract(a) => assert_eq!(a.mode, ExtractMode::Cat(b"/od\xffd".to_vec())),
                other => panic!("expected extract, got {other:?}"),
            }
        }
    }
}
