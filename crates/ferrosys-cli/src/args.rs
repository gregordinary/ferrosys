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

use ferrosys::ext::feature::{FeatureError, FeatureSet};
use ferrosys::ext::ondisk::Timestamp;
use ferrosys::ext::{
    ErrorBehavior, GrowReservation, HashSignedness, HashVersion, InodeCount, JournalSize, Profile,
    ReservedRatio, Severity,
};

use crate::parse::{self, ValueError};

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

/// `ferrosys format`: everything the filesystem's bytes are a function of.
///
/// Every input is here, and nothing else is read: the identity (`uuid`, `hash_seed`),
/// the clock (`time`, `fixed_time`), the geometry (`size`, `feature`, `grow`,
/// `journal`), and the contents (`from_tar`). Two runs given the same values write the
/// same bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FormatArgs {
    /// The file to write. It must be a regular file.
    pub out: PathBuf,
    /// The filesystem's size in bytes.
    pub size: u64,
    /// The filesystem UUID.
    pub uuid: [u8; 16],
    /// The filesystem's creation and write time.
    pub time: Timestamp,
    /// The archive to populate the filesystem from, or `None` for an empty one.
    pub from_tar: Option<Stream>,
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
    /// Print the geometry the format realized as JSON.
    pub json: bool,
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

/// `ferrosys extract`: what to read the filesystem's contents into.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtractArgs {
    /// The image to read.
    pub image: PathBuf,
    /// Where the filesystem begins within it.
    pub offset: u64,
    /// What to produce.
    pub mode: ExtractMode,
}

/// The one thing an extract produces. Exactly one is asked for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExtractMode {
    /// Write the whole tree as a tar archive.
    ToTar(Stream),
    /// Write one file's bytes, and nothing else.
    Cat(Vec<u8>),
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
    /// `extract` was told to produce nothing, or more than one thing.
    #[error("extract: give exactly one of --to-tar, --cat, or --list")]
    ExtractMode,
    /// `--json` was given to an extract that produces bytes, which have no JSON form.
    #[error("extract: --json applies to --list")]
    JsonWithoutList,
    /// `inspect` was given both `--json` and `--sarif`, two different output formats.
    #[error("inspect: --sarif and --json are different output formats; give one")]
    SarifWithJson,
    /// `inspect --sarif` reports scan findings, which `--quick` skips.
    #[error("inspect: --sarif reports scan findings, which --quick skips")]
    SarifWithQuick,
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
        Arg::Positional(name) if name == OsStr::new("help") => Ok(Command::Help(Topic::General)),
        Arg::Long(name, None) if name == "help" => Ok(Command::Help(Topic::General)),
        Arg::Long(name, None) if name == "version" => Ok(Command::Version),
        Arg::Short('h', None) => Ok(Command::Help(Topic::General)),
        Arg::Short('V', None) => Ok(Command::Version),
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
    let mut uuid: Option<[u8; 16]> = None;
    let mut time: Option<i64> = None;
    let mut from_tar: Option<Stream> = None;
    // The feature set is composed once the whole line is read (below), not mutated in place
    // as options arrive. So the base profile (`-t`), the size overrides, and the `-O` deltas
    // take effect in a fixed order — profile seeds, sizes override, `-O` lists layer on last
    // — rather than in the order they happen to appear. This is the order `mke2fs -t … -O …`
    // composes in, and it makes `-t` position-independent.
    let mut profile: Option<Profile> = None;
    let mut block_size: Option<u32> = None;
    let mut inode_size: Option<u16> = None;
    let mut feature_ops: Vec<OsString> = Vec::new();
    let mut errors = ErrorBehavior::default();
    let mut inodes = InodeCount::default();
    let mut reserved = ReservedRatio::default();
    let mut volume_name = [0u8; 16];
    let mut grow = GrowReservation::default();
    let mut journal = JournalSize::Auto;
    let mut fixed_time: Option<i64> = None;
    let mut hash_version = HashVersion::default();
    let mut hash_signedness = HashSignedness::default();
    let mut hash_seed: Option<[u8; 16]> = None;
    let mut json = false;

    while let Some(arg) = args.next()? {
        match arg {
            Arg::Long(name, attached) => {
                let flag = format!("--{name}");
                match name.as_str() {
                    "help" => return Ok(Command::Help(Topic::Format)),
                    "size" => {
                        size = Some(
                            parse::size(&args.value(&flag, attached)?).map_err(value_err(&flag))?,
                        );
                    }
                    "uuid" => {
                        uuid = Some(
                            parse::hex16(&args.value(&flag, attached)?)
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
                    // The base profile seeds the feature set; `--type` and `-t` name the same
                    // thing, and the last one given wins. `-O` and the size options layer on
                    // top of it when the set is composed below.
                    "type" => {
                        profile = Some(
                            parse::profile(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "block-size" => {
                        block_size = Some(
                            parse::count_u32(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "inode-size" => {
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
                        let count = parse::count_u32(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                        inodes = InodeCount::Count(count);
                    }
                    "bytes-per-inode" => {
                        inodes = parse::bytes_per_inode(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "reserved-percent" => {
                        reserved = parse::reserved_percent(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    // A label is bytes, not text — the on-disk field holds sixteen of them
                    // and the reader reports whatever is there — so it is taken as the
                    // argument's bytes, as a path inside the image is.
                    "label" => {
                        let value = args.value(&flag, attached)?;
                        volume_name = parse::label(os::bytes(&value)).map_err(value_err(&flag))?;
                    }
                    "grow" => {
                        grow =
                            parse::grow(&args.value(&flag, attached)?).map_err(value_err(&flag))?;
                    }
                    "journal" => {
                        journal = parse::journal(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "errors" => {
                        errors = parse::error_behavior(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "fixed-time" => {
                        fixed_time = Some(
                            parse::seconds(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
                    }
                    "hash" => {
                        hash_version = parse::hash_version(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "hash-signedness" => {
                        hash_signedness = parse::hash_signedness(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
                    }
                    "hash-seed" => {
                        hash_seed = Some(
                            parse::hex16(&args.value(&flag, attached)?)
                                .map_err(value_err(&flag))?,
                        );
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
            // `-O` and `-t` are read here but applied below, once the whole line is known:
            // the base profile seeds the set and every `-O` list layers on top, left to
            // right, so two `-O`s compose and the last element to name a feature wins.
            Arg::Short('O', attached) => feature_ops.push(args.value("-O", attached)?),
            Arg::Short('t', attached) => {
                profile =
                    Some(parse::profile(&args.value("-t", attached)?).map_err(value_err("-t"))?);
            }
            Arg::Short('h', None) => return Ok(Command::Help(Topic::Format)),
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
    let uuid = uuid.ok_or(UsageError::MissingRequired {
        command: CMD,
        flag: "--uuid",
    })?;
    let size = size.ok_or(UsageError::MissingRequired {
        command: CMD,
        flag: "--size",
    })?;
    let out = out.ok_or(UsageError::MissingArgument {
        command: CMD,
        what: "output file",
    })?;
    // Compose the feature set now that the whole line is read: the base profile seeds it
    // (ext4 when no `-t` was given), the size options override, and the `-O` lists layer on
    // last, left to right. A combination that must never reach disk is a request that cannot
    // be honoured, so it is refused here, by the name of the conflict, rather than deep in
    // the planner.
    let mut feature = profile.unwrap_or_default().feature_set();
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

    Ok(Command::Format(Box::new(FormatArgs {
        out,
        size,
        uuid,
        time: Timestamp::from_secs(time),
        from_tar,
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
        // The seed defaults to the UUID's bytes: an identity the caller already supplied,
        // rather than one the tool would have to invent from a random source it does not
        // have.
        hash_seed: hash_seed.unwrap_or(uuid),
        json,
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

    while let Some(arg) = args.next()? {
        match arg {
            Arg::Long(name, attached) => {
                let flag = format!("--{name}");
                match name.as_str() {
                    "help" => return Ok(Command::Help(Topic::Inspect)),
                    "offset" => {
                        offset =
                            parse::size(&args.value(&flag, attached)?).map_err(value_err(&flag))?;
                    }
                    "fail-on" => {
                        fail_on = parse::fail_on(&args.value(&flag, attached)?)
                            .map_err(value_err(&flag))?;
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
            Arg::Short('h', None) => return Ok(Command::Help(Topic::Inspect)),
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
    // report. So it selects a different output format from --json, and it needs the scan
    // --quick would skip.
    if sarif && json {
        return Err(UsageError::SarifWithJson);
    }
    if sarif && quick {
        return Err(UsageError::SarifWithQuick);
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

/// `ferrosys extract [options] IMAGE`.
fn extract(args: &mut Args) -> Result<Command, UsageError> {
    const CMD: &str = "extract";
    let mut image: Option<PathBuf> = None;
    let mut offset = 0u64;
    let mut to_tar: Option<Stream> = None;
    let mut cat: Option<Vec<u8>> = None;
    let mut list = false;
    let mut json = false;

    while let Some(arg) = args.next()? {
        match arg {
            Arg::Long(name, attached) => {
                let flag = format!("--{name}");
                match name.as_str() {
                    "help" => return Ok(Command::Help(Topic::Extract)),
                    "offset" => {
                        offset =
                            parse::size(&args.value(&flag, attached)?).map_err(value_err(&flag))?;
                    }
                    "to-tar" => to_tar = Some(Stream::from_value(args.value(&flag, attached)?)),
                    // A path inside the image is a byte string, not text: it is taken as
                    // the bytes the argument holds, and never rendered through a
                    // character encoding on the way in.
                    "cat" => {
                        let value = args.value(&flag, attached)?;
                        cat = Some(os::bytes(&value).to_vec());
                    }
                    "list" => {
                        Args::no_value(&flag, attached)?;
                        list = true;
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
            Arg::Short('h', None) => return Ok(Command::Help(Topic::Extract)),
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
    // Exactly one artifact per run: the standard output carries a tar stream, or a
    // file's bytes, or a listing, and the tool is told which.
    let mode = match (to_tar, cat, list) {
        (Some(stream), None, false) => ExtractMode::ToTar(stream),
        (None, Some(path), false) => ExtractMode::Cat(path),
        (None, None, true) => ExtractMode::List { json },
        _ => return Err(UsageError::ExtractMode),
    };
    if json && !matches!(mode, ExtractMode::List { .. }) {
        return Err(UsageError::JsonWithoutList);
    }

    Ok(Command::Extract(ExtractArgs {
        image,
        offset,
        mode,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    const UUID: &str = "f0e17055-0000-4000-8000-000000000000";
    const UUID_BYTES: [u8; 16] = [
        0xf0, 0xe1, 0x70, 0x55, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn format_takes_its_required_inputs() {
        let a = fmt(&format!(
            "format --size 512M --uuid {UUID} --time 1700000000 out.img"
        ));
        assert_eq!(a.out, PathBuf::from("out.img"));
        assert_eq!(a.size, 512 << 20);
        assert_eq!(a.uuid, UUID_BYTES);
        assert_eq!(a.time, Timestamp::from_secs(1_700_000_000));
        // The hash seed defaults to the UUID: an identity the caller supplied, rather
        // than one the tool would have had to invent.
        assert_eq!(a.hash_seed, UUID_BYTES);
        assert_eq!(a.feature, FeatureSet::DEFAULT);
        assert_eq!(a.from_tar, None);
        assert!(!a.json);
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
    fn format_folds_the_feature_options_together() {
        let a = fmt(&format!(
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
        let ext2 = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 -t ext2 out.img"
        ));
        assert_eq!(ext2.feature, FeatureSet::EXT2);
        assert_eq!(Profile::of(ext2.feature), Profile::Ext2);
        let ext3 = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 --type ext3 out.img"
        ));
        assert_eq!(ext3.feature, FeatureSet::EXT3);
        // No profile is ext4, exactly as it was before the selector existed.
        let ext4 = fmt(&format!("format --size 64M --uuid {UUID} --time 1 out.img"));
        assert_eq!(ext4.feature, FeatureSet::DEFAULT);
        assert_eq!(Profile::of(ext4.feature), Profile::Ext4);
    }

    #[test]
    fn the_base_profile_seeds_and_o_layers_on_top_in_any_order() {
        // `-O` composes over the profile whichever came first on the line: the profile is
        // the base, the `-O` deltas layer on last. A journal over the ext2 baseline is ext3.
        let a = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 -t ext2 -O has_journal out.img"
        ));
        let b = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 -O has_journal -t ext2 out.img"
        ));
        assert_eq!(
            a.feature, b.feature,
            "the order of -t and -O does not matter"
        );
        assert_eq!(a.feature, FeatureSet::EXT3);
        assert_eq!(Profile::of(a.feature), Profile::Ext3);

        // The size options override the profile's baseline sizes, in any position.
        let sized = fmt(&format!(
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
    fn format_takes_the_sizing_and_label_options() {
        let a = fmt(&format!(
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
        let a = fmt(&format!(
            "format --size 256M --uuid {UUID} --time 1 --inodes 5000 --bytes-per-inode 65536 out.img"
        ));
        assert_eq!(
            a.inodes,
            InodeCount::BytesPerInode(std::num::NonZeroU64::new(65536).unwrap())
        );

        // The defaults when none are given: size-driven inodes, 5% reserved, no label.
        let a = fmt(&format!("format --size 64M --uuid {UUID} --time 1 out.img"));
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
            let a = fmt(&format!(
                "format --size 64M --uuid {UUID} --time 1 --errors {name} out.img"
            ));
            assert_eq!(a.errors, want, "--errors {name}");
        }
        let a = fmt(&format!("format --size 64M --uuid {UUID} --time 1 out.img"));
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
        let a = fmt(&format!(
            "format --size 64M --uuid {UUID} --time 1 --label -- out.img"
        ));
        assert_eq!(a.out, PathBuf::from("out.img"));
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
            UsageError::JsonWithoutList
        );
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
