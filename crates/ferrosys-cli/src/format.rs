//! `ferrosys format`: write a filesystem into a file.
//!
//! The bytes stream out through the library's `FormatPlan`, which writes only the blocks
//! the filesystem uses, so a file destination stays sparse and an image far larger than
//! memory can be written. A `--from-tar` archive named by path is opened and left on
//! disk, each member read only as its file is placed, so the memory a run needs is the
//! largest single member rather than the whole archive; a `--from-dir` tree is walked for
//! its metadata alone and each file read as it is placed, which is the same bound. An
//! archive arriving on the standard input has nothing to seek back to and is read whole, so
//! that one path carries a size cap: a stream with no end must not become memory with no
//! bound.
//!
//! # One spine, one writer per family
//!
//! `-t` names which filesystem to write, and everything only that family takes travels with
//! it. What is shared is above the split — the destination, the size, the time, the contents
//! — and each family's module holds its own options, its own plan, and its own report. A
//! later family is a module and a `match` arm.
//!
//! # The destination is touched last
//!
//! A format writes only the blocks the filesystem uses, so every byte of the destination
//! it does not write must already read as zero — which means creating the file, or
//! truncating one that exists, is part of formatting rather than something done to it
//! afterwards. So the order matters: the archive is parsed, the geometry planned, and the
//! inode model built and checked against it *before* the destination is opened. A run that
//! cannot succeed leaves the file that was there exactly as it was. `--size auto` searches
//! for the size in that same window, placing the contents into candidate geometries without
//! writing any of them, so a size that cannot be found is a run that never opened the file
//! either.
//!
//! `--atomic` goes further, for the case where a failure part-way through the writing must
//! not be visible either: the image is written to a sibling temporary file, flushed to
//! disk, and renamed over the destination once it is complete.
//!
//! # `--from-dir` is Linux's
//!
//! Walking a host tree records Linux inode metadata and Linux extended attributes, so the
//! library builds its directory source on Linux alone. Everything else here — an empty
//! filesystem, `--from-tar`, and every geometry option — is the same on every platform, so
//! each family's module carries the boundary rather than the whole tool: `from_dir` is the
//! walk on Linux and a typed refusal elsewhere.

mod btrfs;
mod exfat;
mod ext;
mod fat;

use std::io::Read;
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "android"))]
use ferrosys::DirectorySource;
use ferrosys::{ArchiveSource, Slack, Source, TreeBuilder};

use crate::Error;
use crate::args::{Contents, FormatArgs, Size, Stream, Target};
use crate::dest::Destination;

/// Write the filesystem the arguments describe.
pub fn run(args: FormatArgs) -> Result<(), Error> {
    match &args.target {
        Target::Ext(target) => ext::run(&args, target),
        Target::Fat(target) => fat::run(&args, target),
        Target::ExFat(target) => exfat::run(&args, target),
        Target::Btrfs(target) => btrfs::run(&args, target),
    }
}

/// A family's format, decided but not yet performed.
///
/// The two ways a plan is arrived at, and nothing else: everything else about a plan —
/// what it writes, what geometry it realizes, what it costs in fidelity — is the family's
/// own and is read through its own type in its own module.
///
/// The trait exists so that [`planned`] is written once. Which source a run reads and how a
/// size is arrived at are questions about the command line rather than about a filesystem,
/// and answering them per family is three copies of a four-arm match that must stay in step
/// on a change to either question.
pub(crate) trait Plan: Sized {
    /// The options that family's format takes.
    type Options;

    /// The `-t` word this family answers to, for the refusal below.
    const FAMILY: &'static str;

    /// Plan a filesystem of exactly `bytes` bytes.
    fn sized(source: impl Source, bytes: u64, options: Self::Options) -> Result<Self, Error>;

    /// Plan the smallest filesystem that holds `source` with `slack` left free.
    ///
    /// The default refuses, because the search is a family's own: how much room a filesystem
    /// has left follows from its size, so the size that just holds a tree is a fixed point
    /// arrived at by planning candidates and placing into them rather than by a formula. A
    /// family with no such search does not implement this, which is what makes "this family
    /// cannot" a fact the type carries rather than a function nothing reaches.
    ///
    /// A caller never meets the refusal: [`UsageError::NoFitForFamily`] is raised while the
    /// command line is being read, before a source is opened. It is spelled once, here, so the
    /// two cannot come to say different things.
    fn fitted(source: impl Source, options: Self::Options, slack: Slack) -> Result<Self, Error> {
        let _ = (source, options, slack);
        Err(crate::args::UsageError::NoFitForFamily {
            family: Self::FAMILY,
        }
        .into())
    }
}

/// A family whose plan is carried through to an image by [`realize`] and nothing else.
///
/// Two of the three are: their whole write step is open the destination, write, commit, and
/// report the geometry that came back. ext's is not — it reads the filesystem's own free
/// counts back out of what was just written, between the write and the commit — so it opens
/// the destination itself and this trait is the two that do not.
///
/// That is the shape the split follows generally: what every family does identically is
/// written once, and a family that does something more keeps its own body rather than the
/// shared one growing a hook for it.
pub(crate) trait Written: Plan {
    /// The geometry this family's format realizes.
    ///
    /// Unbounded, because a geometry is whatever the family's is: three of them fit in a
    /// register and btrfs's is a list of chunks. What [`realize`] does with one is hand it
    /// back, which needs nothing of it.
    type Layout;

    /// The geometry the plan will realize, before anything is written.
    fn planned_layout(&self) -> Self::Layout;

    /// Write the image, and hand back the geometry it actually took.
    fn write_to(&self, file: &mut std::fs::File) -> Result<Self::Layout, Error>;
}

/// Carry a plan through to the image, or stop at the plan.
///
/// A dry run reports the geometry the plan realizes and stops. The layout is the same value
/// the write would use, so what it reports is exact rather than an estimate — and the
/// destination is never opened at all.
///
/// The second half of the answer says which of the two happened, because a report has to: a
/// receipt claiming an image was written when none was is worse than one that says nothing.
pub(crate) fn realize<P: Written>(args: &FormatArgs, plan: &P) -> Result<(P::Layout, bool), Error> {
    if args.dry_run {
        return Ok((plan.planned_layout(), false));
    }
    let mut dest = open_destination(&args.out, args.atomic)?;
    let layout = plan.write_to(dest.file())?;
    dest.commit()?;
    Ok((layout, true))
}

/// Plan the format the arguments describe, without opening the destination.
///
/// The source is consumed by value and each kind is a distinct type, so the plan is built
/// once per kind rather than behind a trait object the library would have to accept — which
/// is what makes this a four-arm match rather than one call.
///
/// An archive named by path is opened by the library, which keeps every file's bytes on disk
/// until the file is placed: peak memory is the largest single member rather than the whole
/// archive. A stream on the standard input has no such option — there is nothing to seek back
/// to — so it is read whole, under [`MAX_STDIN_ARCHIVE`]. A walked tree names each file rather
/// than reading it, so peak memory there is the largest single file too.
pub(crate) fn planned<P: Plan>(args: &FormatArgs, options: P::Options) -> Result<P, Error> {
    match &args.contents {
        None => at_size(TreeBuilder::new(), args, options),
        Some(Contents::Tar(Stream::Std)) => {
            at_size(ArchiveSource::from_reader(bounded_stdin())?, args, options)
        }
        Some(Contents::Tar(Stream::File(path))) => {
            at_size(ArchiveSource::from_path(path)?, args, options)
        }
        Some(Contents::Dir(path)) => from_dir(path, args, options),
    }
}

/// Plan one source at whichever size the arguments asked for.
///
/// A named size is planned directly. `--size auto` is a search instead: candidate sizes are
/// planned and the source placed into each until the smallest one that holds it with the
/// requested room to spare is found. Either way what comes back is a plan over the same
/// model, so the search costs no second reading of the source and nothing downstream knows
/// which way the size was arrived at.
fn at_size<P: Plan>(
    source: impl Source,
    args: &FormatArgs,
    options: P::Options,
) -> Result<P, Error> {
    match args.size {
        Size::Bytes(bytes) => P::sized(source, bytes, options),
        Size::Fit(slack) => P::fitted(source, options, slack),
    }
}

/// Plan a format from a walked directory tree.
///
/// The ownership override is applied to the walk, since it is what records the host's ids in
/// the first place.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn from_dir<P: Plan>(path: &Path, args: &FormatArgs, options: P::Options) -> Result<P, Error> {
    let mut source = DirectorySource::from_path(path)?;
    if let Some((uid, gid)) = args.owner {
        source = source.owner(uid, gid);
    }
    at_size(source, args, options)
}

/// The same, on a platform the library builds no directory source for: a named failure
/// rather than a walk.
///
/// The refusal is the whole of what `--from-dir` does here, and it happens before the
/// destination is opened, like every other planning failure.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn from_dir<P: Plan>(_path: &Path, _args: &FormatArgs, _options: P::Options) -> Result<P, Error> {
    Err(Error::NoDirectorySource)
}

/// What the build could not carry, one line per property, in this tool's own spelling.
///
/// Rendered here rather than taken from the library so the words are the ones `--accept-loss`
/// reads: a property this table names is one that can be typed straight back into the command
/// line that produced it.
///
/// Shared by the two families that record a name, a few attribute bits and some times and have
/// nowhere to put anything else. They lose the same six properties for the same reason, so the
/// accounting behind this is already one function in the library; what a person reads off it
/// is one function here for the same reason.
pub(crate) fn fidelity_table(fidelity: &ferrosys::FidelityReport) -> String {
    let summary = fidelity.summary();
    if summary.is_empty() {
        return "nothing dropped or synthesized\n".to_string();
    }
    let mut s = String::from("DIRECTION  PROPERTY             ENTRIES\n");
    for (direction, property, entries) in summary {
        s.push_str(&format!(
            "{:<11}{:<21}{}\n",
            direction.as_str(),
            crate::parse::property_name(property),
            entries
        ));
    }
    if fidelity.is_truncated() {
        // The counts are complete either way; it is the per-entry records that stopped.
        s.push_str("(more entries than the report stores individually; the counts are whole)\n");
    }
    s
}

/// The most an archive arriving on the standard input may be.
///
/// An archive named by path is opened by the library and each member read as its file is
/// placed, so peak memory is the largest single member. A stream has nothing to seek back to
/// and is read whole — which is inherent, and is why the cap is here rather than a defect to
/// fix. Without one, a service or CI step piping an untrusted or accidentally-huge tar into
/// the command has no way to bound what it costs.
///
/// Four gibibytes is far past any root filesystem anyone pipes in, and the way past it is to
/// name the archive as a file, which is not merely permitted but cheaper.
const MAX_STDIN_ARCHIVE: u64 = 4 << 30;

/// The standard input, bounded, so an archive with no end cannot be read into memory
/// without limit.
///
/// The bound is reported as an I/O error because that is what a parser reading past it
/// meets, and it says what to do instead.
pub(crate) fn bounded_stdin() -> impl Read {
    struct Bounded<R> {
        inner: R,
        left: u64,
    }
    impl<R: Read> Read for Bounded<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.left == 0 {
                return Err(std::io::Error::other(format!(
                    "the archive on the standard input is larger than {MAX_STDIN_ARCHIVE} \
                     bytes: a stream is read whole, so name it as a file instead, which is \
                     read a member at a time"
                )));
            }
            let want = buf
                .len()
                .min(usize::try_from(self.left).unwrap_or(usize::MAX));
            let read = self.inner.read(&mut buf[..want])?;
            self.left -= read as u64;
            Ok(read)
        }
    }
    Bounded {
        inner: std::io::stdin(),
        // One byte beyond the cap, so reading exactly the cap succeeds and the next read is
        // what refuses.
        left: MAX_STDIN_ARCHIVE + 1,
    }
}

/// Open the destination for the image, refusing anything but a regular file.
///
/// A format writes only the blocks the filesystem uses and extends the file to its full
/// size with a single byte at the end, so every byte it does not write must already read
/// as zero. Creating the file, or truncating one that exists, is what makes that true. A
/// block device cannot be made true that way: formatting one would leave whatever it held
/// interleaved with the new filesystem, and the result would pass no checker.
///
/// The kind is checked before the file is opened, so a device is never opened for writing
/// at all, and again after, from the handle itself, so a path that changed underneath the
/// first check cannot slip past.
///
/// Shared rather than per-family: the reasoning is about the destination, and every family
/// writes only what its filesystem occupies.
fn open_destination(out: &Path, atomic: bool) -> Result<Destination, Error> {
    let not_regular = || Error::NotARegularFile(out.display().to_string());
    match std::fs::metadata(out) {
        Ok(meta) if !meta.file_type().is_file() => return Err(not_regular()),
        // A path that does not exist yet is about to be a regular file.
        Ok(_) | Err(_) => {}
    }
    let mut dest = Destination::open(out, atomic)?;
    let meta = dest
        .file()
        .metadata()
        .map_err(|e| Error::io(dest.written(), e))?;
    if !meta.file_type().is_file() {
        return Err(not_regular());
    }
    Ok(dest)
}
