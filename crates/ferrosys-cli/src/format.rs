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

mod ext;
mod fat;

use std::io::Read;
use std::path::Path;

use crate::Error;
use crate::args::{FormatArgs, Target};
use crate::dest::Destination;

/// Write the filesystem the arguments describe.
pub fn run(args: FormatArgs) -> Result<(), Error> {
    match &args.target {
        Target::Ext(target) => ext::run(&args, target),
        Target::Fat(target) => fat::run(&args, target),
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
