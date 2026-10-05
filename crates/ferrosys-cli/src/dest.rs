//! Writing a file the caller named, with `--atomic` deciding what a failure leaves behind.
//!
//! Two commands write a whole artifact to a path: `format` writes an image, `extract
//! --to-tar` writes an archive. Both open the destination only once everything that could
//! fail without touching it has succeeded, and both take the same `--atomic`, so the
//! mechanism lives here once rather than in each of them.
//!
//! # A destination is never a file the run reads
//!
//! Both commands read host files while they write: `format` reads a named archive's members
//! and a walked tree's files as each is placed, and `extract` reads the image it was given.
//! A destination written in place is truncated, and truncating a file the run is still
//! reading destroys the source and fills the artifact with what the truncation left —
//! zeros, or the bytes just written — with every step succeeding. So each command names
//! the files it reads as [`Reads`], and a destination written in place that is one of them,
//! by any name, is refused before a byte of it changes. Under `--atomic` the destination is
//! a new file renamed into place once everything has been read, so nothing is refused.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use ferrosys::{EntryKind, FileContent, SourceEntry};

use crate::Error;

/// The host files a run reads, by identity rather than by name.
///
/// A name is not what decides whether two paths are one file: a hard link, a symbolic link,
/// and two spellings of one directory all name one file several ways. On a Unix host the
/// identity is the device and inode number. Elsewhere the standard library names no
/// identity, and the canonical path stands in for it, which tells two spellings and a
/// symbolic link apart from a different file but takes a hard link for one.
#[derive(Default)]
pub struct Reads(BTreeSet<FileId>);

/// What makes two names one file. See [`Reads`].
#[cfg(unix)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct FileId(u64, u64);

/// What makes two names one file. See [`Reads`].
#[cfg(not(unix))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct FileId(PathBuf);

/// The identity of the file at `path`, whose metadata is `meta`.
#[cfg(unix)]
fn identity(_path: &Path, meta: &std::fs::Metadata) -> std::io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    Ok(FileId(meta.dev(), meta.ino()))
}

/// The identity of the file at `path`, whose metadata is `meta`.
#[cfg(not(unix))]
fn identity(path: &Path, _meta: &std::fs::Metadata) -> std::io::Result<FileId> {
    std::fs::canonicalize(path).map(FileId)
}

impl Reads {
    /// The one file at `path`.
    pub fn file(path: &Path) -> Result<Self, Error> {
        let meta = std::fs::metadata(path).map_err(|e| Error::io(path, e))?;
        let id = identity(path, &meta).map_err(|e| Error::io(path, e))?;
        Ok(Self(BTreeSet::from([id])))
    }

    /// Every host file `entries` read their contents from as they are placed.
    ///
    /// Each path is looked up once however many ranges name it, so an archive's members cost
    /// one lookup between them. A path that cannot be looked up names no file a destination
    /// could be, and the placement that reads it reports why.
    pub fn of(entries: &[SourceEntry]) -> Self {
        let paths: BTreeSet<&Path> = entries
            .iter()
            .filter_map(|entry| match &entry.kind {
                EntryKind::File(FileContent::Range(range)) => Some(range.path()),
                _ => None,
            })
            .collect();
        Self(
            paths
                .into_iter()
                .filter_map(|path| {
                    let meta = std::fs::metadata(path).ok()?;
                    identity(path, &meta).ok()
                })
                .collect(),
        )
    }

    /// Refuse `out` if it is already one of these files.
    ///
    /// This is the early answer, given before anything is planned so a mistyped command
    /// costs nothing. [`Destination::open`] asks again from the handle it is about to
    /// truncate, which is the answer that holds.
    pub fn refuse(&self, out: &Path) -> Result<(), Error> {
        match std::fs::metadata(out) {
            Ok(meta) if self.holds(out, &meta) => {
                Err(Error::DestinationIsSource(out.display().to_string()))
            }
            _ => Ok(()),
        }
    }

    /// Whether the file at `path`, whose metadata is `meta`, is one of these.
    fn holds(&self, path: &Path, meta: &std::fs::Metadata) -> bool {
        identity(path, meta).is_ok_and(|id| self.0.contains(&id))
    }
}

/// Where a command's bytes go, and what makes them the destination's.
///
/// Written in place, this is the destination itself: it is created, or truncated if it
/// exists, and whatever the run manages to write is what the path then holds. Under
/// `--atomic` it is a sibling temporary file that becomes the destination at
/// [`commit`](Self::commit): the rename is atomic, so a reader of the path sees either
/// what was there before or the complete new artifact, and a run that fails part-way
/// through — or dies — leaves the old one untouched.
pub struct Destination {
    /// The path a caller asked for.
    out: PathBuf,
    /// The file being written: `out` itself, or the temporary sibling.
    written: PathBuf,
    file: File,
    /// Whether `written` still has to be renamed over `out`.
    atomic: bool,
}

impl Destination {
    /// Open the destination for `out`.
    ///
    /// The handle is returned rather than the path's metadata, so a caller with a
    /// requirement about what kind of file it wrote to — as `format` has — checks it from
    /// the handle and cannot be told about a path that changed underneath.
    ///
    /// Written in place, the destination is refused if it is one of `reads`, the files the
    /// run reads. It is judged from the handle the run writes through, before that handle
    /// truncates it, so no name reaches a file the run reads without the refusal seeing it.
    pub fn open(out: &Path, atomic: bool, reads: &Reads) -> Result<Self, Error> {
        // The temporary file is a sibling, because a rename cannot cross filesystems: one
        // in a scratch directory could not become this destination. The process id keeps
        // two runs writing the same destination from writing the same temporary file; it
        // reaches no written byte, so it costs the output's reproducibility nothing.
        let written = if atomic {
            let name = out.file_name().unwrap_or_default();
            let mut temp = name.to_os_string();
            temp.push(format!(".ferrosys-{}.tmp", std::process::id()));
            out.with_file_name(temp)
        } else {
            out.to_path_buf()
        };
        // The temporary file must be one this run created. Its name is derivable — the
        // destination and a process id — so opening whatever is already there would open
        // whatever someone else put there, including a symbolic link pointing anywhere this
        // process can write, which the truncate would then empty and the run would then fill.
        // `create_new` is what refuses all of that: it fails if the name exists at all, and
        // it never follows a link. The destination written in place is the opposite case —
        // replacing what is there is the whole request — and it is truncated below, once the
        // handle shows it is not a file the run reads, rather than by the open itself.
        let mut options = OpenOptions::new();
        options.write(true);
        if atomic {
            options.create_new(true);
        } else {
            options.create(true);
        }
        let file = options.open(&written).map_err(|e| Error::io(&written, e))?;
        if !atomic {
            let meta = file.metadata().map_err(|e| Error::io(&written, e))?;
            if reads.holds(&written, &meta) {
                return Err(Error::DestinationIsSource(out.display().to_string()));
            }
            // A FIFO or a terminal has no length to cut, and an open would not have cut one.
            if meta.file_type().is_file() {
                file.set_len(0).map_err(|e| Error::io(&written, e))?;
            }
        }
        Ok(Self {
            out: out.to_path_buf(),
            written,
            file,
            atomic,
        })
    }

    /// The handle the artifact is written through.
    pub fn file(&mut self) -> &mut File {
        &mut self.file
    }

    /// The file the bytes were written to, for reading them back.
    pub fn written(&self) -> &Path {
        &self.written
    }

    /// Make the written bytes the destination's.
    ///
    /// Written in place there is nothing to do. Under `--atomic` the file's bytes are
    /// flushed to disk before the rename and the directory entry after it, since a rename
    /// that reached the disk before the bytes it names would leave the destination holding
    /// an artifact that was never finished — which is the one outcome the option exists to
    /// prevent.
    pub fn commit(self) -> Result<(), Error> {
        if !self.atomic {
            return Ok(());
        }
        self.file
            .sync_all()
            .map_err(|e| Error::io(&self.written, e))?;
        std::fs::rename(&self.written, &self.out).map_err(|e| Error::io(&self.out, e))?;
        // The directory entry the rename created. A parent that cannot be opened is not a
        // failure of the run — the artifact is written and in place — so the durability of
        // the entry is best-effort where the bytes' is not.
        if let Some(parent) = self.out.parent().filter(|p| !p.as_os_str().is_empty())
            && let Ok(dir) = File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

impl Drop for Destination {
    /// Remove the temporary file if it never became the destination, so a failed
    /// `--atomic` run leaves nothing behind. A successful `commit` renamed it away, and the
    /// remove then finds nothing to do.
    fn drop(&mut self) {
        if self.atomic {
            let _ = std::fs::remove_file(&self.written);
        }
    }
}
