//! Writing a file the caller named, with `--atomic` deciding what a failure leaves behind.
//!
//! Two commands write a whole artifact to a path: `format` writes an image, `extract
//! --to-tar` writes an archive. Both open the destination only once everything that could
//! fail without touching it has succeeded, and both take the same `--atomic`, so the
//! mechanism lives here once rather than in each of them.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::Error;

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
    pub fn open(out: &Path, atomic: bool) -> Result<Self, Error> {
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
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&written)
            .map_err(|e| Error::io(&written, e))?;
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
