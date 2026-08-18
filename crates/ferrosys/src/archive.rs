//! Tar archives with PAX extensions, in both directions: [`ArchiveSource`] reads one into
//! the entries a format consumes, and [`ArchiveSink`] writes a filesystem's contents back out
//! as one. An archive that makes the round trip describes the same filesystem at both ends.
//!
//! [`ArchiveSource`] parses a tar stream into the [`SourceEntry`] list the model
//! consumes, carrying the fidelity a package-built rootfs needs: ownership and mode
//! bits, access/change/modification times (the latter two from PAX records), fast
//! and slow symlinks, hard links, device / FIFO nodes, extended attributes from
//! `SCHILY.xattr.*` records, and POSIX ACLs — from the text form of a
//! `SCHILY.acl.access` / `SCHILY.acl.default` record, or from the binary version-2
//! form of a `system.posix_acl_*` attribute — which arrive as one [`Acl`] whichever
//! form carried them and leave as the version-2 `posix_acl_xattr` bytes every boundary
//! speaks. Narrowing that to whatever a filesystem stores is the family's own work.
//!
//! An archive's own root member (`./`) describes the filesystem root: its mode,
//! ownership, times, and extended attributes become the root directory's.
//!
//! Parsing is fallible up front and infallible after: both constructors read every
//! header, path, and PAX record while parsing and return an [`ArchiveError`] on a
//! malformed or unsupported entry, so the [`Source`] the model later consumes cannot
//! fail. An entry type the model cannot represent is a typed error, never a silently
//! dropped entry.
//!
//! The two constructors differ in where a regular file's *contents* live.
//! [`ArchiveSource::from_reader`] takes any stream and reads every body into memory, so a
//! format needs the sum of the archive's file bytes. [`ArchiveSource::from_path`] opens
//! the archive itself, records where each body lies, and reads it only when that file is
//! placed — so a format needs the largest single member. The handles keep the archive
//! open, and it must not be modified in place until the format finishes.
//!
//! Framing the tar stream and parsing its PAX records is this module's own work
//! (see `blocks`), so a PAX value carrying any byte — a newline included, which a
//! binary ACL naming user or group 10 produces — is read intact.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tar::EntryType;

use crate::acl::{Acl, AclEntry, AclQualifier};
use crate::source::{EntryKind, FileContent, FileRange, Metadata, Source, SourceEntry};
use crate::time::Timestamp;
use crate::xattr::Xattr;

mod blocks;
mod sink;

use blocks::{Member, MemberBody, PaxRecord};
pub use sink::ArchiveSink;

/// A failure reading or interpreting a tar archive.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArchiveError {
    /// An I/O error reading the archive stream.
    #[error("reading archive: {0}")]
    Io(#[from] std::io::Error),
    /// An entry could not be interpreted.
    #[error("archive entry {}: {reason}", crate::escape::printable(path))]
    #[non_exhaustive]
    Bad {
        /// The offending entry's path.
        path: Vec<u8>,
        /// What was wrong.
        reason: &'static str,
    },
    /// An entry has a type the model cannot represent.
    #[error(
        "archive entry {} has an unsupported type",
        crate::escape::printable(path)
    )]
    #[non_exhaustive]
    Unsupported {
        /// The offending entry's path.
        path: Vec<u8>,
    },
    /// The archive's block structure, a header checksum, or a PAX extended header
    /// could not be read. The failure is in the framing rather than in one entry,
    /// so it names no path.
    #[error("malformed archive: {reason}")]
    #[non_exhaustive]
    Malformed {
        /// What was wrong.
        reason: &'static str,
    },
    /// The stream is a *compressed* archive, named by the magic at its head. This parser
    /// reads uncompressed tar, so the archive has to be decompressed first — through a pipe
    /// into [`ArchiveSource::from_reader`], or into a file for
    /// [`from_path`](ArchiveSource::from_path) to keep each member on disk.
    ///
    /// It is a variant of its own because everything else this parser could say about such
    /// a stream is about tar framing the caller never wrote, and the one useful fact — that
    /// these are gzip's bytes — is the one a message about framing does not carry.
    #[error(
        "the archive is {format}-compressed, and this reads uncompressed tar: decompress it first"
    )]
    #[non_exhaustive]
    Compressed {
        /// The compression format the head of the stream identifies: `gzip`, `zstd`, `xz`,
        /// `bzip2`, `lz4`, `lzma`, `lzop`, or `compress`.
        format: &'static str,
    },
    /// A `SCHILY.acl.*` record could not be translated into a valid ACL, or an entry's
    /// stored ACL could not be translated into one.
    #[error(
        "archive entry {} has an invalid ACL: {source}",
        crate::escape::printable(path)
    )]
    #[non_exhaustive]
    Acl {
        /// The offending entry's path.
        path: Vec<u8>,
        /// The underlying ACL error.
        source: crate::acl::AclError,
    },
    /// The filesystem being written out could not be read.
    #[error(transparent)]
    Read(#[from] crate::tree::TreeError),
    /// The filesystem holds an entry a tar archive has no way to express: a socket, which
    /// has no entry type at all. It is a typed error rather than an archive quietly missing
    /// a file.
    #[error(
        "{} is a socket, which a tar archive has no entry type for: writing it out would \
         drop it silently",
        crate::escape::printable(path)
    )]
    #[non_exhaustive]
    Unrepresentable {
        /// The offending entry's path.
        path: Vec<u8>,
    },
    /// An extended-attribute name a PAX record's keyword cannot carry faithfully: it holds
    /// an `=` or a newline — the record's own delimiters — or is not valid UTF-8. It is
    /// refused rather than written as a differently-named attribute.
    #[error(
        "{}: extended-attribute name {} cannot be written to a PAX record: it holds an '=' \
         or a newline, or is not valid UTF-8",
        crate::escape::printable(path),
        crate::escape::printable(name)
    )]
    #[non_exhaustive]
    XattrNameUnrepresentable {
        /// The entry carrying the attribute.
        path: Vec<u8>,
        /// The offending attribute name.
        name: Vec<u8>,
    },
}

impl ArchiveError {
    /// Classify the failure of writing one member's body.
    ///
    /// `tar` copies a body out of a reader, so a failure there is either the destination's or
    /// the *filesystem's*, arriving as the [`std::io::Error`] a `Read` is obliged to speak.
    /// The reader's own message is preserved, and the path names the member it was reading —
    /// which a bare i/o error would not.
    fn from_body_io(e: std::io::Error, path: &[u8]) -> Self {
        ArchiveError::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", crate::escape::printable(path)),
        ))
    }
}

/// A [`Source`] that yields the entries parsed from a tar archive.
///
/// Build one with [`from_reader`](Self::from_reader), which reads the whole archive into
/// memory, or [`from_path`](Self::from_path), which leaves each file's bytes on disk
/// until that file is placed. Both produce byte-identical images.
pub struct ArchiveSource {
    entries: Vec<SourceEntry>,
}

impl ArchiveSource {
    /// Parse an entire tar archive from `reader` into a source.
    ///
    /// # Errors
    ///
    /// An [`ArchiveError`] if the stream cannot be read or an entry cannot be
    /// represented.
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, ArchiveError> {
        let entries = blocks::read_members(reader)?
            .into_iter()
            .map(|m| parse_entry(m, None))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries })
    }

    /// Open the tar archive at `path` and parse it, leaving every file's bytes on disk
    /// until the file is placed.
    ///
    /// This is the memory-shaped alternative to [`from_reader`](Self::from_reader): the
    /// entry records, their paths, their metadata, and their extended attributes are read
    /// up front exactly as they are there, but a regular file's *contents* become a
    /// handle into the archive rather than a buffer. A format's peak memory becomes the
    /// largest single file rather than the sum of every file, which for a rootfs archive
    /// is the difference between gigabytes and megabytes.
    ///
    /// The archive is checked to hold every body it declares, so a truncated archive
    /// fails here rather than part-way through writing an image.
    ///
    /// # The archive must not change until the format finishes
    ///
    /// The bytes are read when each file is placed, so an edit between parsing and
    /// formatting reaches the image — as wrong bytes, not as an error. The descriptor is
    /// held open for the source's whole life, which narrows the exposure to exactly the
    /// case that matters: replacing the archive by writing a new file and renaming it
    /// into place leaves the original inode readable and the format unaffected, while an
    /// **in-place** modification or a truncation of the same inode does reach it.
    ///
    /// # Errors
    ///
    /// An [`ArchiveError`] if `path` cannot be opened, the archive cannot be read, or an
    /// entry cannot be represented.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ArchiveError> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let members = blocks::read_members_seeking(&file)?;
        let backing = (Arc::new(file), path.to_path_buf());
        let entries = members
            .into_iter()
            .map(|m| parse_entry(m, Some(&backing)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries })
    }

    /// The number of entries parsed, counting the archive's root member when it has
    /// one.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the archive contributed no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Source for ArchiveSource {
    fn into_entries(self) -> Vec<SourceEntry> {
        self.entries
    }
}

/// The PAX records this source understands, gathered before the entry body is read.
/// The two ACLs are parsed as they are collected, since a record may carry either the
/// text or the binary form of one.
#[derive(Default)]
struct Pax {
    uid: Option<u64>,
    gid: Option<u64>,
    atime: Option<Timestamp>,
    ctime: Option<Timestamp>,
    mtime: Option<Timestamp>,
    xattrs: Vec<Xattr>,
    acl_access: Option<Acl>,
    acl_default: Option<Acl>,
}

/// Parse one archive member into a [`SourceEntry`].
///
/// `backing` is the open archive a located body is read from later, present only for a
/// source built by [`ArchiveSource::from_path`].
fn parse_entry(
    member: Member,
    backing: Option<&(Arc<File>, PathBuf)>,
) -> Result<SourceEntry, ArchiveError> {
    let Member {
        header,
        path: raw_path,
        link,
        records,
        body,
    } = member;
    // The archive's root member (`./`) describes the filesystem root, which already
    // exists: the model applies its metadata to inode 2 rather than creating an inode.
    let path = normalize(&raw_path).unwrap_or_else(|| b"/".to_vec());

    let pax = collect_pax(&records, &path)?;
    let mode = (header.mode()? & 0o7777) as u16;
    // A PAX `uid`/`gid` record is authoritative over the header field, so ownership is
    // read from the record when the archive carries one and falls back to the header
    // otherwise — the same precedence the mtime path uses, taken from the record directly
    // rather than left to the tar layer to fold into the header. ext4 stores 32-bit ids,
    // so whichever source supplies the id is refused past that rather than truncated,
    // which would silently reassign ownership (e.g. 2^32 to root).
    let uid = match pax.uid {
        Some(id) => id,
        None => header.uid()?,
    };
    let uid = u32::try_from(uid).map_err(|_| ArchiveError::Bad {
        path: path.clone(),
        reason: "uid exceeds the 32-bit range ext4 stores",
    })?;
    let gid = match pax.gid {
        Some(id) => id,
        None => header.gid()?,
    };
    let gid = u32::try_from(gid).map_err(|_| ArchiveError::Bad {
        path: path.clone(),
        reason: "gid exceeds the 32-bit range ext4 stores",
    })?;
    // The header carries whole-second mtime; a PAX record refines it (and adds
    // sub-second precision). PAX atime/ctime fall back to the modification time. A
    // malformed header mtime is a typed error, not a silent fallback to the epoch.
    let mtime = match pax.mtime {
        Some(t) => t,
        None => {
            let secs = header.mtime().map_err(|_| ArchiveError::Bad {
                path: path.clone(),
                reason: "malformed modification time",
            })?;
            // The header carries an unsigned second count; a value past the signed range
            // ext4 stores is refused rather than truncated, which would silently reassign
            // a far-future time to a 1901-1969 date (the same guard the uid/gid path uses).
            let secs = i64::try_from(secs).map_err(|_| ArchiveError::Bad {
                path: path.clone(),
                reason: "modification time exceeds the range ext4 stores",
            })?;
            Timestamp::from_secs(secs)
        }
    };
    let meta = Metadata::new(mode, mtime).owned_by(uid, gid).with_times(
        pax.atime.unwrap_or(mtime),
        pax.ctime.unwrap_or(mtime),
        mtime,
    );

    let kind = match header.entry_type() {
        // A regular file. Its body is held whole in memory, bounded by the file's own
        // physical bytes in the archive, so peak memory stays the sum of the files' sizes.
        EntryType::Regular | EntryType::Continuous => EntryKind::File(match body {
            MemberBody::Bytes(bytes) => FileContent::Owned(bytes),
            MemberBody::Range { offset, len } => {
                let (file, archive) = backing.expect("a located body comes from a backed parse");
                FileContent::Range(FileRange::new(
                    Arc::clone(file),
                    archive.clone(),
                    offset,
                    len,
                ))
            }
        }),
        EntryType::Directory => EntryKind::Directory,
        EntryType::Symlink => EntryKind::Symlink(link_target(link, &path)?),
        EntryType::Link => {
            // A hard link's target is a path within the archive.
            let target = link_target(link, &path)?;
            let target = normalize(&target).ok_or(ArchiveError::Bad {
                path: path.clone(),
                reason: "hard link targets the archive root",
            })?;
            EntryKind::HardLink { target }
        }
        EntryType::Char => {
            let (major, minor) = device(&header, &path)?;
            EntryKind::CharDevice { major, minor }
        }
        EntryType::Block => {
            let (major, minor) = device(&header, &path)?;
            EntryKind::BlockDevice { major, minor }
        }
        EntryType::Fifo => EntryKind::Fifo,
        _ => return Err(ArchiveError::Unsupported { path }),
    };

    // Whichever form an ACL arrived in — a binary version-2 attribute or SCHILY text — it
    // leaves here as the one form every boundary speaks, and the family narrows it.
    let mut xattrs = pax.xattrs;
    if let Some(acl) = &pax.acl_access {
        xattrs.push(Xattr {
            name: Acl::ACCESS_NAME.to_vec(),
            value: acl.encode(),
        });
    }
    if let Some(acl) = &pax.acl_default {
        // A default ACL supplies the ACL children inherit, so only a directory can
        // carry one; a default ACL on any other kind is a state no kernel produces.
        if !matches!(kind, EntryKind::Directory) {
            return Err(ArchiveError::Bad {
                path,
                reason: "a default ACL on a non-directory",
            });
        }
        xattrs.push(Xattr {
            name: Acl::DEFAULT_NAME.to_vec(),
            value: acl.encode(),
        });
    }

    Ok(SourceEntry {
        path,
        kind,
        meta,
        xattrs,
    })
}

/// Take a symlink or hard link's target, which a link must have.
fn link_target(link: Option<Vec<u8>>, path: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    link.ok_or(ArchiveError::Bad {
        path: path.to_vec(),
        reason: "link has no target",
    })
}

/// Read a device node's major/minor numbers.
fn device(header: &tar::Header, path: &[u8]) -> Result<(u32, u32), ArchiveError> {
    let major = header.device_major()?.ok_or(ArchiveError::Bad {
        path: path.to_vec(),
        reason: "device has no major number",
    })?;
    let minor = header.device_minor()?.ok_or(ArchiveError::Bad {
        path: path.to_vec(),
        reason: "device has no minor number",
    })?;
    Ok((major, minor))
}

/// Interpret a member's PAX records into the typed values the model consumes.
fn collect_pax(records: &[PaxRecord], path: &[u8]) -> Result<Pax, ArchiveError> {
    let mut pax = Pax::default();
    // `libarchive` (bsdtar) writes each attribute twice: a `SCHILY.xattr.NAME` record
    // with the raw value and a `LIBARCHIVE.xattr.<percent-encoded>` record with a base64
    // one. The percent-decoded names are held until the whole set is read, then each is
    // reconciled against the `SCHILY` records: a duplicate is dropped, since the `SCHILY`
    // form already carries the value, and only a `LIBARCHIVE` record with no counterpart
    // is a lone attribute this crate cannot represent.
    let mut libarchive_names: Vec<Vec<u8>> = Vec::new();
    // Where each attribute name landed in `pax.xattrs`, so a repeat and the
    // reconciliation below are both one lookup. An archive is the documented untrusted
    // input, and a member may carry any number of records — a scan of the gathered list
    // per record would hand it a quadratic cost for linear bytes.
    let mut placed: HashMap<Vec<u8>, usize> = HashMap::new();
    for record in records {
        let key = record.key.as_slice();
        let value = record.value.as_slice();
        if key.starts_with(b"GNU.sparse.") {
            // A GNU-1.0 PAX sparse member stores a hole map in these records and a
            // mangled path; reading its body as-is would store the map, not the file.
            // It is refused rather than silently corrupted.
            return Err(ArchiveError::Bad {
                path: path.to_vec(),
                reason: "PAX-format sparse files are not supported",
            });
        } else if let Some(name) = key.strip_prefix(b"LIBARCHIVE.xattr.") {
            // Held for reconciliation once every SCHILY record has been seen.
            libarchive_names.push(percent_decode(name));
        } else if let Some(name) = key.strip_prefix(b"SCHILY.xattr.") {
            // A `system.posix_acl_*` attribute holds the version-2 ACL form the syscall
            // boundary uses, but ext4 stores the compact version-1 form; passing the
            // bytes through verbatim would write an ACL the kernel misparses. It is
            // decoded here and re-encoded with the ACL the text records produce.
            if name == Acl::ACCESS_NAME {
                pax.acl_access = Some(decode_acl_xattr(value, path)?);
            } else if name == Acl::DEFAULT_NAME {
                pax.acl_default = Some(decode_acl_xattr(value, path)?);
            } else {
                // Duplicate xattr names last-win: a later record replaces an earlier
                // one's value, so the region the model sees never carries a name twice.
                match placed.entry(name.to_vec()) {
                    Entry::Occupied(at) => pax.xattrs[*at.get()].value = value.to_vec(),
                    Entry::Vacant(slot) => {
                        slot.insert(pax.xattrs.len());
                        pax.xattrs.push(Xattr {
                            name: name.to_vec(),
                            value: value.to_vec(),
                        });
                    }
                }
            }
        } else if key == b"SCHILY.acl.access" {
            pax.acl_access = Some(parse_acl_text(value, path)?);
        } else if key == b"SCHILY.acl.default" {
            pax.acl_default = Some(parse_acl_text(value, path)?);
        } else if key == b"uid" {
            pax.uid = Some(parse_pax_id(value, "invalid PAX uid", path)?);
        } else if key == b"gid" {
            pax.gid = Some(parse_pax_id(value, "invalid PAX gid", path)?);
        } else if key == b"atime" {
            pax.atime = parse_pax_time(value, path)?;
        } else if key == b"ctime" {
            pax.ctime = parse_pax_time(value, path)?;
        } else if key == b"mtime" {
            pax.mtime = parse_pax_time(value, path)?;
        }
    }
    // Reconcile the held LIBARCHIVE names against what the SCHILY records supplied. A
    // name that arrived as a SCHILY xattr or a POSIX ACL is already carried; a name that
    // did not is a lone attribute whose value lives only in the base64 LIBARCHIVE record,
    // which this crate does not decode, so it is refused rather than silently dropped.
    for name in libarchive_names {
        let carried = placed.contains_key(&name)
            || (name == Acl::ACCESS_NAME && pax.acl_access.is_some())
            || (name == Acl::DEFAULT_NAME && pax.acl_default.is_some());
        if !carried {
            return Err(ArchiveError::Bad {
                path: path.to_vec(),
                reason: "a LIBARCHIVE.xattr record has no SCHILY counterpart to read it from",
            });
        }
    }
    Ok(pax)
}

/// Percent-decode a `LIBARCHIVE.xattr.*` attribute name: `libarchive` encodes a byte
/// outside the printable-ASCII range as `%XX`. A stray `%` not followed by two hex
/// digits is left as itself, matching how a permissive decoder reads a name that was
/// never encoded.
fn percent_decode(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    let mut i = 0;
    while i < name.len() {
        if name[i] == b'%'
            && i + 2 < name.len()
            && let (Some(hi), Some(lo)) = (hex_digit(name[i + 1]), hex_digit(name[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(name[i]);
        i += 1;
    }
    out
}

/// The value of one hexadecimal digit, or `None` for any other byte.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a PAX `uid`/`gid` record: an unsigned decimal id. The narrowing to the 32 bits
/// ext4 stores happens at the call site, so the header and PAX paths share one bound.
fn parse_pax_id(value: &[u8], reason: &'static str, path: &[u8]) -> Result<u64, ArchiveError> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ArchiveError::Bad {
            path: path.to_vec(),
            reason,
        })
}

/// Parse a PAX time record: decimal seconds with an optional fractional part.
fn parse_pax_time(value: &[u8], path: &[u8]) -> Result<Option<Timestamp>, ArchiveError> {
    let text = std::str::from_utf8(value).map_err(|_| ArchiveError::Bad {
        path: path.to_vec(),
        reason: "non-UTF-8 PAX time",
    })?;
    let (secs_str, frac_str) = match text.split_once('.') {
        Some((s, f)) => (s, f),
        None => (text, ""),
    };
    let mut secs: i64 = secs_str.parse().map_err(|_| ArchiveError::Bad {
        path: path.to_vec(),
        reason: "invalid PAX time seconds",
    })?;
    // Up to nine fractional digits, right-padded to nanoseconds.
    //
    // The fraction is held to being digits before anything is derived from its length, and
    // that order is the whole of the check. Taking nine *characters* and then measuring
    // their length in *bytes* is not the same count: one multi-byte character makes the
    // scale below underflow, and it does so before the parse that would have refused the
    // input. Rejecting first also refuses `0.+5`, which Rust's integer parser accepts as a
    // signed five and which is not a fraction any archiver writes.
    let mut nanos: u32 = 0;
    if !frac_str.is_empty() {
        if !frac_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ArchiveError::Bad {
                path: path.to_vec(),
                reason: "invalid PAX time fraction",
            });
        }
        // Every byte is an ASCII digit, so nine bytes are nine characters and the slice
        // lands on a character boundary. At most nine digits parse to under a billion, and
        // scaling by the digits that are missing keeps it there.
        let digits = &frac_str[..frac_str.len().min(9)];
        let parsed: u32 = digits.parse().map_err(|_| ArchiveError::Bad {
            path: path.to_vec(),
            reason: "invalid PAX time fraction",
        })?;
        nanos = parsed * 10u32.pow(9 - digits.len() as u32);
    }
    // A negative time with a fraction is `secs.frac` below zero, i.e. the whole seconds
    // floored and the fraction its distance up to the next second. The seconds token
    // carries the sign, so a bare `-0.x` is detected from the raw text, not its parse.
    if nanos != 0 && (secs < 0 || secs_str.starts_with('-')) {
        // A crafted `i64::MIN` seconds token has no representable floor, so the borrow is
        // checked: it is refused as an invalid time rather than wrapping to a positive
        // value (release) or panicking (debug).
        secs = secs.checked_sub(1).ok_or(ArchiveError::Bad {
            path: path.to_vec(),
            reason: "invalid PAX time seconds",
        })?;
        nanos = 1_000_000_000 - nanos;
    }
    Ok(Some(Timestamp { secs, nanos }))
}

/// Parse a binary `system.posix_acl_*` attribute — the version-2 form an archiver
/// copies straight from `getxattr` — into an ACL.
fn decode_acl_xattr(value: &[u8], path: &[u8]) -> Result<Acl, ArchiveError> {
    Acl::decode(value).map_err(|source| ArchiveError::Acl {
        path: path.to_vec(),
        source,
    })
}

/// Parse a `SCHILY.acl.*` text record into an ACL.
///
/// The record is a comma-separated list of entries in the POSIX text form, tags
/// either spelled out (`user`) or abbreviated (`u`), named users and groups
/// carrying a numeric id: `u::rwx,u:1000:rw-,g::r-x,m::rwx,o::r--`.
fn parse_acl_text(value: &[u8], path: &[u8]) -> Result<Acl, ArchiveError> {
    let bad = |reason: &'static str| ArchiveError::Bad {
        path: path.to_vec(),
        reason,
    };
    let text = std::str::from_utf8(value).map_err(|_| bad("non-UTF-8 ACL text"))?;
    let mut entries = Vec::new();
    for token in text.split([',', '\n']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        // Drop any "#effective:..." comment the text form may append.
        let token = token.split('#').next().unwrap_or(token).trim();
        let fields: Vec<&str> = token.split(':').map(str::trim).collect();
        // Every entry is tag:qualifier:perms; a missing permissions field (e.g. a bare
        // `u:1000` or `mask`) is malformed, not a zero-permission entry.
        if fields.len() < 3 {
            return Err(bad("ACL entry missing its permissions field"));
        }
        let tag = fields[0];
        let qualifier = fields[1];
        let perm = parse_acl_perm(fields[2]).ok_or(bad("invalid ACL permissions"))?;
        // Some producers append a fourth numeric-id field to a named qualifier
        // (`user:lisa:rw-:502`); when present it is the authoritative id.
        let extra_id = fields.get(3).copied();
        let who = match tag {
            "user" | "u" => named_qualifier(
                qualifier,
                extra_id,
                AclQualifier::UserObj,
                AclQualifier::User,
                || bad("invalid or unresolved ACL user"),
            )?,
            "group" | "g" => named_qualifier(
                qualifier,
                extra_id,
                AclQualifier::GroupObj,
                AclQualifier::Group,
                || bad("invalid or unresolved ACL group"),
            )?,
            "mask" | "m" => AclQualifier::Mask,
            "other" | "o" => AclQualifier::Other,
            _ => return Err(bad("unknown ACL tag")),
        };
        entries.push(AclEntry { who, perm });
    }
    Acl::new(entries).map_err(|source| ArchiveError::Acl {
        path: path.to_vec(),
        source,
    })
}

/// Resolve a user/group ACL qualifier to its typed form. A fourth numeric-id field is
/// authoritative when present (so a named entry carrying its id, or an empty-qualifier
/// entry with an id, resolves to the id); otherwise an empty qualifier is the object
/// entry and a numeric qualifier is that id. A named qualifier with no numeric id
/// cannot be resolved without a name service, so it is an error.
fn named_qualifier(
    qualifier: &str,
    extra_id: Option<&str>,
    object: AclQualifier,
    named: fn(u32) -> AclQualifier,
    err: impl Fn() -> ArchiveError,
) -> Result<AclQualifier, ArchiveError> {
    if let Some(id) = extra_id {
        return Ok(named(id.parse().map_err(|_| err())?));
    }
    if qualifier.is_empty() {
        return Ok(object);
    }
    match qualifier.parse() {
        Ok(id) => Ok(named(id)),
        Err(_) => Err(err()),
    }
}

/// Parse an ACL permission field: the letters `rwx` (with `-` for an absent bit).
fn parse_acl_perm(text: &str) -> Option<u16> {
    let mut perm = 0u16;
    for c in text.chars() {
        match c {
            'r' => perm |= Acl::READ,
            'w' => perm |= Acl::WRITE,
            'x' => perm |= Acl::EXEC,
            '-' => {}
            _ => return None,
        }
    }
    Some(perm)
}

/// Normalize an archive path to an absolute filesystem path, or `None` when it names
/// the archive root and so has no components. Leading `./` and `/` and trailing `/`
/// are stripped and a single leading `/` is added.
fn normalize(raw: &[u8]) -> Option<Vec<u8>> {
    let mut p = raw;
    while let Some(rest) = p.strip_prefix(b"./") {
        p = rest;
    }
    while let Some(rest) = p.strip_prefix(b"/") {
        p = rest;
    }
    while p.last() == Some(&b'/') {
        p = &p[..p.len() - 1];
    }
    if p.is_empty() || p == b"." {
        return None;
    }
    let mut out = Vec::with_capacity(p.len() + 1);
    out.push(b'/');
    out.extend_from_slice(p);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_and_anchors() {
        assert_eq!(normalize(b"./etc/hostname").unwrap(), b"/etc/hostname");
        assert_eq!(normalize(b"bin/sh").unwrap(), b"/bin/sh");
        assert_eq!(normalize(b"var/log/").unwrap(), b"/var/log");
        assert_eq!(normalize(b"."), None);
        assert_eq!(normalize(b"./"), None);
        assert_eq!(normalize(b"/"), None);
    }

    #[test]
    fn pax_time_parses_seconds_and_fraction() {
        let t = parse_pax_time(b"1700000000.5", b"/x").unwrap().unwrap();
        assert_eq!(t.secs, 1_700_000_000);
        assert_eq!(t.nanos, 500_000_000);
        let t = parse_pax_time(b"42", b"/x").unwrap().unwrap();
        assert_eq!(t, Timestamp::from_secs(42));
    }

    #[test]
    fn acl_text_parses_abbreviated_and_full() {
        let acl = parse_acl_text(b"u::rwx,u:1000:rw-,g::r-x,m::rwx,o::r--", b"/x").unwrap();
        let entries = acl.entries();
        assert_eq!(entries[0].who, AclQualifier::UserObj);
        assert_eq!(entries[0].perm, Acl::READ | Acl::WRITE | Acl::EXEC);
        assert!(entries.iter().any(|e| e.who == AclQualifier::User(1000)));
        // The full spelling parses the same.
        let full = parse_acl_text(b"user::rwx,group::r-x,other::r--", b"/x").unwrap();
        assert_eq!(full.entries().len(), 3);
    }

    #[test]
    fn acl_perm_rejects_junk() {
        assert_eq!(
            parse_acl_perm("rwx"),
            Some(Acl::READ | Acl::WRITE | Acl::EXEC)
        );
        assert_eq!(parse_acl_perm("r--"), Some(Acl::READ));
        assert_eq!(parse_acl_perm("rwq"), None);
    }

    #[test]
    fn pax_time_handles_negative_fractions() {
        // A negative time floors the seconds and complements the fraction: -5.25 is
        // -6 + 0.75, and the sign of a bare -0.x survives from the raw text.
        let t = parse_pax_time(b"-5.25", b"/x").unwrap().unwrap();
        assert_eq!((t.secs, t.nanos), (-6, 750_000_000));
        let t = parse_pax_time(b"-0.5", b"/x").unwrap().unwrap();
        assert_eq!((t.secs, t.nanos), (-1, 500_000_000));
        // A whole negative second is unchanged.
        let t = parse_pax_time(b"-1", b"/x").unwrap().unwrap();
        assert_eq!((t.secs, t.nanos), (-1, 0));
    }

    #[test]
    fn pax_time_refuses_a_fraction_that_is_not_digits() {
        // Nine characters are not nine bytes. A fraction whose first nine characters run
        // past nine bytes made the padding scale underflow — panicking in a debug build and
        // wrapping in a release one, where the wrapped exponent produced an arbitrary
        // nanosecond value that reached the on-disk timestamp. The check on the digits comes
        // first, so nothing is computed from a length that is not the count it was taken as.
        for value in [
            &b"1.12345678\xc3\xa9"[..],
            b"1.\xc3\xa9",
            b"1.\xe4\xb8\x80\xe4\xb8\x80\xe4\xb8\x80\xe4\xb8\x80\xe4\xb8\x80",
            b"1.123456789\xc3\xa9",
            // Rust's integer parser takes a leading sign; a fraction does not have one.
            b"0.+5",
            b"0.-5",
            b"1. 5",
        ] {
            let err = match parse_pax_time(value, b"/x") {
                Err(e) => e,
                Ok(t) => panic!("{value:?} is not a time, got {t:?}"),
            };
            assert!(
                matches!(err, ArchiveError::Bad { reason, .. } if reason.contains("fraction")),
                "{value:?}: {err:?}"
            );
        }
        // And a long fraction of real digits is still truncated to nanoseconds rather than
        // refused, which is what the bound is for.
        let t = parse_pax_time(b"1.123456789987654321", b"/x")
            .unwrap()
            .unwrap();
        assert_eq!((t.secs, t.nanos), (1, 123_456_789));
    }

    #[test]
    fn pax_time_refuses_the_unfloorable_minimum() {
        // `i64::MIN` seconds with a fraction has no representable floor: the borrow that
        // turns `secs.frac` into a floored second would overflow. A crafted archive must
        // get a typed refusal, never a debug panic or a release wrap to a positive time.
        let err = parse_pax_time(b"-9223372036854775808.5", b"/x").unwrap_err();
        assert!(matches!(err, ArchiveError::Bad { reason, .. } if reason.contains("seconds")));
        // The same seconds with no fraction takes no borrow and is a valid time.
        let t = parse_pax_time(b"-9223372036854775808", b"/x")
            .unwrap()
            .unwrap();
        assert_eq!((t.secs, t.nanos), (i64::MIN, 0));
    }

    #[test]
    fn acl_text_resolves_named_and_four_field_qualifiers() {
        // A four-field entry carries the numeric id, so a named user resolves to it and
        // an empty-qualifier-with-id is that user, not the owner entry.
        let acl = parse_acl_text(b"u::rwx,u:lisa:rw-:502,g::r-x,m::rwx,o::r--", b"/x").unwrap();
        assert!(
            acl.entries()
                .iter()
                .any(|e| e.who == AclQualifier::User(502))
        );
        let acl = parse_acl_text(b"u::rwx,u::rw-:502,g::r-x,m::rwx,o::r--", b"/x").unwrap();
        // 502 is a distinct user entry, not a second owner entry.
        assert!(
            acl.entries()
                .iter()
                .any(|e| e.who == AclQualifier::User(502))
        );
    }

    #[test]
    fn acl_text_rejects_a_missing_permissions_field_and_unresolved_name() {
        // A two-field entry has no permissions field; a bare `mask` has none either.
        assert!(parse_acl_text(b"u::rwx,u:1000,g::r-x,m::rwx,o::r--", b"/x").is_err());
        assert!(parse_acl_text(b"u::rwx,mask,g::r-x,o::r--", b"/x").is_err());
        // A named user with no numeric id cannot be resolved without a name service.
        assert!(parse_acl_text(b"u::rwx,u:lisa:rw-,g::r-x,m::rwx,o::r--", b"/x").is_err());
    }
}
