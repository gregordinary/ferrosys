//! A [`Source`] backed by a tar archive with PAX extensions.
//!
//! [`ArchiveSource`] parses a tar stream into the [`SourceEntry`] list the model
//! consumes, carrying the fidelity a package-built rootfs needs: ownership and mode
//! bits, access/change/modification times (the latter two from PAX records), fast
//! and slow symlinks, hard links, device / FIFO nodes, extended attributes from
//! `SCHILY.xattr.*` records, and POSIX ACLs — from the text form of a
//! `SCHILY.acl.access` / `SCHILY.acl.default` record, or from the binary version-2
//! form of a `system.posix_acl_*` attribute — which it translates into ext4's on-disk
//! ACL bytes (see [`crate::acl`]).
//!
//! An archive's own root member (`./`) describes the filesystem root: its mode,
//! ownership, times, and extended attributes become the root directory's.
//!
//! Parsing is eager and fallible: [`ArchiveSource::from_reader`] reads the whole
//! archive up front and returns an [`ArchiveError`] on a malformed or unsupported
//! entry, so the [`Source`] the model later consumes is infallible. An entry type
//! the model cannot represent is a typed error, never a silently dropped entry.
//!
//! Framing the tar stream and parsing its PAX records is this module's own work
//! (see `blocks`), so a PAX value carrying any byte — a newline included, which a
//! binary ACL naming user or group 10 produces — is read intact.

use std::io::Read;

use tar::EntryType;

use crate::acl::{Acl, AclEntry, AclQualifier, EXEC, READ, WRITE};
use crate::ondisk::{Timestamp, Xattr};
use crate::source::{EntryKind, Metadata, Source, SourceEntry};

mod blocks;

use blocks::{Member, PaxRecord};

/// A failure reading or interpreting a tar archive.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// An I/O error reading the archive stream.
    #[error("reading archive: {0}")]
    Io(#[from] std::io::Error),
    /// An entry could not be interpreted.
    #[error("archive entry {}: {reason}", String::from_utf8_lossy(path))]
    Bad {
        /// The offending entry's path.
        path: Vec<u8>,
        /// What was wrong.
        reason: &'static str,
    },
    /// An entry has a type the model cannot represent.
    #[error(
        "archive entry {} has an unsupported type",
        String::from_utf8_lossy(path)
    )]
    Unsupported {
        /// The offending entry's path.
        path: Vec<u8>,
    },
    /// The archive's block structure, a header checksum, or a PAX extended header
    /// could not be read. The failure is in the framing rather than in one entry,
    /// so it names no path.
    #[error("malformed archive: {reason}")]
    Malformed {
        /// What was wrong.
        reason: &'static str,
    },
    /// A `SCHILY.acl.*` record could not be translated into a valid ACL.
    #[error(
        "archive entry {} has an invalid ACL: {source}",
        String::from_utf8_lossy(path)
    )]
    Acl {
        /// The offending entry's path.
        path: Vec<u8>,
        /// The underlying ACL error.
        source: crate::acl::AclError,
    },
}

/// A [`Source`] that yields the entries parsed from a tar archive.
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
            .map(parse_entry)
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
fn parse_entry(member: Member) -> Result<SourceEntry, ArchiveError> {
    let Member {
        header,
        path: raw_path,
        link,
        records,
        data,
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
        EntryType::Regular | EntryType::Continuous => EntryKind::File(data),
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

    // Whichever form an ACL arrived in, it reaches the disk as ext4's compact bytes.
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
                // Duplicate xattr names last-win: a later record replaces an earlier one,
                // so the region the model sees never carries a name twice.
                let name = name.to_vec();
                pax.xattrs.retain(|x| x.name != name);
                pax.xattrs.push(Xattr {
                    name,
                    value: value.to_vec(),
                });
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
        let carried = pax.xattrs.iter().any(|x| x.name == name)
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
    // Take up to nine fractional digits, right-padded to nanoseconds.
    let mut nanos: u32 = 0;
    if !frac_str.is_empty() {
        let digits: String = frac_str.chars().take(9).collect();
        let scale = 9 - digits.len() as u32;
        let parsed: u32 = digits.parse().map_err(|_| ArchiveError::Bad {
            path: path.to_vec(),
            reason: "invalid PAX time fraction",
        })?;
        nanos = parsed * 10u32.pow(scale);
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
    Acl::decode_xattr_v2(value).map_err(|source| ArchiveError::Acl {
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
            'r' => perm |= READ,
            'w' => perm |= WRITE,
            'x' => perm |= EXEC,
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
        assert_eq!(entries[0].perm, READ | WRITE | EXEC);
        assert!(entries.iter().any(|e| e.who == AclQualifier::User(1000)));
        // The full spelling parses the same.
        let full = parse_acl_text(b"user::rwx,group::r-x,other::r--", b"/x").unwrap();
        assert_eq!(full.entries().len(), 3);
    }

    #[test]
    fn acl_perm_rejects_junk() {
        assert_eq!(parse_acl_perm("rwx"), Some(READ | WRITE | EXEC));
        assert_eq!(parse_acl_perm("r--"), Some(READ));
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
