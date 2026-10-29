//! Firmlinks: the directories of a volume group's System volume that macOS joins to a path in
//! its Data volume.
//!
//! A firmlinked directory carries two marks, both on the directory itself: the BSD flag
//! [`FIRMLINK_FLAG`] beside whatever flags it has, and the attribute [`FIRMLINK_XATTR`], whose
//! value is the path it joins, relative to the Data volume's root, and a NUL. macOS 15, 26 and 27
//! keep the directories their own lists name that way.
//!
//! The list is a file of one line per firmlink: the directory's absolute path in the System
//! volume, a tab, and the target's path relative to the Data volume, each line ending in a
//! newline. [`Firmlinks::parse`] reads that and nothing looser.

use crate::path::{canonical_key, canonical_parts};
use crate::source::{Darwin, EntryKind, SourceEntry};
use crate::xattr::Xattr;

use super::materialize::FormatError;
use super::names;

/// The BSD flag a firmlinked directory carries beside its own.
pub const FIRMLINK_FLAG: u32 = 0x0080_0000;

/// The attribute a firmlinked directory carries: its target and a NUL, held in its record and
/// flagged as held there, as macOS 15, 26 and 27 hold each firmlink of their own system volumes.
pub const FIRMLINK_XATTR: &[u8] = b"com.apple.fs.firmlink";

/// The longest target a line may give, in bytes: a path macOS resolves holds at most 1,024
/// bytes with its NUL (`PATH_MAX` in its headers), so the attribute stays a short value held in
/// its record.
pub const MAX_FIRMLINK_TARGET: usize = 1023;

/// A line of a firmlink list that is not one.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FirmlinksError {
    /// The line is not two fields joined by one tab.
    #[error("line {line} is not two fields joined by one tab")]
    #[non_exhaustive]
    Fields {
        /// The line, counted from 1.
        line: usize,
    },
    /// The first field is not an absolute path.
    #[error("line {line}: the directory is not an absolute path")]
    #[non_exhaustive]
    NotAbsolute {
        /// The line, counted from 1.
        line: usize,
    },
    /// The first field names the root directory, which cannot be a firmlink.
    #[error("line {line}: the directory is the root")]
    #[non_exhaustive]
    Root {
        /// The line, counted from 1.
        line: usize,
    },
    /// The second field is empty or an absolute path.
    #[error("line {line}: the target is not a relative path")]
    #[non_exhaustive]
    NotRelative {
        /// The line, counted from 1.
        line: usize,
    },
    /// The second field is longer than [`MAX_FIRMLINK_TARGET`].
    #[error("line {line}: the target is {len} bytes, longer than a path macOS resolves")]
    #[non_exhaustive]
    TargetTooLong {
        /// The line, counted from 1.
        line: usize,
        /// The target's length in bytes.
        len: usize,
    },
    /// The line holds a NUL byte.
    #[error("line {line} holds a NUL byte")]
    #[non_exhaustive]
    Nul {
        /// The line, counted from 1.
        line: usize,
    },
    /// The line names a directory an earlier line names.
    #[error("line {line} names the directory line {first} names")]
    #[non_exhaustive]
    Repeated {
        /// The line, counted from 1.
        line: usize,
        /// The earlier line.
        first: usize,
    },
    /// The last line does not end in a newline.
    #[error("the last line does not end in a newline")]
    NoFinalNewline,
}

/// A list of firmlinks, as a volume group's System volume is given it.
///
/// ```
/// # use ferrosys::apfs::Firmlinks;
/// let links = Firmlinks::parse(b"/Shared\tShared\n/Library/Local\tLibrary/Local\n")?;
/// assert_eq!(links.len(), 2);
/// assert_eq!(
///     links.iter().next(),
///     Some((&b"/Shared"[..], &b"Shared"[..]))
/// );
/// assert!(Firmlinks::parse(b"Shared\tShared\n").is_err());
/// # Ok::<(), ferrosys::apfs::FirmlinksError>(())
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Firmlinks {
    links: Vec<Firmlink>,
}

/// One line of the list.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Firmlink {
    /// The directory's absolute path in the System volume, as the line gives it.
    directory: Vec<u8>,
    /// The target's path relative to the Data volume's root, as the line gives it.
    target: Vec<u8>,
}

impl Firmlinks {
    /// The firmlinks `text` lists.
    ///
    /// # Errors
    ///
    /// [`FirmlinksError`] for the first line that is not two fields joined by one tab, the
    /// first an absolute path other than the root and the second a relative one of at most
    /// [`MAX_FIRMLINK_TARGET`] bytes, with no NUL in either; for a line naming a directory an earlier one
    /// names; and for a list whose last line does not end in a newline.
    pub fn parse(text: &[u8]) -> Result<Self, FirmlinksError> {
        if text.is_empty() {
            return Ok(Self::default());
        }
        let Some(body) = text.strip_suffix(b"\n") else {
            return Err(FirmlinksError::NoFinalNewline);
        };
        let mut links: Vec<Firmlink> = Vec::new();
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for (line, bytes) in (1..).zip(body.split(|b| *b == b'\n')) {
            if bytes.contains(&0) {
                return Err(FirmlinksError::Nul { line });
            }
            let fields: Vec<&[u8]> = bytes.split(|b| *b == b'\t').collect();
            let [directory, target] = fields[..] else {
                return Err(FirmlinksError::Fields { line });
            };
            if !directory.starts_with(b"/") {
                return Err(FirmlinksError::NotAbsolute { line });
            }
            let key = canonical_key(directory);
            if key.is_empty() {
                return Err(FirmlinksError::Root { line });
            }
            if target.is_empty() || target.starts_with(b"/") {
                return Err(FirmlinksError::NotRelative { line });
            }
            if target.len() > MAX_FIRMLINK_TARGET {
                return Err(FirmlinksError::TargetTooLong {
                    line,
                    len: target.len(),
                });
            }
            if let Some(first) = keys.iter().position(|k| *k == key) {
                return Err(FirmlinksError::Repeated {
                    line,
                    first: first + 1,
                });
            }
            keys.push(key);
            links.push(Firmlink {
                directory: directory.to_vec(),
                target: target.to_vec(),
            });
        }
        Ok(Self { links })
    }

    /// How many firmlinks the list holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Whether the list holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Each firmlink in the order the list gives them: the directory's absolute path and the
    /// target's relative one, as the line has them.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.links
            .iter()
            .map(|link| (link.directory.as_slice(), link.target.as_slice()))
    }
}

/// Mark each directory of `entries` that `links` names as a firmlink, and answer how many were
/// marked. A line names a directory whose path the volume compares as the same, under its own
/// comparison of names, folding case where `fold` says; a line naming no entry marks nothing.
///
/// # Errors
///
/// [`FormatError::FirmlinkNotDirectory`] for a line naming an entry that is not a directory,
/// and [`FormatError::FirmlinkAttributeHeld`] for a directory already holding
/// [`FIRMLINK_XATTR`] with another value.
pub(super) fn mark(
    entries: &mut [SourceEntry],
    links: &Firmlinks,
    fold: bool,
) -> Result<usize, FormatError> {
    let mut marked = 0;
    for link in &links.links {
        let key = compared(&link.directory, fold);
        let Some(entry) = entries.iter_mut().find(|e| compared(&e.path, fold) == key) else {
            continue;
        };
        if !matches!(entry.kind, EntryKind::Directory) {
            return Err(FormatError::FirmlinkNotDirectory {
                path: link.directory.clone(),
            });
        }
        let mut value = link.target.clone();
        value.push(0);
        match entry.xattrs.iter().find(|x| x.name == FIRMLINK_XATTR) {
            Some(held) if held.value != value => {
                return Err(FormatError::FirmlinkAttributeHeld {
                    path: link.directory.clone(),
                });
            }
            Some(_) => {}
            None => entry.xattrs.push(Xattr {
                name: FIRMLINK_XATTR.to_vec(),
                value,
            }),
        }
        entry.darwin.get_or_insert_with(Darwin::default).bsd_flags |= FIRMLINK_FLAG;
        marked += 1;
    }
    Ok(marked)
}

/// `path` as the volume compares it: each component in the form its names are compared in, and
/// one that is not UTF-8, which no entry of a volume can be named, as its bytes.
fn compared(path: &[u8], fold: bool) -> Vec<Result<Vec<u32>, Vec<u8>>> {
    canonical_parts(path)
        .into_iter()
        .map(|part| names::key(part, fold).ok_or_else(|| part.to_vec()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;
    use crate::{Metadata, Timestamp, TreeBuilder};

    #[test]
    fn a_list_is_lines_of_an_absolute_directory_a_tab_and_a_relative_target() {
        let links = Firmlinks::parse(b"/a\tb\n/c/d\te/f\n").expect("a list");
        let all: Vec<_> = links.iter().collect();
        assert_eq!(all, [(&b"/a"[..], &b"b"[..]), (&b"/c/d"[..], &b"e/f"[..])]);
        assert!(Firmlinks::parse(b"").expect("an empty list").is_empty());
    }

    #[test]
    fn every_other_shape_of_line_is_refused_by_its_number() {
        use FirmlinksError as E;
        let cases: [(&[u8], FirmlinksError); 9] = [
            (b"/a\tb", E::NoFinalNewline),
            (b"/a\tb\n\n", E::Fields { line: 2 }),
            (b"/a b\n", E::Fields { line: 1 }),
            (b"/a\tb\tc\n", E::Fields { line: 1 }),
            (b"/a\tb\na\tb\n", E::NotAbsolute { line: 2 }),
            (b"//.\tb\n", E::Root { line: 1 }),
            (b"/a\t/b\n", E::NotRelative { line: 1 }),
            (b"/a\tb\0\n", E::Nul { line: 1 }),
            (
                b"/a\tb\n/c\td\n//a/\te\n",
                E::Repeated { line: 3, first: 1 },
            ),
        ];
        for (text, error) in cases {
            assert_eq!(Firmlinks::parse(text), Err(error), "{text:?}");
        }
        assert_eq!(Firmlinks::parse(b"/a\t\n"), Err(E::NotRelative { line: 1 }));
        // A target is a path macOS resolves, so it is no longer than one.
        let line = |len: usize| [&b"/a\t"[..], &vec![b'x'; len], b"\n"].concat();
        Firmlinks::parse(&line(MAX_FIRMLINK_TARGET)).expect("the longest target");
        assert_eq!(
            Firmlinks::parse(&line(5000)),
            Err(E::TargetTooLong { line: 1, len: 5000 })
        );
    }

    fn tree() -> Vec<SourceEntry> {
        let meta = Metadata::new(0o755, Timestamp::from_secs(1_700_000_000));
        TreeBuilder::new()
            .directory("/a", meta)
            .directory("/b", meta)
            .file("/f", "f", meta)
            .into_entries()
    }

    #[test]
    fn a_named_directory_gains_the_flag_beside_its_own_and_the_attribute() {
        let mut entries = tree();
        entries[0].darwin = Some(Darwin {
            bsd_flags: 0x8000,
            ..Darwin::default()
        });
        let links = Firmlinks::parse(b"/a\tx/a\n/b/\tb\n/absent\tz\n").expect("a list");
        assert_eq!(mark(&mut entries, &links, true).expect("marked"), 2);
        let flags = |e: &SourceEntry| e.darwin.as_ref().map(|d| d.bsd_flags);
        assert_eq!(flags(&entries[0]), Some(0x8000 | FIRMLINK_FLAG));
        assert_eq!(flags(&entries[1]), Some(FIRMLINK_FLAG));
        assert_eq!(entries[0].xattrs[0].name, FIRMLINK_XATTR);
        assert_eq!(entries[0].xattrs[0].value, b"x/a\0");
        assert_eq!(entries[1].xattrs[0].value, b"b\0");
        assert_eq!(flags(&entries[2]), None, "the file is untouched");
    }

    #[test]
    fn a_line_names_a_directory_as_the_volume_compares_its_names() {
        // Case folds on a volume that folds it and not on one that keeps it, and a name is one
        // whichever normalization form the line and the tree spell it in.
        let meta = Metadata::new(0o755, Timestamp::from_secs(1_700_000_000));
        let tree = || {
            TreeBuilder::new()
                .directory("/Users", meta)
                .directory("/caf\u{e9}", meta)
                .into_entries()
        };
        let links =
            Firmlinks::parse("/users\tUsers\n/cafe\u{301}\tcafe\n".as_bytes()).expect("a list");
        assert_eq!(mark(&mut tree(), &links, true).expect("marked"), 2);
        assert_eq!(mark(&mut tree(), &links, false).expect("marked"), 1);
    }

    #[test]
    fn a_firmlink_to_anything_but_a_directory_or_against_a_held_value_is_refused() {
        let links = Firmlinks::parse(b"/f\tf\n").expect("a list");
        assert!(matches!(
            mark(&mut tree(), &links, true),
            Err(FormatError::FirmlinkNotDirectory { path }) if path == b"/f"
        ));
        let mut entries = tree();
        entries[0].xattrs.push(Xattr {
            name: FIRMLINK_XATTR.to_vec(),
            value: b"other\0".to_vec(),
        });
        let links = Firmlinks::parse(b"/a\ta\n").expect("a list");
        assert!(matches!(
            mark(&mut entries, &links, true),
            Err(FormatError::FirmlinkAttributeHeld { path }) if path == b"/a"
        ));
        // The same value is the firmlink already, and is kept once.
        entries[0].xattrs[0].value = b"a\0".to_vec();
        assert_eq!(mark(&mut entries, &links, true).expect("marked"), 1);
        assert_eq!(entries[0].xattrs.len(), 1);
    }
}
