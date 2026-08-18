//! Names: the UTF-16 a directory entry set carries, the folding two names are compared
//! through, and the hash that lets a driver skip a set without reassembling the name in it.
//!
//! exFAT stores one name per file and stores it whole. There is no second, shortened name to
//! derive and no collision to number around — a name is up to 255 UTF-16 code units, carried
//! fifteen at a time in the entries behind the file's stream extension, and what a caller
//! wrote is what a driver reads back.
//!
//! # A name that does not fit is refused, never shortened
//!
//! A name is what a file is found by. Substituting one would hand back a tree whose entries
//! are not the entries that were asked for, so every limit here is a refusal naming the path
//! it happened on.
//!
//! # Two names one directory cannot hold
//!
//! Every exFAT lookup compares names through the volume's own up-case table, so `README` and
//! `readme` in one directory are one name to every driver that reads the volume: a lookup has
//! two answers and returns whichever it met first, and the other file is unreachable by its
//! own name. Such a pair is refused before a byte is written, with both paths named.
//!
//! The comparison is the *volume's*, not this crate's idea of case. That is the whole reason
//! [`UpcaseTable`] is a value built from the table a volume
//! carries rather than a function: folding through anything else would refuse pairs a driver
//! would have told apart, and — far worse — accept pairs it will not.

pub use crate::exfat::ondisk::MAX_NAME_UNITS;

use crate::exfat::ondisk::{NAME_UNITS_PER_ENTRY, UpcaseTable, name_hash};
use crate::path::is_reserved_name_char;

/// A name an exFAT directory cannot hold.
///
/// Every one of these is a refusal rather than a fidelity loss, for the reason the module
/// states: a name is the thing a file is found by.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// The name is not valid UTF-8, so it has no UTF-16 form to store.
    ///
    /// A source path is a byte string, which on a POSIX host need not be text at all. An
    /// exFAT name is a sequence of UTF-16 code units, so a name this crate cannot decode is
    /// one the format cannot represent.
    #[error("the name is not valid UTF-8, so it has no UTF-16 form a name entry holds")]
    NotUtf8,
    /// The name is empty.
    #[error("the name is empty")]
    Empty,
    /// The name needs more code units than the format holds.
    #[error("a name of {units} UTF-16 code units exceeds the {limit} the format holds")]
    #[non_exhaustive]
    TooLong {
        /// Code units the name needs.
        units: usize,
        /// Code units the format holds.
        limit: usize,
    },
    /// The name contains a character a driver would interpret rather than store.
    #[error("{ch:?} is not a character an exFAT name may contain")]
    #[non_exhaustive]
    ForbiddenCharacter {
        /// The offending character.
        ch: char,
    },
    /// The name ends in a dot or a space, which the interfaces callers reach this format
    /// through strip when they create a name — so the entry would not be found under the name
    /// it was written with.
    #[error("a name ending in a dot or a space is not one a driver reads back unchanged")]
    TrailingDotOrSpace,
}

/// A name as a directory will store it: its code units, and the hash of its folded form.
///
/// The folded form itself is not kept. It is needed twice while a name is placed — once for
/// the hash, once as the key that catches a pair no directory can hold — and never again, so
/// carrying it would be carrying a second copy of every name in the tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct PlacedName {
    /// The name's UTF-16 code units, as the name entries carry them.
    pub units: Vec<u16>,
    /// The hash of the up-cased name, which the stream extension records.
    pub hash: u16,
}

impl PlacedName {
    /// Directory entries this name's set occupies: the file entry, its stream extension, and
    /// one name entry per fifteen code units.
    pub(crate) fn slots(&self) -> u32 {
        // A name is at most 255 units, so the count fits with room to spare.
        2 + self.units.len().div_ceil(NAME_UNITS_PER_ENTRY) as u32
    }

    /// The value the file entry's `SecondaryCount` records: everything in the set but the file
    /// entry itself.
    pub(crate) fn secondary_count(&self) -> u8 {
        // Bounded by `MAX_NAME_UNITS`, which puts the largest count at eighteen.
        (self.slots() - 1) as u8
    }
}

/// The name `name` becomes, and the key that decides whether the directory can hold it —
/// or the reason the format cannot store it.
///
/// The key is the up-cased name, which is what every driver compares through. Two entries in
/// one directory whose keys match describe a directory a lookup has two answers in, and the
/// caller refuses the pair rather than writing it.
pub(crate) fn place(
    name: &[u8],
    upcase: &UpcaseTable,
) -> Result<(PlacedName, Vec<u16>), NameError> {
    let text = core::str::from_utf8(name).map_err(|_| NameError::NotUtf8)?;
    if text.is_empty() {
        return Err(NameError::Empty);
    }
    for ch in text.chars() {
        if is_reserved_name_char(ch) {
            return Err(NameError::ForbiddenCharacter { ch });
        }
    }
    if text.ends_with('.') || text.ends_with(' ') {
        return Err(NameError::TrailingDotOrSpace);
    }
    let units: Vec<u16> = text.encode_utf16().collect();
    if units.len() > MAX_NAME_UNITS {
        return Err(NameError::TooLong {
            units: units.len(),
            limit: MAX_NAME_UNITS,
        });
    }
    // Folded once and used twice: the hash is taken over exactly the form a lookup compares,
    // which is what makes a hash miss and a name mismatch the same event on the volume.
    let folded = upcase.fold(&units);
    let hash = name_hash(&folded);
    Ok((PlacedName { units, hash }, folded))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name `name` places to, through the folding this crate's writer lays down.
    fn placed(name: &str) -> Result<(PlacedName, Vec<u16>), NameError> {
        place(name.as_bytes(), &UpcaseTable::recommended())
    }

    #[test]
    fn a_name_is_stored_as_the_units_it_was_given() {
        // Whole and unchanged, which is the difference between this format and the one it
        // shares a name with: no case folding on the way in, no shortened second name, no
        // substitution.
        let (name, _) = placed("A Long Name.txt").expect("a name the format holds");
        assert_eq!(
            name.units,
            "A Long Name.txt".encode_utf16().collect::<Vec<_>>()
        );

        let (unicode, _) = placed("Ünïcode — 名前").expect("a name the format holds");
        assert_eq!(
            String::from_utf16(&unicode.units).expect("well-formed"),
            "Ünïcode — 名前"
        );
    }

    #[test]
    fn a_set_is_the_two_leading_entries_and_one_per_fifteen_units() {
        for (units, slots, secondary) in [
            (1, 3, 2),
            (15, 3, 2),
            (16, 4, 3),
            (30, 4, 3),
            (31, 5, 4),
            (255, 19, 18),
        ] {
            let (name, _) = placed(&"a".repeat(units)).expect("a name the format holds");
            assert_eq!(name.slots(), slots, "{units} units");
            assert_eq!(name.secondary_count(), secondary, "{units} units");
        }
    }

    #[test]
    fn the_hash_is_taken_over_the_folded_name_so_two_spellings_hash_alike() {
        // What the field is for: a driver compares hashes to skip a set without reassembling
        // the name in it, and it looks the name up case-insensitively. A hash over the name as
        // written would make `README` invisible to a lookup for `readme`.
        let (upper, _) = placed("README.TXT").expect("a name");
        let (lower, _) = placed("readme.txt").expect("a name");
        let (mixed, _) = placed("ReadMe.Txt").expect("a name");
        assert_eq!(upper.hash, lower.hash);
        assert_eq!(upper.hash, mixed.hash);
        assert_ne!(upper.units, lower.units, "the stored names still differ");

        let (other, _) = placed("README.TX").expect("a name");
        assert_ne!(upper.hash, other.hash);
    }

    #[test]
    fn the_key_is_the_volumes_folding_rather_than_the_hosts_idea_of_case() {
        // Two names one directory cannot hold, keyed alike; and two it can, keyed apart.
        let key = |name: &str| placed(name).expect("a name").1;
        assert_eq!(key("README"), key("readme"));
        assert_eq!(key("Ünïcode"), key("ÜNÏCODE"));
        assert_ne!(key("README"), key("READ_ME"));

        // The two characters whose case the host and the volume disagree about. ß has no
        // single upper-case form and the dotless ı upper-cases to I only under a Turkish
        // locale, so a fold through the host's rules would key each with something the volume
        // keys apart — refusing a pair every driver reading the volume tells apart.
        assert_ne!(key("stra\u{00DF}e"), key("STRASSE"));
        assert_ne!(key("\u{0131}"), key("I"));
    }

    #[test]
    fn a_name_the_format_cannot_hold_is_refused_by_name() {
        for (name, expected) in [
            (&b""[..], NameError::Empty),
            (b"a/b", NameError::ForbiddenCharacter { ch: '/' }),
            (b"a:b", NameError::ForbiddenCharacter { ch: ':' }),
            (b"a*b", NameError::ForbiddenCharacter { ch: '*' }),
            (b"a?b", NameError::ForbiddenCharacter { ch: '?' }),
            (b"a\\b", NameError::ForbiddenCharacter { ch: '\\' }),
            (b"a|b", NameError::ForbiddenCharacter { ch: '|' }),
            (b"a\"b", NameError::ForbiddenCharacter { ch: '"' }),
            (b"a<b", NameError::ForbiddenCharacter { ch: '<' }),
            (b"a>b", NameError::ForbiddenCharacter { ch: '>' }),
            (b"a\tb", NameError::ForbiddenCharacter { ch: '\t' }),
            (b"trailing.", NameError::TrailingDotOrSpace),
            (b"trailing ", NameError::TrailingDotOrSpace),
            (b"\xFF\xFE", NameError::NotUtf8),
        ] {
            assert_eq!(
                place(name, &UpcaseTable::recommended()).unwrap_err(),
                expected,
                "{}",
                crate::escape::printable(name)
            );
        }
    }

    #[test]
    fn a_name_is_bounded_by_the_field_and_not_by_its_characters() {
        assert!(placed(&"a".repeat(MAX_NAME_UNITS)).is_ok());
        assert!(matches!(
            placed(&"a".repeat(MAX_NAME_UNITS + 1)),
            Err(NameError::TooLong { limit: 255, .. })
        ));

        // Units, not characters: a character outside the Basic Multilingual Plane is a
        // surrogate pair and costs two, so 128 of them overrun a field 255 wide while 127 fit.
        assert!(placed(&"\u{1F600}".repeat(127)).is_ok());
        assert!(matches!(
            placed(&"\u{1F600}".repeat(128)),
            Err(NameError::TooLong { units: 256, .. })
        ));
    }
}
