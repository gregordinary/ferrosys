//! Names: the 8.3 short name every entry must have, and the long-name entries that carry
//! the name a caller actually wrote.
//!
//! Every FAT directory entry has an eleven-byte name field holding an upper-case name of at
//! most eight characters and an extension of at most three, with no dot between them. A name
//! that is anything else — lower case, longer, punctuated differently, not ASCII — is stored
//! in a run of [`LfnEntry`] values immediately before the entry, and
//! the short name becomes a fallback that a driver without long-name support sees.
//!
//! # The short name is derived, and the derivation is pinned here
//!
//! The classic numeric-tail algorithm resolves a collision in *insertion* order, which would
//! make two formats of one tree differ. The model sorts entries by path before anything is
//! placed, so the numbering is deterministic given that order — and this module is written
//! against that guarantee rather than around it. What the rules *are* is pinned by the tests
//! below rather than inherited from any particular implementation: this crate reproduces no
//! other formatter's short names, and does not claim to.
//!
//! # A long name is written whenever the short name is not the name
//!
//! Byte 12 of a directory entry carries two bits Windows NT uses to mean "the base is lower
//! case" and "the extension is lower case", which would let `readme.txt` be one entry instead
//! of two. They are left zero. The format's own specification says that byte is reserved and
//! that an implementation must never look at it, and implementations take it at its word —
//! so a name carried only there reads back as `README.TXT` under some mount options and on
//! some firmware. Once a long name is present every driver uses it, which is the property
//! worth having.

use std::collections::HashSet;

use crate::path::is_reserved_name_char;

use super::ondisk::{
    LFN_CHARS_PER_ENTRY, LFN_LAST_ENTRY, LFN_PADDING, LfnEntry, NAME_DELETED, NAME_LEADING_E5,
    lfn_checksum, unpadded,
};

/// Bytes in the name field of a directory entry: eight of base and three of extension.
pub(crate) const SHORT_NAME_LEN: usize = 11;

/// Characters of the base, before the extension begins.
const BASE_LEN: usize = 8;

/// Characters of the extension.
const EXT_LEN: usize = 3;

/// The most code units a long name holds. The ordinal field is six bits with zero reserved,
/// so a name spans at most twenty entries of thirteen units — and the format caps the name
/// below what those entries could carry.
pub const MAX_NAME_UNITS: usize = 255;

/// The highest numeric tail this crate will assign. Seven characters of `~999999` leave one
/// of the base, which is as far as the field goes.
const MAX_TAIL: u32 = 999_999;

/// Characters a *short* name may not contain, beyond those a long name also excludes. Every
/// one of these is legal in a long name, so an entry carrying one keeps it there and takes an
/// underscore in the short name.
const SHORT_NAME_ALSO_FORBIDDEN: &[u8] = b"+,.;=[]";

/// The character an unrepresentable one becomes in a short name.
const SUBSTITUTE: u8 = b'_';

/// A name a FAT directory cannot hold.
///
/// Every one of these is a refusal rather than a fidelity loss: a name is what a file is
/// found by, so substituting one silently would hand back a tree whose entries are not the
/// entries that were asked for. [`Property::Name`](crate::Property) therefore never appears
/// in a FAT build's report — it is this error instead.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// The name is not valid UTF-8, so it has no UTF-16 form to store.
    ///
    /// A source path is a byte string, which on a POSIX host need not be text at all. A FAT
    /// long name is a sequence of UTF-16 code units, so a name this crate cannot decode is
    /// one the format cannot represent.
    #[error("the name is not valid UTF-8, so it has no UTF-16 form a long name entry holds")]
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
    #[error("{ch:?} is not a character a FAT name may contain")]
    #[non_exhaustive]
    ForbiddenCharacter {
        /// The offending character.
        ch: char,
    },
    /// The name ends in a dot or a space, which drivers strip when they create a name — so
    /// the entry would not be found under the name it was written with.
    #[error("a name ending in a dot or a space is not one a driver reads back unchanged")]
    TrailingDotOrSpace,
    /// Every numeric tail is taken: the directory already holds as many entries shortening
    /// to this same stem as the eight-character field has room to distinguish.
    #[error(
        "no short name is left for this name: all {limit} numeric tails on the stem {} are \
         taken",
        crate::escape::printable(.stem)
    )]
    #[non_exhaustive]
    TailsExhausted {
        /// The eight-character base every candidate shortens to.
        stem: Vec<u8>,
        /// The highest tail this crate assigns.
        limit: u32,
    },
}

/// A name as a directory will store it: the eleven-byte short name, and the long name where
/// the short one is not the name that was asked for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct PlacedName {
    /// The eleven-byte name field, space-padded, upper case, with no dot.
    pub short: [u8; SHORT_NAME_LEN],
    /// The name's UTF-16 code units, or `None` where the short name renders back to exactly
    /// the name that was given and no long-name entries are needed.
    pub long: Option<Vec<u16>>,
}

impl PlacedName {
    /// Directory entries this name occupies: its own, plus one per thirteen code units of
    /// any long name.
    pub fn slots(&self) -> usize {
        1 + self.lfn_count()
    }

    /// Long-name entries this name needs.
    fn lfn_count(&self) -> usize {
        match &self.long {
            Some(units) => units.len().div_ceil(LFN_CHARS_PER_ENTRY),
            None => 0,
        }
    }

    /// The long-name entries, in the order they are written — which is *reverse* name order,
    /// the final chunk first, because a forward reader meets them before the entry they
    /// belong to and reassembles backwards.
    ///
    /// Every entry carries the checksum of the short name, which is what stops a driver
    /// without long-name support from orphaning the name onto a different file: rename the
    /// short entry and the checksum stops matching, so the stale long name is ignored.
    pub fn lfn_entries(&self) -> Vec<LfnEntry> {
        let Some(units) = &self.long else {
            return Vec::new();
        };
        let checksum = lfn_checksum(&self.short);
        let chunks: Vec<&[u16]> = units.chunks(LFN_CHARS_PER_ENTRY).collect();
        let last = chunks.len() - 1;
        chunks
            .iter()
            .enumerate()
            .rev()
            .map(|(i, chunk)| {
                let mut name = [LFN_PADDING; LFN_CHARS_PER_ENTRY];
                name[..chunk.len()].copy_from_slice(chunk);
                // A name that does not fill its final entry is terminated by one zero and
                // padded after it. One that fills it exactly gets neither, which is why the
                // terminator is written here rather than appended to the units.
                if chunk.len() < LFN_CHARS_PER_ENTRY {
                    name[chunk.len()] = 0;
                }
                LfnEntry {
                    // The ordinal counts from one, and the entry holding the name's final
                    // characters is flagged — it is the last in the sequence and the first
                    // on disk.
                    order: (i as u8 + 1) | if i == last { LFN_LAST_ENTRY } else { 0 },
                    name,
                    checksum,
                }
            })
            .collect()
    }
}

/// The short names one directory has already handed out, so the next collision takes the
/// next numeric tail.
///
/// One of these per directory. The set is what makes the tail numbering meaningful and the
/// order the model feeds it — sorted by path — is what makes it reproducible.
#[derive(Default, Debug)]
pub(crate) struct DirNames {
    used: HashSet<[u8; SHORT_NAME_LEN]>,
}

impl DirNames {
    /// An empty set.
    ///
    /// The `.` and `..` entries of a subdirectory are not seeded into it and cannot collide
    /// with anything it hands out: their name fields begin with a dot, and the derivation
    /// strips every leading dot before it takes a character.
    pub fn new() -> Self {
        Self::default()
    }

    /// Place `name` in this directory, assigning a short name no other entry here has.
    ///
    /// # Errors
    ///
    /// A [`NameError`] for a name the format cannot represent, or when every numeric tail on
    /// the name's stem is already taken.
    pub fn place(&mut self, name: &[u8]) -> Result<PlacedName, NameError> {
        let units = long_name_units(name)?;
        let text = core::str::from_utf8(name).map_err(|_| NameError::NotUtf8)?;
        let (base, ext) = stem(text);

        // The plain form first: an entry whose name is already a short name takes the slot
        // that name would otherwise be shortened into, which is what keeps a literal
        // `ALONGF~1.TXT` from being shadowed by a tail assigned to some other name.
        let plain = assemble(&base, &ext);
        let short = if self.used.insert(plain) {
            plain
        } else {
            self.with_tail(&base, &ext)?
        };

        // The long name is needed exactly when the short name is not the name. Rendering and
        // comparing is the whole test: an upper-case 8.3 name renders back to itself, and
        // anything that was folded, substituted, truncated, or given a tail does not.
        let long = (render(&short) != text).then_some(units);
        Ok(PlacedName { short, long })
    }

    /// The first `BASE~n` form of this stem no entry here holds.
    fn with_tail(&mut self, base: &[u8], ext: &[u8]) -> Result<[u8; SHORT_NAME_LEN], NameError> {
        for n in 1..=MAX_TAIL {
            let mut tail = [0u8; BASE_LEN];
            let mut at = 0;
            tail[at] = b'~';
            at += 1;
            for digit in n.to_string().bytes() {
                tail[at] = digit;
                at += 1;
            }
            let tail = &tail[..at];
            // The tail is what must survive, so the base is what gives way. A base shorter
            // than the room left keeps all of itself.
            let keep = base.len().min(BASE_LEN - tail.len());
            let mut tailed = Vec::with_capacity(BASE_LEN);
            tailed.extend_from_slice(&base[..keep]);
            tailed.extend_from_slice(tail);
            let candidate = assemble(&tailed, ext);
            if self.used.insert(candidate) {
                return Ok(candidate);
            }
        }
        Err(NameError::TailsExhausted {
            stem: base.to_vec(),
            limit: MAX_TAIL,
        })
    }
}

/// The name's UTF-16 code units, or the reason the format cannot hold it.
///
/// This is where every refusal happens, so a name that reaches the derivation below is one
/// the format represents and the derivation has nothing left to reject.
fn long_name_units(name: &[u8]) -> Result<Vec<u16>, NameError> {
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
    Ok(units)
}

/// The base and extension a name shortens to, before any numeric tail.
///
/// Leading dots and spaces go first, so `.config` shortens to `CONFIG` rather than to an
/// extension; what follows the *last* remaining dot is the extension; and within each half
/// every dot and space is dropped and everything the field cannot hold becomes an
/// underscore. Both halves are then truncated to the field.
fn stem(name: &str) -> (Vec<u8>, Vec<u8>) {
    let trimmed = name.trim_start_matches(['.', ' ']);
    let (base_src, ext_src) = match trimmed.rfind('.') {
        Some(dot) => (&trimmed[..dot], &trimmed[dot + 1..]),
        None => (trimmed, ""),
    };
    let mut base = shorten(base_src, BASE_LEN);
    let ext = shorten(ext_src, EXT_LEN);
    // No legal name reaches here with an empty base: the leading dots and spaces are gone, a
    // name that was only those ends in one and was refused, and the separator is the *last*
    // dot in what remains — so the first character after the strip is always in the base. The
    // fallback stands because the alternative if that ever stopped holding is a name field of
    // eleven spaces, which is a well-formed entry for a file with no name.
    debug_assert!(
        !base.is_empty(),
        "a legal name shortened to nothing: {name:?}"
    );
    if base.is_empty() {
        base.push(SUBSTITUTE);
    }
    (base, ext)
}

/// `part` folded up, stripped of what a short name cannot hold, and truncated to `limit`.
///
/// A character outside ASCII becomes one underscore rather than one per byte: the field
/// counts characters, and a code page that could hold the character is not one this crate
/// interprets.
fn shorten(part: &str, limit: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(limit);
    for ch in part.chars() {
        if out.len() == limit {
            break;
        }
        // A dot or a space inside the name is dropped rather than substituted: the field has
        // no dot, and a trailing space is padding, so either would make the name ambiguous
        // where an underscore only makes it different.
        if ch == '.' || ch == ' ' {
            continue;
        }
        let byte = if !ch.is_ascii() {
            SUBSTITUTE
        } else {
            let byte = (ch as u8).to_ascii_uppercase();
            if SHORT_NAME_ALSO_FORBIDDEN.contains(&byte) {
                SUBSTITUTE
            } else {
                byte
            }
        };
        out.push(byte);
    }
    out
}

/// The eleven-byte name field a base and an extension make: each space-padded into its own
/// half, with no dot between them.
fn assemble(base: &[u8], ext: &[u8]) -> [u8; SHORT_NAME_LEN] {
    let mut name = [b' '; SHORT_NAME_LEN];
    name[..base.len()].copy_from_slice(base);
    name[BASE_LEN..BASE_LEN + ext.len()].copy_from_slice(ext);
    // A leading 0xE5 marks an entry deleted, so a name that genuinely begins with it is
    // stored as 0x05 and read back the other way. The derivation above cannot produce one —
    // every byte it emits is ASCII — but the escape is applied where the byte is written
    // rather than assumed away.
    if name[0] == NAME_DELETED {
        name[0] = NAME_LEADING_E5;
    }
    name
}

/// The name an eleven-byte field renders back to: the base, then a dot and the extension
/// where there is one.
///
/// Every byte the derivation emits is ASCII, so this is exact rather than lossy.
pub(crate) fn render(short: &[u8; SHORT_NAME_LEN]) -> String {
    let base = unpadded(&short[..BASE_LEN]);
    let ext = unpadded(&short[BASE_LEN..]);
    let mut out = String::with_capacity(SHORT_NAME_LEN + 1);
    out.push_str(&crate::escape::printable(base));
    if !ext.is_empty() {
        out.push('.');
        out.push_str(&crate::escape::printable(ext));
    }
    out
}

/// The name folded to a single case, which is how a driver compares two of them.
///
/// FAT long names are matched case-insensitively, so two entries in one directory whose
/// names differ only in case are one name to every driver that reads the volume — a
/// directory holding both is ambiguous however well-formed each entry is. The model refuses
/// such a pair, and this is the comparison it refuses on.
///
/// The folding is Unicode's rather than ASCII's, which errs toward refusing: whether two
/// non-ASCII names collide depends on the code page a driver was mounted with, and refusing
/// a pair that might have been distinct is the safe direction when the alternative is a
/// directory with two entries a lookup cannot choose between.
pub(crate) fn folded(name: &[u8]) -> Option<String> {
    core::str::from_utf8(name).ok().map(str::to_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The short name `name` takes in an empty directory, as text.
    fn short_of(name: &str) -> String {
        String::from_utf8(
            DirNames::new()
                .place(name.as_bytes())
                .expect("a name the format holds")
                .short
                .to_vec(),
        )
        .expect("the derivation emits ASCII")
    }

    /// Whether `name` needs long-name entries in an empty directory.
    fn needs_lfn(name: &str) -> bool {
        DirNames::new()
            .place(name.as_bytes())
            .expect("a name the format holds")
            .long
            .is_some()
    }

    #[test]
    fn a_name_that_is_already_a_short_name_is_stored_as_one() {
        // The property that keeps an ESP's own paths to one entry each, and the only case in
        // which no long name is written at all.
        for name in ["BOOTX64.EFI", "MAKEFILE", "A", "README.TXT", "X.Y"] {
            assert!(
                !needs_lfn(name),
                "{name} was given a long name it does not need"
            );
            assert_eq!(render(&assemble_of(name)), name);
        }
    }

    /// The eleven-byte field `name` is stored in.
    fn assemble_of(name: &str) -> [u8; SHORT_NAME_LEN] {
        DirNames::new().place(name.as_bytes()).expect("place").short
    }

    #[test]
    fn the_derivation_folds_strips_substitutes_and_truncates() {
        // Each rule of the derivation, one at a time, pinned rather than inherited.
        assert_eq!(short_of("readme.txt"), "README  TXT");
        assert_eq!(short_of("Makefile"), "MAKEFILE   ");
        // Longer than the field: the base truncates and so does the extension.
        assert_eq!(short_of("configuration.yaml"), "CONFIGURYAM");
        // Dots inside the name are dropped and the last one is the separator.
        assert_eq!(short_of("archive.tar.gz"), "ARCHIVETGZ ");
        // Spaces are dropped rather than substituted: a trailing one is padding, so an
        // embedded one would make the field ambiguous.
        assert_eq!(short_of("my file.txt"), "MYFILE  TXT");
        // A character the short field cannot hold but a long name can.
        assert_eq!(short_of("a+b,c;d.txt"), "A_B_C_D TXT");
        // A leading dot does not begin an extension.
        assert_eq!(short_of(".config"), "CONFIG     ");
        assert_eq!(short_of(".gitignore"), "GITIGNOR   ");
        // Not ASCII: one underscore per character, not per byte.
        assert_eq!(short_of("é.txt"), "_       TXT");
        assert_eq!(short_of("日本語.txt"), "___     TXT");
        // The leading strip runs before the separator is looked for, so a name whose only
        // dots are leading ones has no extension at all rather than an empty base.
        assert_eq!(short_of(". .txt"), "TXT        ");
        // Every one of these needed a long name, which is the other half of the claim.
        for name in [
            "readme.txt",
            "Makefile",
            "configuration.yaml",
            "archive.tar.gz",
            "my file.txt",
            ".config",
            "é.txt",
        ] {
            assert!(needs_lfn(name), "{name} lost its name to the short form");
        }
    }

    #[test]
    fn a_collision_takes_the_next_numeric_tail_in_the_order_it_is_offered() {
        // Deterministic given the order, and the model sorts by path before it places
        // anything — which is what makes two formats of one tree byte-identical.
        // All three shorten to `ALONGFIL` before any tail, which is what makes them collide:
        // the spaces are dropped and the first eight characters of what is left agree.
        let mut dir = DirNames::new();
        let names = [
            "A Long File Name.txt",
            "A Long File Name Also.txt",
            "A Long File Number Three.txt",
        ];
        let shorts: Vec<String> = names
            .iter()
            .map(|n| {
                String::from_utf8(dir.place(n.as_bytes()).expect("place").short.to_vec())
                    .expect("ASCII")
            })
            .collect();
        assert_eq!(shorts, ["ALONGFILTXT", "ALONGF~1TXT", "ALONGF~2TXT"]);

        // Offered in a different order they take the tails in *that* order, so the numbering
        // is a function of the sequence and of nothing hidden — and the model's sort by path
        // is what fixes the sequence.
        let mut reversed = DirNames::new();
        assert_eq!(
            &reversed.place(names[2].as_bytes()).expect("place").short,
            b"ALONGFILTXT"
        );
        assert_eq!(
            &reversed.place(names[0].as_bytes()).expect("place").short,
            b"ALONGF~1TXT"
        );
    }

    #[test]
    fn a_literal_short_name_takes_the_slot_a_tail_would_have_used() {
        // Otherwise a generated `ALONGF~1TXT` would shadow a file genuinely called that, and
        // a lookup of the literal name would find two entries.
        let mut dir = DirNames::new();
        assert_eq!(
            &dir.place(b"ALONGF~1.TXT").expect("place").short,
            b"ALONGF~1TXT"
        );
        let placed = dir.place(b"A Long File Name.txt").expect("place");
        assert_eq!(&placed.short, b"ALONGFILTXT");
        // This one does collide, so it reaches for a tail — and `~1` is the literal file's,
        // so it must skip to `~2` rather than shadow it.
        let next = dir.place(b"A Long File Name Also.txt").expect("place");
        assert_eq!(
            &next.short, b"ALONGF~2TXT",
            "the taken tail was not skipped"
        );
    }

    #[test]
    fn the_tail_shortens_the_base_rather_than_overflowing_the_field() {
        let mut dir = DirNames::new();
        dir.place(b"document.txt").expect("place");
        // `~9` costs two characters of an eight-character base, and the field never grows.
        for expected in [b"DOCUME~1TXT", b"DOCUME~2TXT"] {
            let short = dir.place(b"document.txt").expect("place").short;
            assert_eq!(&short, expected);
            assert_eq!(short.len(), SHORT_NAME_LEN);
        }
        // A base shorter than the room the tail leaves keeps all of itself.
        let mut short_base = DirNames::new();
        short_base.place(b"ab").expect("place");
        assert_eq!(
            &short_base.place(b"ab").expect("place").short,
            b"AB~1       "
        );
    }

    #[test]
    fn a_name_the_format_cannot_represent_is_refused_rather_than_substituted() {
        // A renamed file is not the file that was asked for, so none of these is a fidelity
        // loss to be recorded — each is a refusal.
        let mut dir = DirNames::new();
        for (name, want) in [
            (&b"a/b"[..], NameError::ForbiddenCharacter { ch: '/' }),
            (b"a:b", NameError::ForbiddenCharacter { ch: ':' }),
            (b"a*b", NameError::ForbiddenCharacter { ch: '*' }),
            (b"a?b", NameError::ForbiddenCharacter { ch: '?' }),
            (b"a\\b", NameError::ForbiddenCharacter { ch: '\\' }),
            (b"a|b", NameError::ForbiddenCharacter { ch: '|' }),
            (b"a\"b", NameError::ForbiddenCharacter { ch: '"' }),
            (b"a<b", NameError::ForbiddenCharacter { ch: '<' }),
            (b"a>b", NameError::ForbiddenCharacter { ch: '>' }),
            (b"a\tb", NameError::ForbiddenCharacter { ch: '\t' }),
            (b"", NameError::Empty),
            (b"trailing.", NameError::TrailingDotOrSpace),
            (b"trailing ", NameError::TrailingDotOrSpace),
        ] {
            assert_eq!(
                dir.place(name),
                Err(want),
                "{} was accepted",
                String::from_utf8_lossy(name)
            );
        }
        // A byte string that is not text has no UTF-16 form, which a POSIX path may well be.
        assert_eq!(dir.place(&[0xFF, 0xFE]), Err(NameError::NotUtf8));
        // And a name past what the entries hold.
        let long = "x".repeat(MAX_NAME_UNITS + 1);
        assert_eq!(
            dir.place(long.as_bytes()),
            Err(NameError::TooLong {
                units: MAX_NAME_UNITS + 1,
                limit: MAX_NAME_UNITS
            })
        );
        // Exactly at the limit is held, which is the boundary that matters.
        assert!(dir.place("x".repeat(MAX_NAME_UNITS).as_bytes()).is_ok());

        // The characters a long name holds and a short name does not are substituted rather
        // than refused, because the long name still carries the truth.
        assert!(dir.place(b"a+b=c[d].txt").is_ok());
    }

    #[test]
    fn a_long_name_is_chunked_backwards_and_every_chunk_carries_the_checksum() {
        // The one ordering in the format that reads wrong if transcribed from prose: the
        // entries precede the name they belong to and run in reverse, so the flagged one is
        // written first and holds the name's *final* characters.
        let placed = DirNames::new()
            .place("A Long File Name.txt".as_bytes())
            .expect("place");
        let entries = placed.lfn_entries();
        assert_eq!(entries.len(), 2, "twenty characters spans two entries");
        assert_eq!(entries[0].order, 2 | LFN_LAST_ENTRY);
        assert_eq!(entries[1].order, 1);
        let checksum = lfn_checksum(&placed.short);
        assert!(entries.iter().all(|e| e.checksum == checksum));

        // Reassembled forwards, the entries are the name: the first written holds the tail.
        let mut units: Vec<u16> = Vec::new();
        for entry in entries.iter().rev() {
            units.extend(
                entry
                    .name
                    .iter()
                    .take_while(|&&u| u != 0 && u != LFN_PADDING),
            );
        }
        assert_eq!(
            String::from_utf16(&units).expect("utf16"),
            "A Long File Name.txt"
        );
    }

    #[test]
    fn a_name_that_fills_its_last_entry_gets_no_terminator() {
        // Thirteen characters exactly: the format says a name that fills the entry is not
        // terminated, and a reader that expected one would truncate the name by a character.
        let placed = DirNames::new().place(b"abcdefghijklm").expect("place");
        let entries = placed.lfn_entries();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].name.iter().all(|&u| u != 0 && u != LFN_PADDING));

        // One shorter leaves a single zero and then padding, which is the other half.
        let placed = DirNames::new().place(b"abcdefghijkl").expect("place");
        let entry = placed.lfn_entries()[0];
        assert_eq!(entry.name[12], 0);
        let placed = DirNames::new().place(b"abcdefghijk").expect("place");
        let entry = placed.lfn_entries()[0];
        assert_eq!(entry.name[11], 0);
        assert_eq!(entry.name[12], LFN_PADDING);
    }

    #[test]
    fn a_name_spans_the_entries_its_length_needs_and_the_slots_say_so() {
        for (units, entries) in [
            (1usize, 1usize),
            (13, 1),
            (14, 2),
            (26, 2),
            (27, 3),
            (255, 20),
        ] {
            let placed = DirNames::new()
                .place("x".repeat(units).as_bytes())
                .expect("place");
            assert_eq!(placed.lfn_entries().len(), entries, "{units} characters");
            assert_eq!(placed.slots(), entries + 1);
        }
        // A name stored as its own short name occupies one slot and no long-name entries.
        let placed = DirNames::new().place(b"BOOTX64.EFI").expect("place");
        assert!(placed.lfn_entries().is_empty());
        assert_eq!(placed.slots(), 1);
    }

    #[test]
    fn a_character_outside_the_basic_plane_survives_as_its_surrogate_pair() {
        // Two code units for one character, which is what the entries store — so a name is
        // capped in units rather than in characters.
        let placed = DirNames::new().place("🦀.rs".as_bytes()).expect("place");
        let units = placed.long.expect("a long name");
        assert_eq!(units.len(), 5, "one surrogate pair, a dot, and two letters");
        assert_eq!(String::from_utf16(&units).expect("utf16"), "🦀.rs");
        assert_eq!(&placed.short, b"_       RS ");
    }

    #[test]
    fn two_names_a_driver_cannot_tell_apart_fold_to_one() {
        // The comparison the model refuses a directory on. A FAT lookup is case-insensitive,
        // so these are one name however distinct the source considered them.
        assert_eq!(folded(b"readme.txt"), folded(b"README.TXT"));
        assert_eq!(folded(b"MixedCase"), folded(b"mIXEDcASE"));
        assert_ne!(folded(b"readme.txt"), folded(b"readme.md"));
        // The folding is Unicode's, which errs toward refusing a pair whose distinctness
        // would depend on the code page a driver was mounted with.
        assert_eq!(folded("Ä.txt".as_bytes()), folded("ä.txt".as_bytes()));
        // A name with no text form has no folded form, and is refused by `place` anyway.
        assert_eq!(folded(&[0xFF]), None);
    }
}
