//! The equivalence an APFS volume compares names under, and the hash a directory entry is
//! stored by.
//!
//! A volume stores a name as the bytes it was given, and compares names as their normalized
//! form: on a volume whose names fold case, two names are one name when their canonical
//! decompositions, case-folded and decomposed again, are equal, which is the Unicode Standard's
//! canonical caseless match (definition D145); on one that keeps case, when their canonical
//! decompositions are. A directory entry is keyed by a 22-bit hash of that
//! form, so a name looked up under a hash computed any other way is a name the volume does not
//! find. The rules here were observed on volumes macOS 15, 26 and 27 wrote, one name per code
//! point from U+0000 to U+33450 on each kind of volume, canonical ordering excepted, and they
//! disagree with the reference in two places it says so:
//!
//! - **The form.** Canonical decomposition with canonical ordering; then, on a case-insensitive
//!   volume, full case folding (statuses C and F of Unicode's `CaseFolding.txt`, non-Turkic),
//!   and canonical decomposition again. No single code point decomposes to marks out of
//!   canonical order, so a name of one code point never exercises the ordering, and it is the
//!   Unicode Standard's Canonical Ordering Algorithm (section 3.11), held to the combining
//!   classes the tables carry.
//! - **The hash.** The CRC-32C of the form's code points as little-endian 32-bit words,
//!   without a terminator, complemented, in the low 22 bits. The reference hashes the
//!   terminator, and its mask keeps 21 of the 22 bits.
//!
//! macOS 15 follows Unicode 16.0 and macOS 26 and 27 follow 17.0, exactly. The two differ only
//! in the code points 16.0 leaves unassigned, which macOS 15 refuses in a name, and Unicode's
//! stability policies fix an assigned code point's decomposition and folding; so the 17.0
//! tables compare every name either version wrote.
//!
//! # The names macOS refuses
//!
//! macOS refuses to create a name, with `EILSEQ`, that is not UTF-8, or that holds a code point
//! the Unicode version it follows leaves unassigned, or a noncharacter: U+FDD0 to U+FDEF and the
//! last two code points of every plane. It refuses one longer than 255 UTF-16 code units with
//! `ENAMETOOLONG`, which is 255 characters of the Basic Multilingual Plane however many bytes
//! they take. Each was observed on macOS 15, 26 and 27, at both ends of every range. [`check`]
//! holds a name to those rules for a Unicode version a caller names.
//!
//! This module is pure: it computes values and does no I/O.

use super::unicode_tables::{ASSIGNED, CASE_FOLDING, COMBINING_CLASS, DECOMPOSITION};

/// The bits a directory entry's hash takes.
pub(crate) const HASH_MASK: u32 = 0x3F_FFFF;

/// The first Hangul syllable, and the arithmetic Unicode decomposes one by: the Unicode
/// Standard's Hangul syllable decomposition (section 3.12, Conjoining Jamo Behavior).
const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = 19 * N_COUNT;

/// The form a name is compared and hashed as, or [`None`] for a name that is not UTF-8, which
/// a volume holds only where something other than macOS wrote it.
pub(crate) fn key(name: &[u8], fold: bool) -> Option<Vec<u32>> {
    let text = std::str::from_utf8(name).ok()?;
    let decomposed = decompose(text.chars().map(u32::from));
    if !fold {
        return Some(decomposed);
    }
    let folded = decomposed.into_iter().flat_map(|cp| {
        CASE_FOLDING
            .binary_search_by_key(&cp, |(c, _)| *c)
            .map_or_else(|_| vec![cp], |i| CASE_FOLDING[i].1.to_vec())
    });
    Some(decompose(folded))
}

/// The hash a directory entry for a name of this form is stored by.
pub(crate) fn hash(form: &[u32]) -> u32 {
    let bytes: Vec<u8> = form.iter().flat_map(|cp| cp.to_le_bytes()).collect();
    crate::crc32c::crc32c(!0, &bytes) & HASH_MASK
}

/// The longest name macOS creates, in UTF-16 code units.
pub(crate) const MAX_NAME_UNITS: usize = 255;

/// A Unicode version, by its major and minor numbers.
pub(crate) type UnicodeVersion = (u8, u8);

/// Why macOS refuses a name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum NameFault {
    /// The name is not UTF-8.
    NotUtf8,
    /// The name is longer than [`MAX_NAME_UNITS`] UTF-16 code units: it has this many.
    TooLong(usize),
    /// The name holds a code point the version leaves unassigned.
    Unassigned(u32),
    /// The name holds a noncharacter.
    Noncharacter(u32),
}

/// Whether macOS creates `name` under Unicode `version`.
pub(crate) fn check(name: &[u8], version: UnicodeVersion) -> Result<(), NameFault> {
    let text = std::str::from_utf8(name).map_err(|_| NameFault::NotUtf8)?;
    let units: usize = text.chars().map(char::len_utf16).sum();
    if units > MAX_NAME_UNITS {
        return Err(NameFault::TooLong(units));
    }
    for cp in text.chars().map(u32::from) {
        if is_noncharacter(cp) {
            return Err(NameFault::Noncharacter(cp));
        }
        if !assigned_in(cp, version) {
            return Err(NameFault::Unassigned(cp));
        }
    }
    Ok(())
}

/// Whether `cp` is one of Unicode's noncharacters.
const fn is_noncharacter(cp: u32) -> bool {
    (cp >= 0xFDD0 && cp <= 0xFDEF) || cp & 0xFFFE == 0xFFFE
}

/// Whether Unicode `version` assigns `cp`.
fn assigned_in(cp: u32, version: UnicodeVersion) -> bool {
    let at = ASSIGNED.partition_point(|(_, last, _, _)| *last < cp);
    ASSIGNED
        .get(at)
        .is_some_and(|&(first, _, major, minor)| first <= cp && (major, minor) <= version)
}

/// The canonical decomposition of `code_points`, canonically ordered.
fn decompose(code_points: impl Iterator<Item = u32>) -> Vec<u32> {
    let mut out = Vec::new();
    for cp in code_points {
        if (S_BASE..S_BASE + S_COUNT).contains(&cp) {
            let s = cp - S_BASE;
            out.push(L_BASE + s / N_COUNT);
            out.push(V_BASE + (s % N_COUNT) / T_COUNT);
            if !s.is_multiple_of(T_COUNT) {
                out.push(T_BASE + s % T_COUNT);
            }
        } else if let Ok(i) = DECOMPOSITION.binary_search_by_key(&cp, |(c, _)| *c) {
            out.extend_from_slice(DECOMPOSITION[i].1);
        } else {
            out.push(cp);
        }
    }
    // The Unicode Standard's Canonical Ordering Algorithm (section 3.11): every run of code
    // points with a nonzero combining class, sorted by class, stably.
    let mut i = 0;
    while i < out.len() {
        if class(out[i]) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < out.len() && class(out[i]) != 0 {
            i += 1;
        }
        out[start..i].sort_by_key(|cp| class(*cp));
    }
    out
}

/// A code point's canonical combining class.
fn class(cp: u32) -> u8 {
    COMBINING_CLASS
        .binary_search_by_key(&cp, |(c, _)| *c)
        .map_or(0, |i| COMBINING_CLASS[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(a: &str, b: &str, fold: bool) -> bool {
        key(a.as_bytes(), fold) == key(b.as_bytes(), fold)
    }

    #[test]
    fn composed_and_decomposed_spellings_are_one_name_on_either_kind_of_volume() {
        for fold in [false, true] {
            assert!(same("caf\u{E9}", "cafe\u{301}", fold));
            // Singleton decompositions: KELVIN SIGN, ANGSTROM SIGN, OHM SIGN.
            assert!(same("\u{212A}", "K", fold));
            assert!(same("\u{212B}", "\u{C5}", fold));
            assert!(same("\u{2126}", "\u{3A9}", fold));
            // A Hangul syllable and its jamo.
            assert!(same("\u{D55C}", "\u{1112}\u{1161}\u{11AB}", fold));
            // Marks of different classes in either order are one name, in the order Unicode's
            // combining classes give: U+0316 is class 220 and U+0301 class 230, so it comes
            // first whichever order the name spells them in.
            assert!(same("a\u{301}\u{316}", "a\u{316}\u{301}", fold));
            assert_eq!(
                key("a\u{301}\u{316}".as_bytes(), fold),
                Some(vec![u32::from('a'), 0x316, 0x301])
            );
        }
        assert!(!same("Readme", "README", false));
    }

    #[test]
    fn a_volume_that_folds_case_folds_it_fully_and_not_as_turkish() {
        assert!(same("Readme", "README", true));
        assert!(same("STRASSE", "stra\u{DF}e", true));
        assert!(same("\u{FB01}", "fi", true));
        assert!(same("\u{130}", "i\u{307}", true));
        assert!(!same("I", "\u{131}", true));
        assert!(
            same("\u{3C2}", "\u{3C3}", true),
            "final sigma folds to sigma"
        );
    }

    #[test]
    fn the_hash_is_the_complemented_crc_of_the_form_in_22_bits() {
        // An ASCII name's form is its code points, so its hash is the CRC of those as 32-bit
        // little-endian words, with no terminator.
        let form = key(b"hello", false).expect("UTF-8");
        let words: Vec<u8> = b"hello"
            .iter()
            .flat_map(|b| u32::from(*b).to_le_bytes())
            .collect();
        assert_eq!(hash(&form), crate::crc32c::crc32c(!0, &words) & HASH_MASK);
        assert!(hash(&form) <= HASH_MASK);
    }

    #[test]
    fn a_name_hashes_to_what_a_volume_macos_wrote_stores_it_under() {
        // Observed: the hash each name is stored under on a volume macOS 26 wrote that folds
        // case, and on one that keeps it. A forged volume hashes its names with this module,
        // so these values are what hold the module to macOS.
        let observed: [(&str, u32, u32); 8] = [
            ("names", 0x09_3833, 0x09_3833),
            ("MixedCase", 0x05_183B, 0x37_08E3),
            ("\u{E9}cole", 0x2D_A0E8, 0x2D_A0E8),
            ("\u{130}", 0x3E_E29A, 0x3E_8703),
            ("\u{AC00}", 0x2A_953B, 0x2A_953B),
            ("stra\u{DF}e", 0x14_6C83, 0x3F_993D),
            ("\u{3A3}\u{3B1}", 0x1D_E450, 0x1D_4AFB),
            ("\u{FB01}", 0x30_19CF, 0x06_9132),
        ];
        for (name, folding, keeping) in observed {
            for (fold, stored) in [(true, folding), (false, keeping)] {
                let form = key(name.as_bytes(), fold).expect("UTF-8");
                assert_eq!(hash(&form), stored, "{name:?}, folding case: {fold}");
            }
        }
    }

    #[test]
    fn a_name_that_is_not_utf8_has_no_form() {
        assert_eq!(key(b"\xff\xfe", true), None);
    }

    #[test]
    fn a_name_is_held_to_the_code_points_its_version_assigns_and_255_utf16_units() {
        const V16: UnicodeVersion = (16, 0);
        const V17: UnicodeVersion = (17, 0);
        // Observed refused on every release: U+0378 unassigned, U+E0080 unassigned, and each
        // end of the noncharacter ranges.
        for cp in [0x378, 0xE0080] {
            let name = char::from_u32(cp).unwrap().to_string();
            assert_eq!(check(name.as_bytes(), V17), Err(NameFault::Unassigned(cp)));
        }
        for cp in [0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x10FFFF] {
            let name = char::from_u32(cp).unwrap().to_string();
            assert_eq!(
                check(name.as_bytes(), V17),
                Err(NameFault::Noncharacter(cp))
            );
        }
        // Private use, a tag, an emoji, a zero-width joiner and a colon are accepted.
        for name in ["\u{E000}", "\u{E0041}", "\u{1F600}", "a\u{200D}b", "a:b"] {
            assert_eq!(check(name.as_bytes(), V17), Ok(()), "{name:?}");
        }
        // Two code points 16.0 assigns, Garay's U+10D50 and U+1E5D0, and one 17.0 assigns,
        // U+10EC5, which macOS 15 refuses and macOS 26 accepts.
        assert_eq!(check("\u{10D50}".as_bytes(), V16), Ok(()));
        assert_eq!(check("\u{1E5D0}".as_bytes(), V16), Ok(()));
        assert_eq!(
            check("\u{10EC5}".as_bytes(), V16),
            Err(NameFault::Unassigned(0x10EC5))
        );
        assert_eq!(check("\u{10EC5}".as_bytes(), V17), Ok(()));
        // 255 euro signs are 765 bytes and 255 units; 256 are refused.
        assert_eq!(check("\u{20AC}".repeat(255).as_bytes(), V17), Ok(()));
        assert_eq!(
            check("\u{20AC}".repeat(256).as_bytes(), V17),
            Err(NameFault::TooLong(256))
        );
        // A code point past the plane counts two units.
        assert_eq!(
            check("\u{1F600}".repeat(128).as_bytes(), V17),
            Err(NameFault::TooLong(256))
        );
        assert_eq!(check(b"x\xed\xa0\x80", V17), Err(NameFault::NotUtf8));
    }
}
