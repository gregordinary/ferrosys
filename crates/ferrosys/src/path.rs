//! What a path is made of, and which of its components a directory can hold.
//!
//! Two questions are asked of a path everywhere in this crate, by every family and on both
//! sides of it. **Which components does it have** — a source keying entries by path, a model
//! placing them, a reader resolving one, a walk building one. And **may this component be a
//! name** — a directory entry read out of an image, a component of a host path about to be
//! created.
//!
//! Both are answered here rather than by each layer, and for the same reason: a second answer
//! that drifted would not fail. A splitter that disagreed about an empty component would key
//! two entries apart that the model considers one path, and leave both in the image. A name
//! rule that gained a clause in one place and not another would refuse a name where it is
//! read and accept it where it is written.
//!
//! This module is pure: it inspects byte strings and answers questions about them. It does
//! no I/O and rejects nothing on its own — each caller applies the answer as its own error.
//!
//! # The two name rules, and why there are two
//!
//! `is_hostile_entry` is what no directory entry may carry at all. `is_hostile_component` is
//! that rule and two clauses more, for the case where the name is about to become a component
//! of a path. (Named without links: each is compiled only where something asks it, and this
//! module is compiled always.)
//!
//! The difference is `.` and `..`, and it is a real one rather than a strictness dial. An ext
//! directory genuinely holds both as entries — a resolution walks `..` through the one the
//! directory carries, and a listing that omitted them would not be the directory — so ext
//! reads them with the entry rule and filters them by name where a path is built. A FAT
//! directory's dot entries are identified by their short-name field before a name is
//! resolved at all, so by the time a resolved name exists there is no legitimate `.` left,
//! and the volume's own reader asks the stricter question. A host sink asks it too, of every
//! component it is about to create.
//!
//! Stating them as one rule and one rule-plus-two-clauses is what keeps the shared part
//! shared: a clause added to what no name may carry reaches all three callers, and the
//! asymmetry stays visible as the two functions rather than as a flag.

/// The meaningful components of `path`, in order: what [`canonical_key`] joins, and what a
/// model validates.
///
/// Separators and `.` elements carry no meaning, so they are what this drops. It is the
/// normalization half alone — a caller that must also *reject* a component runs its own rules
/// over what comes back, so there is one answer to "which components are these" and one place
/// each layer states what it will not accept.
///
/// `..` is left in. It resolves through the directory's own entry for it, which is the only
/// thing that knows where the parent is, and a model that cannot represent one refuses it by
/// name rather than by having never seen it.
pub(crate) fn canonical_parts(path: &[u8]) -> Vec<&[u8]> {
    path.split(|&b| b == b'/')
        .filter(|part| !part.is_empty() && *part != b".")
        .collect()
}

/// The canonical key for `path`: its meaningful components joined by single separators, with
/// no leading or trailing one.
///
/// `/etc/hostname`, `//etc//hostname`, and `etc/./hostname` are one path and key alike, and
/// the root keys as the empty slice.
///
/// This is the rule a family's own path handling is built on, so that a caller keying entries
/// by path outside a model — composing two sources into one, where a later entry replaces an
/// earlier one at the same path — decides which paths *are* the same the way the model that
/// consumes them will. Two normalizations that disagreed would not fail; they would quietly
/// leave both entries in the list, and the model would reject the duplicate or, worse, accept
/// two names it thought were different. So there is one: a model splits a path through
/// [`canonical_parts`] and validates what comes back.
///
/// It rejects nothing. A `..` element, an over-long component, or one carrying a NUL keys
/// as itself and is refused when a model reads the entry, so there is one rejection site
/// and its error names the path the caller wrote.
pub(crate) fn canonical_key(path: &[u8]) -> Vec<u8> {
    canonical_parts(path).join(&b'/')
}

/// Whether `name` is one no directory entry could carry: it is empty, or holds a path
/// separator or a NUL.
///
/// The kernel's `ext4_check_dir_entry` forbids the last two, so either marks a crafted or
/// corrupt image, and no FAT driver writes them either. A name carrying `/` traverses out of
/// its directory (`../../etc/...`); one carrying a NUL ends early at the C-string boundary a
/// consumer would build a host path against.
///
/// An empty name is not a name, and every family reaches one. An ext directory entry may
/// record a zero-length name beside a non-zero inode; a FAT eleven-byte field of spaces
/// renders to nothing, and a long-name run beginning with a zero code unit decodes to
/// nothing. The path built from any of them is the *directory's own path* with a trailing
/// separator, so two such siblings produce two entries at identical paths — which contradicts
/// what a walk promises — and an archive writer renders one as a member ending in `/`, which
/// every tar reader takes for a directory, so it collides with the real entry of that name
/// and changes its type.
///
/// Compiled wherever a family is, and wherever `is_hostile_component` is: the stricter rule
/// is this one and two clauses, so a build carrying a host sink and no family asks the
/// stricter question and reaches here through it.
#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    all(feature = "dir", any(target_os = "linux", target_os = "android"))
))]
pub(crate) fn is_hostile_entry(name: &[u8]) -> bool {
    name.is_empty() || name.contains(&b'/') || name.contains(&0)
}

/// Whether `name` is one that could not be a component of a path: everything
/// [`is_hostile_entry`] refuses, and `.` or `..` besides.
///
/// Those two name a directory rather than something inside it — `..` would ascend out of the
/// tree a path is being built in, and `.` would name the directory itself — so a component
/// that is either is not a name the path can gain. The test is on the name as a caller
/// receives it, after a FAT long name is decoded and a short one is read under the volume's
/// code page, because that is the byte string a path is built from.
#[cfg(any(
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    all(feature = "dir", any(target_os = "linux", target_os = "android"))
))]
pub(crate) fn is_hostile_component(name: &[u8]) -> bool {
    is_hostile_entry(name) || is_dot_entry(name)
}

/// Whether `name` is one of the two entries a directory holds for itself and its parent.
///
/// Not hostile on its own — the formats that store the pair store it legitimately — but
/// never a name below the directory either, so every walk that builds paths and every
/// listing that yields names skips both. One home for the pair, because the test is the
/// same wherever a family stores them — and it is a clause of `is_hostile_component`
/// besides, so it is compiled wherever either caller is.
#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    all(feature = "dir", any(target_os = "linux", target_os = "android"))
))]
pub(crate) fn is_dot_entry(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

/// Characters reserved in a name on the formats that inherited the DOS filename rules. Each
/// is a path separator, a wildcard, or a redirection a shell or a driver interprets rather
/// than stores.
#[cfg(any(feature = "fat", feature = "exfat"))]
const RESERVED_NAME_CHARS: &[u8] = b"\"*/:<>?\\|";

/// Whether `ch` is one no name a FAT or exFAT volume carries may contain.
///
/// One rule, because it is one rule: FAT's long names and exFAT's names reserve the same nine
/// characters and the same control codes, both formats having taken the restriction from the
/// same place rather than each inventing it. Two copies would agree today and drift the moment
/// either was corrected, and the drift would be silent — a name one family stores and the
/// other refuses, discovered by whoever copies a tree between two images.
///
/// It says nothing about *short* names, which reserve more; that is FAT's alone, because only
/// FAT has them.
#[cfg(any(feature = "fat", feature = "exfat"))]
pub(crate) fn is_reserved_name_char(ch: char) -> bool {
    ch.is_ascii() && (RESERVED_NAME_CHARS.contains(&(ch as u8)) || (ch as u8) < 0x20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_and_dot_elements_carry_no_meaning() {
        // The three spellings a caller writes, all one path.
        for path in [&b"/etc/hostname"[..], b"//etc//hostname", b"etc/./hostname"] {
            assert_eq!(canonical_parts(path), [&b"etc"[..], b"hostname"]);
            assert_eq!(canonical_key(path), b"etc/hostname");
        }
        // The root has no components, and keys as the empty slice rather than as `/`.
        assert!(canonical_parts(b"/").is_empty());
        assert_eq!(canonical_key(b"/"), b"");
        assert_eq!(canonical_key(b""), b"");
    }

    #[test]
    fn a_parent_element_is_kept_for_whoever_must_answer_for_it() {
        // Dropping `..` here would silently turn `/a/../b` into `/b`, which is a different
        // path to every caller that resolves one and to every model that refuses one.
        assert_eq!(canonical_parts(b"/a/../b"), [&b"a"[..], b"..", b"b"]);
    }

    // The same predicate the function carries, so a build that compiles the rule is a build
    // that tests it. An `exfat`-only build compiles both — the exFAT reader asks the stricter
    // of the two, and the stricter one is this rule and two clauses.
    #[cfg(any(
        feature = "ext",
        feature = "fat",
        feature = "exfat",
        feature = "btrfs",
        all(feature = "dir", any(target_os = "linux", target_os = "android"))
    ))]
    #[test]
    fn no_entry_may_carry_a_separator_a_nul_or_nothing_at_all() {
        assert!(is_hostile_entry(b""));
        assert!(is_hostile_entry(b"a/b"));
        assert!(is_hostile_entry(b"a\0b"));
        assert!(!is_hostile_entry(b"hostname"));
        // `.` and `..` are entries an ext directory genuinely holds, so the shared rule
        // does not refuse them — the component rule does.
        assert!(!is_hostile_entry(b"."));
        assert!(!is_hostile_entry(b".."));
    }

    #[cfg(any(
        feature = "fat",
        feature = "exfat",
        feature = "btrfs",
        all(feature = "dir", any(target_os = "linux", target_os = "android"))
    ))]
    #[test]
    fn a_path_component_may_not_name_the_directory_it_sits_in() {
        assert!(is_hostile_component(b"."));
        assert!(is_hostile_component(b".."));
        assert!(!is_hostile_component(b"hostname"));
        // The stricter rule is the base rule and two clauses, never less: everything no
        // entry may carry is something no component may carry either.
        for name in [&b""[..], b"a/b", b"a\0b"] {
            assert!(
                is_hostile_entry(name) && is_hostile_component(name),
                "the component rule contains the entry rule"
            );
        }
    }

    #[cfg(any(feature = "fat", feature = "exfat"))]
    #[test]
    fn the_reserved_characters_are_the_nine_and_the_control_codes() {
        for ch in ['"', '*', '/', ':', '<', '>', '?', '\\', '|'] {
            assert!(is_reserved_name_char(ch), "{ch:?}");
        }
        for ch in ['\0', '\t', '\n', '\r', '\u{1F}'] {
            assert!(is_reserved_name_char(ch), "{ch:?}");
        }
        // The space is the first character that is not a control code, and it is allowed
        // inside a name — only at the end of one is it a problem, which is a rule about
        // position rather than about the character.
        for ch in [' ', '.', 'a', 'Z', '_', '~', '+', ',', ';', '=', '[', ']'] {
            assert!(!is_reserved_name_char(ch), "{ch:?}");
        }
        // The rule is about the ASCII range: a character outside it is stored as it stands,
        // whatever it looks like.
        for ch in ['é', '中', '\u{2044}', '\u{1F600}'] {
            assert!(!is_reserved_name_char(ch), "{ch:?}");
        }
    }
}
