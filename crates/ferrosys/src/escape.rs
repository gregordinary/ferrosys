//! Rendering bytes that came off an image, an archive, or a host tree as text a person
//! reads.
//!
//! Every name in every family this crate reads is a byte string, and the only bytes any of
//! them forbid are the ones that would break the directory format itself. Everything else is
//! a legal name: an escape sequence, a carriage return, a bidirectional override. A message
//! or a finding that interpolates such a name raw hands those bytes to whatever renders it,
//! and a terminal acts on them — so `\x1b[2J\x1b[1;1Hno findings\x1b[0m` as a directory name
//! puts a forged clean report on the screen of anyone who inspects the image, from a command
//! that succeeded and said nothing was wrong.
//!
//! So a name is escaped where it is interpolated, not where it is displayed. That is the only
//! place the rule can hold: a message is a `String` by the time anything downstream sees it,
//! and nothing at that point can tell which of its characters came from the image. Doing it
//! here means a caller reading [`Finding::detail`](crate::Finding::detail), a caller printing
//! an error, and a caller writing either into a log all get the same guarantee without
//! knowing they needed one.
//!
//! Two renderings share those rules and differ in where the escaped text goes:
//! [`printable`] writes for a person to read on a terminal, and [`push_json_string`] writes
//! a JSON string literal for a document. Both escape the same two classes of character, so a
//! name that is safe in a message is safe in a report.
//!
//! [`hex`] is the third rendering and the one that escapes nothing: it writes bytes as
//! themselves, for a document that carries the exact name beside the readable one and for a
//! contract that has to state a UUID or a label as the bytes it is.
//!
//! Every escape [`printable`] emits names exactly one character of the input: a backslash is
//! doubled first, so a name holding the four characters `\x1b` does not render as the one
//! holding the escape byte. What that does *not* recover is a byte that is not text at all —
//! both renderings are lossy over invalid UTF-8, which becomes `U+FFFD` and is thereafter
//! indistinguishable from any other invalid byte and from a `U+FFFD` the name itself held. A
//! caller that must recover the exact bytes carries them beside the rendering, as the JSON
//! projection's `<key>_hex` field does.

/// Text for `bytes`, with everything a terminal would act on rendered as an escape.
///
/// Invalid UTF-8 becomes `U+FFFD` — the name stays recognizable, which is the point of
/// naming it — and the two classes a terminal honours are escaped instead: control
/// characters, and the bidirectional formatting characters that reorder the text around them
/// without occupying a column.
///
/// The backslash is doubled, so every `\x` and `\u{}` in the output stands for exactly one
/// character of the input.
///
/// ```
/// // A crafted name that would otherwise clear the screen and forge a line of its own.
/// assert_eq!(
///     ferrosys::printable(b"\x1b[2J\x1b[1;1Hno findings"),
///     "\\x1b[2J\\x1b[1;1Hno findings"
/// );
/// ```
#[must_use]
pub fn printable(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for c in String::from_utf8_lossy(bytes).chars() {
        match c {
            // First, so the escapes below are unambiguous: an escape a reader cannot invert
            // is one they cannot trust.
            '\\' => out.push_str("\\\\"),
            // A control character is at most `U+009F`, so two hex digits name it. This
            // covers DEL and the C1 block, which a terminal speaking 8-bit controls treats
            // as `U+009B` being a CSI.
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if is_direction_control(c) => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Text for a path on *this* host, escaped by [`printable`]'s rules.
///
/// A host tree is untrusted input in exactly the way an image is: the trees a build points a
/// walk at are unpacked tarballs, container layers, and staging areas, and whoever produced
/// one chose the names in it. `Path::display` replaces invalid UTF-8 with `U+FFFD` and does
/// nothing at all about a control character or a direction override, so a message built from
/// it hands those on — the same forged output the image path is escaped to prevent, reached
/// through the other end of the tree.
///
/// A path is bytes on Unix and is escaped as those bytes. Elsewhere it is escaped as the
/// lossy text the platform renders it to, which is the most any escaping can do where the
/// bytes are not addressable.
pub(crate) fn printable_path(path: &std::path::Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        printable(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        printable(path.as_os_str().to_string_lossy().as_bytes())
    }
}

/// Append `s` to `out` as a JSON string literal, quotes included, escaping what the grammar
/// requires and what a terminal acts on.
///
/// The grammar itself asks only for the quote, the backslash, and everything below `U+0020`.
/// The rest is not a requirement of the format but of where a document is read: a terminal
/// speaking eight-bit controls treats `U+009B` as a CSI, and a direction override reorders
/// every character after it, so a name carrying either moves or rearranges what whoever
/// looks at the document sees — through `jq`, through `cat`, through a log viewer. Both
/// classes go out as the `\uXXXX` escape the grammar defines, which a parser reads back as
/// the character the name held: the document still carries the name exactly, and nothing
/// downstream of the parser has to know it was ever escaped.
///
/// ```
/// let mut out = String::new();
/// // `U+202E` would otherwise display the rest of the line reversed.
/// ferrosys::push_json_string(&mut out, "photo\u{202e}gnp.exe");
/// assert_eq!(out, r#""photo\u202egnp.exe""#);
/// ```
pub fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || is_direction_control(c) => push_json_escape(out, c),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `bytes` as lower-case hexadecimal, two digits each and no separator.
///
/// The rendering that loses nothing. Where [`printable`] and [`push_json_string`] make bytes
/// readable — and are lossy over anything that is not text — this states them exactly, at a
/// fixed two characters per byte. It is what a document carrying a name it could not render
/// puts beside the rendering, and what a value that is an identifier rather than text — a
/// UUID, a hash seed — is written as in the first place.
///
/// ```
/// assert_eq!(ferrosys::hex(&[0xf0, 0xe1, 0x00]), "f0e100");
/// assert_eq!(ferrosys::hex(&[]), "");
/// ```
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        // A byte is two nibbles and each names one hex digit, so this is the same walk
        // `push_json_escape` does one level up, without a format machine in the loop.
        for shift in [4, 0] {
            let nibble = u32::from((b >> shift) & 0xf);
            out.push(char::from_digit(nibble, 16).expect("a nibble is a hex digit"));
        }
    }
    out
}

/// Append `c` as JSON's `\uXXXX` escape.
///
/// Every character this is called for is below `U+FFFF` — a control is at most `U+009F` and
/// the highest direction control is `U+2069` — so one escape describes each, with no
/// surrogate pair to form.
fn push_json_escape(out: &mut String, c: char) {
    let point = c as u32;
    out.push_str("\\u");
    for shift in [12, 8, 4, 0] {
        let nibble = (point >> shift) & 0xf;
        out.push(char::from_digit(nibble, 16).expect("a nibble is a hex digit"));
    }
}

/// Whether `c` is a bidirectional formatting character — one that reorders the text around
/// it without occupying a column of its own.
///
/// These are not `char::is_control`: they are category `Cf`, and a terminal honours them.
/// Left raw, `U+202E` alone makes the rest of a line render right to left, which is enough to
/// display a name as its own reverse. The set is closed and small, so it is named here rather
/// than reached for through a Unicode table.
fn is_direction_control(c: char) -> bool {
    matches!(
        c,
        // The marks: LRM, RLM, ALM.
        '\u{200e}' | '\u{200f}' | '\u{061c}'
        // The embedding and override run: LRE, RLE, PDF, LRO, RLO.
        | '\u{202a}'..='\u{202e}'
        // The isolates: LRI, RLI, FSI, PDI.
        | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::{hex, printable, push_json_string};

    #[test]
    fn hex_states_bytes_exactly_and_at_a_fixed_width() {
        assert_eq!(hex(b"\x00\x0f\xf0\xff"), "000ff0ff");
        assert_eq!(hex(&[]), "");
        // Two digits per byte whatever the byte is, so a fixed-width field renders at a
        // fixed width and a leading zero is never dropped.
        assert_eq!(hex(&[1u8; 16]).len(), 32);
        // Lower case, which is what every other tool that prints a UUID or a seed writes.
        assert_eq!(hex(b"\xab\xcd"), "abcd");
    }

    /// `push_json_string`'s output for `s`, quotes included.
    fn json(s: &str) -> String {
        let mut out = String::new();
        push_json_string(&mut out, s);
        out
    }

    #[test]
    fn ordinary_text_passes_through() {
        assert_eq!(printable(b"/etc/passwd"), "/etc/passwd");
        assert_eq!(printable("naïve".as_bytes()), "naïve");
        assert_eq!(printable(b""), "");
    }

    #[test]
    fn everything_a_terminal_acts_on_is_escaped() {
        // The forged-report shape: an escape sequence that clears the screen and writes its
        // own line.
        assert_eq!(
            printable(b"\x1b[2J\x1b[1;1Hclean\x1b[0m"),
            "\\x1b[2J\\x1b[1;1Hclean\\x1b[0m"
        );
        // A carriage return overwrites the line already printed; NUL and DEL are controls
        // too, and so is the C1 block a terminal reads as CSI.
        assert_eq!(printable(b"a\rb\0c\x7fd"), "a\\x0db\\x00c\\x7fd");
        assert_eq!(printable("\u{9b}[31m".as_bytes()), "\\x9b[31m");
        // A right-to-left override displays the rest of the line reversed.
        assert_eq!(printable("gpj.\u{202e}exe".as_bytes()), "gpj.\\u{202e}exe");
    }

    #[test]
    fn every_escape_names_exactly_one_character() {
        // A backslash already in the name is doubled, so nothing in the output is ambiguous
        // between a character the name held and an escape this produced. Without it a
        // crafted name could be written to look like the escaped form of an innocent one.
        assert_eq!(printable(b"a\\x1bb"), "a\\\\x1bb");
        assert_eq!(printable(b"\\"), "\\\\");
        assert_ne!(printable(br"a\x1bb"), printable(b"a\x1bb"));
    }

    #[test]
    fn a_json_string_escapes_what_the_grammar_requires() {
        assert_eq!(json("a\"b\\c\nd\te\u{1}f"), r#""a\"b\\c\nd\te\u0001f""#);
    }

    #[test]
    fn a_json_string_escapes_what_a_terminal_acts_on_as_well() {
        // DEL and the C1 block are controls the grammar asks nothing about, and a terminal
        // speaking eight-bit controls reads `U+009B` as a CSI.
        assert_eq!(
            json("a\u{7f}b\u{9b}[31mc\u{9f}"),
            r#""a\u007fb\u009b[31mc\u009f""#
        );
        // A direction override is category `Cf` rather than a control, so `is_control`
        // misses it, and left raw it would reorder the rest of the line for every consumer
        // that prints the document. Escaped, a parser still reads back the character the
        // name held, so the document carries the name and nothing acts on it on the way.
        assert_eq!(json("photo\u{202e}gnp.exe"), r#""photo\u202egnp.exe""#);
        assert_eq!(json("a\u{2066}b\u{200f}c"), r#""a\u2066b\u200fc""#);
        // An ordinary non-ASCII character is neither, and stands as itself.
        assert_eq!(json("caf\u{e9}"), "\"caf\u{e9}\"");
    }

    #[test]
    #[cfg(feature = "tar")]
    fn every_error_that_names_a_path_renders_it_through_this() {
        // The second way image bytes reach a terminal: not a finding but an error, printed
        // by whatever ran the command. A name is escaped in the `Display` that builds the
        // message, for the same reason it is escaped in a finding — that is the last point
        // anything can tell the name from the words around it.
        let hostile = b"/tmp/\x1b[2Jgone\r".to_vec();
        let messages = [
            crate::archive::ArchiveError::Unrepresentable {
                path: hostile.clone(),
            }
            .to_string(),
            crate::archive::ArchiveError::XattrNameUnrepresentable {
                path: hostile.clone(),
                name: b"user.\x1b[31m".to_vec(),
            }
            .to_string(),
            crate::archive::ArchiveError::Bad {
                path: hostile.clone(),
                reason: "a reason",
            }
            .to_string(),
        ];
        for message in messages {
            assert!(
                !message.chars().any(char::is_control),
                "an error message carries a raw control byte: {message:?}"
            );
            assert!(
                message.contains("\\x1b"),
                "and still names the path: {message:?}"
            );
        }
    }

    #[test]
    #[cfg(all(feature = "dir", any(target_os = "linux", target_os = "android")))]
    fn a_path_off_the_host_is_escaped_like_one_off_an_image() {
        // The other input surface. A tree a build points a walk at is an unpacked tarball or
        // a container layer, so its names are someone else's choice just as an image's are —
        // and `Path::display` does nothing about a control character, so an error naming one
        // would put the same forged output on the terminal that the image path is escaped to
        // prevent.
        use std::path::PathBuf;

        let hostile = PathBuf::from("staging/\u{1b}[2Jgone");
        let messages = [
            crate::HostError::NotADirectory {
                path: hostile.clone(),
            }
            .to_string(),
            crate::HostError::Unsupported {
                path: hostile.clone(),
            }
            .to_string(),
            crate::HostError::NotEmpty {
                path: hostile.clone(),
            }
            .to_string(),
            crate::HostError::RepeatedDirectory {
                path: hostile.clone(),
                first: hostile.clone(),
            }
            .to_string(),
            crate::HostError::UnstableXattrs {
                path: hostile,
                name: Some(b"user.\x1b[31m".to_vec()),
                attempts: 4,
            }
            .to_string(),
        ];
        for message in messages {
            assert!(
                !message.chars().any(char::is_control),
                "an error message carries a raw control byte: {message:?}"
            );
            assert!(
                message.contains("\\x1b"),
                "and still names the path: {message:?}"
            );
        }
    }

    #[test]
    fn invalid_utf8_still_names_the_entry() {
        // Refusing to render a name at all would leave a message that says less than the
        // image does. The replacement character is what a lossy rendering is for.
        assert_eq!(printable(b"caf\xc3"), "caf\u{fffd}");
        assert_eq!(printable(b"\xff\xfe"), "\u{fffd}\u{fffd}");
    }
}
