//! Rendering values into the forms their readers require.
//!
//! Most of what this module renders comes out of an image and is rendered for a person: a
//! label, a mode, a time, and the [`Rows`] every label-and-value table here is built from.
//! [`uri_reference`] renders for a machine instead — a host path in the URI dialect a SARIF
//! consumer requires.
//!
//! This module is pure and has no calendar of its own: [`iso8601`] renders a civil date
//! computed arithmetically, so a timestamp renders the same everywhere. Every time this tool
//! prints is UTC, computed rather than looked up.

use std::fmt::Write as _;
use std::path::Path;

use ferrosys::ext::ondisk::unpadded;
use ferrosys::{Acl, AclQualifier, Timestamp};

use crate::args::os;

/// The canonical dashed form of a 16-byte identifier: the filesystem UUID, and the
/// directory-hash seed, which is written the same way.
///
/// The 8-4-4-4-12 grouping is the only thing here that is a UUID's own; the digits come from
/// the crate's one hex renderer, so a UUID and the `_hex` field beside a name in a document
/// are written by the same code.
#[must_use]
pub fn uuid(bytes: &[u8; 16]) -> String {
    let group = |range: std::ops::Range<usize>| hex(&bytes[range]);
    format!(
        "{}-{}-{}-{}-{}",
        group(0..4),
        group(4..6),
        group(6..8),
        group(8..10),
        group(10..16)
    )
}

/// A label-and-value table being built, one row per line.
///
/// Every table this tool prints has the same shape — a label, padding to a fixed column, the
/// value — and the padding is the whole of the format, so it is decided here rather than at
/// each `writeln!`. What each table chooses is the column, and there are two:
/// [`report`](Self::report) for a description of an image and [`summary`](Self::summary) for
/// an account of what a command did.
pub struct Rows {
    out: String,
    width: usize,
}

impl Rows {
    /// A table describing an image, as `inspect` prints one.
    ///
    /// The wider column: a description names the field the filesystem itself names, and
    /// those run long — `Directory hash signedness:` is twenty-six characters.
    #[must_use]
    pub fn report() -> Self {
        Self {
            out: String::new(),
            width: 28,
        }
    }

    /// A table accounting for what a command did, as `format` and `extract` print one.
    ///
    /// The narrower column: these labels name what was written rather than what a format
    /// calls it, and none of them reaches the width above.
    #[must_use]
    pub fn summary() -> Self {
        Self {
            out: String::new(),
            width: 24,
        }
    }

    /// One row: `label`, padded to the column, then `value`.
    ///
    /// A label at or past the column still takes one space, so a table that grows a long
    /// label loses its alignment rather than running the value into the label.
    pub fn row(&mut self, label: &str, value: impl std::fmt::Display) {
        let pad = self.width.saturating_sub(label.len()).max(1);
        let _ = writeln!(self.out, "{label}{:pad$}{value}", "");
    }

    /// A blank line, separating one section of a table from the next.
    pub fn blank(&mut self) {
        self.out.push('\n');
    }

    /// Text this table carries that is not a row: a column-headed listing, a note.
    pub fn text(&mut self, text: &str) {
        self.out.push_str(text);
    }

    /// The table as it now stands.
    #[must_use]
    pub fn finish(self) -> String {
        self.out
    }
}

/// A FAT volume serial number in the form every tool that shows one writes it: two
/// upper-case hex groups of four digits, separated by a dash.
///
/// The spelling is the convention rather than a choice — it is what a driver, `fatlabel`,
/// and a DOS `VOL` all print — so a serial copied out of this tool's report matches one
/// copied out of any other.
#[must_use]
pub fn volume_serial(id: u32) -> String {
    format!("{:04X}-{:04X}", id >> 16, id & 0xffff)
}

/// An ext volume label as a person reads it: the field's name, rendered lossily, or `None`
/// when the label is empty.
///
/// Where the padding stops is the format's rule, not this tool's, so it comes from the
/// library — which is also what the caller wanting the *bytes* rather than the rendering
/// reaches for, so the two never disagree about where a label ends.
///
/// The field is bytes, not guaranteed text, so a non-UTF-8 label renders with the
/// replacement character rather than failing — the same forensic reading the reader gives
/// a label it did not write.
#[must_use]
pub fn label(name: &[u8; 16]) -> Option<String> {
    let name = unpadded(name);
    (!name.is_empty()).then(|| printable(name))
}

/// Render image-controlled bytes for a person to read on a terminal, with every character
/// that acts on the terminal rather than appearing on it replaced by a visible escape.
///
/// A name, symlink target, or label comes from the filesystem, which a reader does not
/// trust: left raw, an escape sequence in one could move the cursor, recolor the line, or
/// erase what precedes it, and a direction override could reverse the rest of the line so
/// that a path reads as one thing and resolves as another. So a crafted image could forge
/// or hide output.
///
/// This is the library's own [`ferrosys::printable`], not a copy of it. The rule is the same
/// rule — the escaping every message and finding the library renders has already been
/// through — and a second implementation of it here would be a second place for it to drift.
/// The JSON projection escapes the same two classes on its own, inside the library's own
/// writer, so only the human renderers reach for this.
pub use ferrosys::printable;

/// Bytes as lower-case hexadecimal: the rendering that loses nothing, for a value that is an
/// identifier rather than text and for a document carrying a name it could not render.
///
/// The library's own, like [`printable`] and for the same reason — a document this tool
/// writes and one the library writes state the same bytes the same way.
pub use ferrosys::hex;

/// The mode as `ls` writes it: the type letter, then the owner, group, and other
/// permission triples, with the `setuid`, `setgid`, and sticky bits folded into the
/// execute positions as they are on a terminal.
#[must_use]
pub fn mode(mode: u16) -> String {
    let kind = match mode & 0o170000 {
        0o140000 => 's',
        0o120000 => 'l',
        0o100000 => '-',
        0o060000 => 'b',
        0o040000 => 'd',
        0o020000 => 'c',
        0o010000 => 'p',
        _ => '?',
    };
    let mut out = String::with_capacity(10);
    out.push(kind);
    // Each triple's execute position carries the set-id or sticky bit when one is set:
    // `s`/`t` when the execute bit is also set, `S`/`T` when it is not.
    let triple = |shift: u32, special: bool, special_set: char, special_clear: char| {
        let bits = (mode >> shift) & 0o7;
        let mut t = String::with_capacity(3);
        t.push(if bits & 4 != 0 { 'r' } else { '-' });
        t.push(if bits & 2 != 0 { 'w' } else { '-' });
        t.push(match (bits & 1 != 0, special) {
            (true, true) => special_set,
            (false, true) => special_clear,
            (true, false) => 'x',
            (false, false) => '-',
        });
        t
    };
    out.push_str(&triple(6, mode & 0o4000 != 0, 's', 'S'));
    out.push_str(&triple(3, mode & 0o2000 != 0, 's', 'S'));
    out.push_str(&triple(0, mode & 0o1000 != 0, 't', 'T'));
    out
}

/// A host path as a URI reference, for a consumer that requires one.
///
/// A path is not a URI: a space is not allowed at all, and `#`, `?`, and `%` each mean
/// something else, so a validator reading a document that carries a path verbatim rejects
/// it — SARIF's `artifactLocation.uri` is the case at hand. Every byte outside the
/// unreserved set (`A`-`Z`, `a`-`z`, `0`-`9`, `-`, `.`, `_`, `~`) is percent-encoded and
/// `/` is kept as the separator it already is, so the reference is legal to parse and
/// decodes back to the path byte for byte. Encoding `:` along with the rest keeps a
/// relative path's first segment from reading as a scheme.
///
/// A rooted path becomes an absolute `file://` URI, naming the host it was read on; any
/// other path stays a relative reference, naming what the invocation named.
#[must_use]
pub fn uri_reference(path: &Path) -> String {
    let bytes = os::bytes(path.as_os_str());
    let mut out = String::new();
    if bytes.first() == Some(&b'/') {
        out.push_str("file://");
    }
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// A time as `YYYY-MM-DDTHH:MM:SSZ`, in UTC.
///
/// The calendar is the library's, which is the one the FAT writer encodes a date with — so
/// what this tool prints and what an image stores are read off the same arithmetic.
///
/// ext4 timestamps reach from 1901 to 2446, and a negative count of seconds is a time
/// before the epoch, so the arithmetic floors rather than truncates: `-1` second is
/// `1969-12-31T23:59:59Z`, not one second into 1970.
#[must_use]
pub fn iso8601(secs: i64) -> String {
    Timestamp::from_secs(secs).civil().to_string()
}

/// A POSIX ACL in `getfacl`'s `tag:qualifier:perms` spelling, entries comma-joined on one
/// line, in the order the ACL stores them. One line rather than `getfacl`'s one entry per
/// line, because this is a value in a label-and-value table and a multi-line value would
/// break the column.
///
/// The on-disk form is ext's compact encoding, which is neither what a person reads nor what
/// any other tool speaks, so an ACL that is only ever shown as bytes is an ACL nobody can
/// check. Named users and groups carry their numeric id, since a filesystem records ids and
/// this tool resolves no names — the host's `/etc/passwd` has nothing to do with the image's.
#[must_use]
pub fn acl(acl: &Acl) -> String {
    let mut out = String::new();
    for entry in acl.entries() {
        if !out.is_empty() {
            out.push(',');
        }
        let (tag, qualifier) = match entry.who {
            AclQualifier::UserObj => ("user", String::new()),
            AclQualifier::User(uid) => ("user", uid.to_string()),
            AclQualifier::GroupObj => ("group", String::new()),
            AclQualifier::Group(gid) => ("group", gid.to_string()),
            AclQualifier::Mask => ("mask", String::new()),
            AclQualifier::Other => ("other", String::new()),
        };
        let bits = [(Acl::READ, 'r'), (Acl::WRITE, 'w'), (Acl::EXEC, 'x')]
            .iter()
            .map(|&(bit, ch)| if entry.perm & bit != 0 { ch } else { '-' })
            .collect::<String>();
        out.push_str(&format!("{tag}:{qualifier}:{bits}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_volume_serial_is_written_the_way_every_tool_prints_one() {
        // Two upper-case hex groups of four digits: what a driver, `fatlabel`, and a DOS
        // `VOL` all show, so a serial copied out of this tool matches one copied out of any
        // other — and one this prints can be typed back into `format --volume-id`.
        assert_eq!(volume_serial(0x1a2b_3c4d), "1A2B-3C4D");
        assert_eq!(volume_serial(0), "0000-0000");
        assert_eq!(volume_serial(u32::MAX), "FFFF-FFFF");
        // Leading zeros are kept in both halves: the field is eight digits wide, and a
        // shorter rendering would be a different serial.
        assert_eq!(volume_serial(0x0001_0002), "0001-0002");
    }

    #[test]
    fn a_uuid_is_written_in_the_canonical_dashed_form() {
        assert_eq!(
            uuid(&[
                0xf0, 0xe1, 0x70, 0x55, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0
            ]),
            "f0e17055-0000-4000-8000-000000000000"
        );
        assert_eq!(uuid(&[0; 16]), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn a_label_reads_up_to_its_first_nul() {
        assert_eq!(
            label(b"rootfs\0\0\0\0\0\0\0\0\0\0").as_deref(),
            Some("rootfs")
        );
        // A full sixteen bytes has no terminator.
        assert_eq!(
            label(b"0123456789abcdef").as_deref(),
            Some("0123456789abcdef")
        );
        // An empty field is no label at all.
        assert_eq!(label(&[0u8; 16]), None);
        // A non-UTF-8 label renders lossily rather than failing.
        assert_eq!(
            label(b"a\xffb\0\0\0\0\0\0\0\0\0\0\0\0\0").as_deref(),
            Some("a\u{fffd}b")
        );
        // A control byte in a label is escaped, not sent to the terminal raw.
        assert_eq!(
            label(b"a\x1bb\0\0\0\0\0\0\0\0\0\0\0\0\0").as_deref(),
            Some("a\\x1bb")
        );
    }

    #[test]
    fn a_path_renders_as_a_uri_reference_that_decodes_back_to_it() {
        // The common case: a rooted path of ordinary characters becomes a `file://` URI
        // with nothing encoded.
        assert_eq!(
            uri_reference(Path::new("/var/tmp/disk.img")),
            "file:///var/tmp/disk.img"
        );
        // Every character the URI grammar treats specially is encoded. A space is not
        // allowed in a URI at all; `#` starts a fragment, `?` a query, `%` an escape, and
        // a `:` in a relative reference's first segment would read as a scheme.
        assert_eq!(
            uri_reference(Path::new("a b#c?d%e:f")),
            "a%20b%23c%3Fd%25e%3Af"
        );
        // Non-ASCII is encoded a byte at a time, which is what a URI carries.
        assert_eq!(uri_reference(Path::new("café.img")), "caf%C3%A9.img");
        // The unreserved set survives, and `/` stays the separator.
        assert_eq!(
            uri_reference(Path::new("/a-b/c.d/e_f/g~h")),
            "file:///a-b/c.d/e_f/g~h"
        );
        // A relative path stays relative: it names what the invocation named.
        assert_eq!(uri_reference(Path::new("./sub/disk.img")), "./sub/disk.img");
    }

    #[test]
    fn a_mode_reads_as_it_does_on_a_terminal() {
        assert_eq!(mode(0o040755), "drwxr-xr-x");
        assert_eq!(mode(0o100644), "-rw-r--r--");
        assert_eq!(mode(0o120777), "lrwxrwxrwx");
        assert_eq!(mode(0o020666), "crw-rw-rw-");
        assert_eq!(mode(0o060660), "brw-rw----");
        assert_eq!(mode(0o010600), "prw-------");
        assert_eq!(mode(0o140666), "srw-rw-rw-");
        // The set-id and sticky bits sit in the execute positions, upper-cased when the
        // execute bit they share is clear.
        assert_eq!(mode(0o104755), "-rwsr-xr-x");
        assert_eq!(mode(0o104644), "-rwSr--r--");
        assert_eq!(mode(0o041777), "drwxrwxrwt");
        assert_eq!(mode(0o041666), "drw-rw-rwT");
    }

    #[test]
    fn a_time_renders_as_utc_without_a_calendar_to_consult() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap day in a year divisible by 400, which the 100-year rule would otherwise
        // have skipped.
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        // Before the epoch the arithmetic floors: one second before 1970 is the last
        // second of 1969, not the first of 1970.
        assert_eq!(iso8601(-1), "1969-12-31T23:59:59Z");
        // The ends of the range an ext4 timestamp reaches.
        assert_eq!(iso8601(-2_147_483_648), "1901-12-13T20:45:52Z");
        assert_eq!(iso8601(15_032_385_535), "2446-05-10T22:38:55Z");
    }
}
