//! Rendering values into the forms their readers require.
//!
//! Most of what this module renders comes out of an image and is rendered for a person: a
//! label, a mode, a time. [`uri_reference`] renders for a machine instead — a host path
//! in the URI dialect a SARIF consumer requires.
//!
//! This module is pure and has no calendar of its own: [`iso8601`] computes a civil date
//! from a count of seconds arithmetically, so a timestamp renders the same everywhere.
//! Every time this tool prints is UTC, computed rather than looked up.

use std::fmt::Write as _;
use std::path::Path;

use ferrosys::ext::ondisk::Timestamp;

use crate::args::os;

/// Seconds in a day.
const DAY: i64 = 86_400;

/// The canonical dashed form of a 16-byte identifier: the filesystem UUID, and the
/// directory-hash seed, which is written the same way.
#[must_use]
pub fn uuid(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A volume label as a person reads it: the bytes up to the first NUL, rendered lossily,
/// or `None` when the label is empty.
///
/// The field is bytes, not guaranteed text, so a non-UTF-8 label renders with the
/// replacement character rather than failing — the same forensic reading the reader gives
/// a label it did not write.
#[must_use]
pub fn label(name: &[u8; 16]) -> Option<String> {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    (end != 0).then(|| printable(&name[..end]))
}

/// Render image-controlled bytes for a person to read on a terminal, with every control
/// character replaced by a visible `\xNN` escape.
///
/// A name, symlink target, or label comes from the filesystem, which a reader does not
/// trust: left raw, an escape sequence in one could move the cursor, recolor the line, or
/// erase what precedes it, so a crafted image could forge or hide output. Escaping the
/// control bytes renders the value faithfully without handing the terminal their effect.
/// Invalid UTF-8 still renders lossily, as elsewhere; the JSON projection escapes these
/// bytes on its own, so only the human renderers need this.
#[must_use]
pub fn printable(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for c in String::from_utf8_lossy(bytes).chars() {
        if c.is_control() {
            // A control character is at most `U+009F`, so two hex digits name it.
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

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
/// ext4 timestamps reach from 1901 to 2446, and a negative count of seconds is a time
/// before the epoch, so the arithmetic floors rather than truncates: `-1` second is
/// `1969-12-31T23:59:59Z`, not one second into 1970.
#[must_use]
pub fn iso8601(secs: i64) -> String {
    let days = secs.div_euclid(DAY);
    let rem = secs.rem_euclid(DAY);
    let (y, m, d) = civil_from_days(days);
    let (h, min, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
}

/// The civil year, month, and day a count of days since 1970-01-01 names, in the
/// proleptic Gregorian calendar.
///
/// The computation shifts the epoch to March 1st of year 0, which puts the leap day at
/// the end of the year and makes the month lengths a regular sequence; the era is the
/// 400-year cycle over which the calendar repeats exactly.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // 719468 days from 0000-03-01 to 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era, 0..=146096
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // 0..=399
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365, from March 1st
    let mp = (5 * doy + 2) / 153; // 0..=11, March is 0
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // 1..=31
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // 1..=12
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// A timestamp as a PAX record's value: decimal seconds, with a fractional part when the
/// time carries one.
///
/// A negative time floors its seconds and carries the fraction up towards the next
/// second — the same convention the archive source reads back — so
/// `Timestamp { secs: -6, nanos: 750_000_000 }` is written `-5.250000000`, which is the
/// instant it names.
///
/// An inode's stored fraction is a thirty-bit field, so a filesystem this crate did not
/// write can name more nanoseconds than there are in a second. Such a fraction is carried
/// into the seconds before anything is written, so the record names the instant the two
/// fields describe and always holds a nine-digit fraction — rather than a ten-digit one a
/// reader would scale wrongly.
#[must_use]
pub fn pax_time(t: Timestamp) -> String {
    // Normalize first: every case below assumes a fraction smaller than a second.
    let t = Timestamp {
        secs: t
            .secs
            .saturating_add(i64::from(t.nanos / Timestamp::NANOS_PER_SEC)),
        nanos: t.nanos % Timestamp::NANOS_PER_SEC,
    };
    if t.nanos == 0 {
        return t.secs.to_string();
    }
    if t.secs < 0 {
        let whole = t.secs + 1;
        let frac = Timestamp::NANOS_PER_SEC - t.nanos;
        // A time inside the last second before the epoch has no negative whole part to
        // carry the sign, so the sign is written onto the zero.
        if whole == 0 {
            return format!("-0.{frac:09}");
        }
        return format!("{whole}.{frac:09}");
    }
    format!("{}.{:09}", t.secs, t.nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn printable_escapes_control_bytes_and_keeps_the_rest() {
        // Ordinary text, including the path separator, passes through untouched.
        assert_eq!(printable(b"/etc/passwd"), "/etc/passwd");
        // A terminal escape sequence a crafted image might carry is neutralized: the ESC
        // and the carriage return become visible escapes rather than acting on the
        // terminal.
        assert_eq!(
            printable(b"safe\x1b[31mred\rgone"),
            "safe\\x1b[31mred\\x0dgone"
        );
        // NUL and DEL are controls too.
        assert_eq!(printable(b"a\0b\x7fc"), "a\\x00b\\x7fc");
        // Invalid UTF-8 still renders lossily.
        assert_eq!(printable(b"a\xffb"), "a\u{fffd}b");
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

    #[test]
    fn a_pax_time_is_the_instant_it_names() {
        assert_eq!(pax_time(Timestamp::from_secs(1_700_000_000)), "1700000000");
        assert_eq!(
            pax_time(Timestamp {
                secs: 1_700_000_000,
                nanos: 123_456_789
            }),
            "1700000000.123456789"
        );
        // A negative time stores the floored second and the fraction up to the next one;
        // the decimal form is the instant itself.
        assert_eq!(
            pax_time(Timestamp {
                secs: -6,
                nanos: 750_000_000
            }),
            "-5.250000000"
        );
        // Inside the last second before the epoch there is no negative whole part, so the
        // sign is written onto the zero.
        assert_eq!(
            pax_time(Timestamp {
                secs: -1,
                nanos: 500_000_000
            }),
            "-0.500000000"
        );
        assert_eq!(pax_time(Timestamp::from_secs(-1)), "-1");
    }

    #[test]
    fn a_pax_time_carries_an_over_long_fraction_into_the_seconds() {
        // An inode's fraction is a thirty-bit field, so an image this crate did not write
        // can name more nanoseconds than a second holds. The record still names the
        // instant the two fields describe, with a nine-digit fraction: writing the raw
        // value would make a ten-digit one, which a reader scales as a tenth of what was
        // meant.
        assert_eq!(
            pax_time(Timestamp {
                secs: 100,
                nanos: 1_073_741_823 // the largest the field holds
            }),
            "101.073741823"
        );
        // The same on the negative side, where the fraction is written as the distance to
        // the next second — the subtraction that an over-long fraction would otherwise
        // take below zero.
        assert_eq!(
            pax_time(Timestamp {
                secs: -6,
                nanos: 1_073_741_823
            }),
            "-4.926258177"
        );
        // A whole number of extra seconds leaves no fraction at all.
        assert_eq!(
            pax_time(Timestamp {
                secs: 10,
                nanos: 2_000_000_000
            }),
            "12"
        );
    }
}
