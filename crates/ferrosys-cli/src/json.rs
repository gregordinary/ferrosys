//! A small JSON writer: objects, arrays, and the four value kinds this tool emits.
//!
//! JSON is built rather than templated, so a value cannot escape its string: every
//! string goes through [`push_string`], which escapes what the grammar requires and
//! writes a control byte as a `\u00xx` escape.
//!
//! A filesystem name is a byte string and need not be text, but JSON strings are text.
//! [`Obj::bytes`] renders a name the way it reads and, when that rendering is not the
//! bytes themselves, adds a `<key>_hex` field carrying them exactly — so a machine
//! consuming the output can always recover the name, and a person reading it can always
//! read it.

use std::fmt::Write as _;

/// Append a JSON string literal for `s`, escaping what the grammar requires.
pub fn push_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The lowercase hex of `bytes`, with no separators.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A JSON object being written into a string. Dropping it without [`end`](Self::end)
/// leaves the object unterminated, so every one is ended explicitly.
pub struct Obj<'a> {
    out: &'a mut String,
    empty: bool,
}

impl<'a> Obj<'a> {
    /// Begin an object.
    pub fn new(out: &'a mut String) -> Self {
        out.push('{');
        Self { out, empty: true }
    }

    /// Write a key and the comma that precedes it once past the first field.
    fn key(&mut self, key: &str) {
        if !self.empty {
            self.out.push(',');
        }
        self.empty = false;
        push_string(self.out, key);
        self.out.push(':');
    }

    /// A string field.
    pub fn str(&mut self, key: &str, value: &str) {
        self.key(key);
        push_string(self.out, value);
    }

    /// An unsigned integer field.
    pub fn u64(&mut self, key: &str, value: u64) {
        self.key(key);
        let _ = write!(self.out, "{value}");
    }

    /// A signed integer field. Timestamps are seconds since the epoch and reach back
    /// before it, so they are signed.
    pub fn i64(&mut self, key: &str, value: i64) {
        self.key(key);
        let _ = write!(self.out, "{value}");
    }

    /// A boolean field.
    pub fn bool(&mut self, key: &str, value: bool) {
        self.key(key);
        self.out.push_str(if value { "true" } else { "false" });
    }

    /// A field whose value is already JSON, spliced in as a value rather than as a
    /// string — so a document a library rendered is never escaped a second time.
    pub fn raw(&mut self, key: &str, value: &str) {
        self.key(key);
        self.out.push_str(value);
    }

    /// A byte-string field — a filesystem name, a symlink target — rendered as text.
    ///
    /// When the rendering is not the bytes themselves, a `<key>_hex` field carries them
    /// exactly. The hex field is absent when it would say nothing new, so its presence
    /// is itself the signal that the name is not text.
    pub fn bytes(&mut self, key: &str, value: &[u8]) {
        let shown = String::from_utf8_lossy(value);
        self.str(key, &shown);
        if shown.as_bytes() != value {
            self.str(&format!("{key}_hex"), &hex(value));
        }
    }

    /// An array of strings.
    pub fn strings(&mut self, key: &str, values: &[&str]) {
        self.key(key);
        self.out.push('[');
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            push_string(self.out, v);
        }
        self.out.push(']');
    }

    /// A nested object.
    pub fn obj(&mut self, key: &str) -> Obj<'_> {
        self.key(key);
        Obj::new(self.out)
    }

    /// A nested array of objects.
    pub fn arr(&mut self, key: &str) -> Arr<'_> {
        self.key(key);
        Arr::new(self.out)
    }

    /// Close the object.
    pub fn end(self) {
        self.out.push('}');
    }
}

/// A JSON array of objects being written into a string.
pub struct Arr<'a> {
    out: &'a mut String,
    empty: bool,
}

impl<'a> Arr<'a> {
    /// Begin an array.
    fn new(out: &'a mut String) -> Self {
        out.push('[');
        Self { out, empty: true }
    }

    /// Begin one object element.
    pub fn obj(&mut self) -> Obj<'_> {
        if !self.empty {
            self.out.push(',');
        }
        self.empty = false;
        Obj::new(self.out)
    }

    /// Close the array.
    pub fn end(self) {
        self.out.push(']');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_escape_what_the_grammar_requires() {
        let mut out = String::new();
        push_string(&mut out, "a\"b\\c\nd\te\u{1}f");
        // A control byte has no literal form in a JSON string, so it goes out as the
        // escape the grammar defines for it.
        assert_eq!(out, r#""a\"b\\c\nd\te\u0001f""#);
    }

    #[test]
    fn an_object_carries_the_value_kinds_this_tool_emits() {
        let mut out = String::new();
        let mut o = Obj::new(&mut out);
        o.u64("blocks", 16384);
        o.i64("created", -1);
        o.bool("clean", true);
        o.str("uuid", "f0e1");
        o.strings("features", &["extent", "64bit"]);
        // A document a library rendered is spliced as a value, not as a string: it is
        // already JSON, and escaping it again would make it a string of JSON.
        o.raw("scan", "{\"clean\":true}");
        o.end();
        assert_eq!(
            out,
            r#"{"blocks":16384,"created":-1,"clean":true,"uuid":"f0e1","features":["extent","64bit"],"scan":{"clean":true}}"#
        );
    }

    #[test]
    fn a_name_that_is_not_text_carries_its_bytes_as_well() {
        let mut out = String::new();
        let mut o = Obj::new(&mut out);
        o.bytes("name", b"/etc/hostname");
        o.end();
        assert_eq!(
            out, r#"{"name":"/etc/hostname"}"#,
            "a name that is text says so once"
        );

        let mut out = String::new();
        let mut o = Obj::new(&mut out);
        o.bytes("name", b"/od\xffd");
        o.end();
        // The lossy rendering is what a person reads; the hex is what a machine recovers
        // the exact name from, and it appears only when the two differ.
        assert_eq!(
            out,
            r#"{"name":"/od\u{fffd}d","name_hex":"2f6f64ff64"}"#.replace("\\u{fffd}", "\u{fffd}")
        );
    }

    #[test]
    fn nested_objects_and_arrays() {
        let mut out = String::new();
        let mut o = Obj::new(&mut out);
        let mut inner = o.obj("features");
        inner.u64("unknown", 0);
        inner.end();
        let mut groups = o.arr("groups");
        let mut g = groups.obj();
        g.u64("group", 0);
        g.end();
        let mut g = groups.obj();
        g.u64("group", 1);
        g.end();
        groups.end();
        o.end();
        assert_eq!(
            out,
            r#"{"features":{"unknown":0},"groups":[{"group":0},{"group":1}]}"#
        );
    }
}
