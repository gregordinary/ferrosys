//! Building a JSON document: objects, arrays, and the value kinds a report carries.
//!
//! Every document this crate emits — a findings report, a SARIF log — and every document a
//! consumer wraps one in is built here rather than assembled from string pieces. What that
//! buys is not brevity: it is that the comma before a field, the quoting of a key, and the
//! escaping of a value are decided in one place, so a document cannot be well-formed in one
//! projection and not in another.
//!
//! Strings go out through [`push_json_string`], which escapes what
//! the grammar requires and, beyond it, everything a terminal acts on — so a name out of an
//! image cannot move or reorder what whoever reads the document sees.
//!
//! A filesystem name is a byte string and need not be text, where a JSON string is text.
//! [`Object::bytes`] renders a name the way it reads and, when that rendering is not the
//! bytes themselves, adds a `<key>_hex` field carrying them exactly — so a machine consuming
//! the document can always recover the name and a person reading it can always read it.
//!
//! Nothing here parses. This crate writes documents and reads filesystems, and a JSON reader
//! would be a second thing to keep correct for no consumer.

use std::fmt::Write as _;

use crate::escape::{hex, push_json_string};

/// A JSON object being written into a string.
///
/// Dropping one without [`end`](Self::end) leaves the object unterminated, so every one is
/// ended explicitly — a nested object's lifetime borrows the string it is being written
/// into, which is what stops a caller writing to the outer object while an inner one is
/// open.
pub struct Object<'a> {
    out: &'a mut String,
    empty: bool,
}

impl<'a> Object<'a> {
    /// Begin an object, writing its opening brace into `out`.
    pub fn new(out: &'a mut String) -> Self {
        out.push('{');
        Self { out, empty: true }
    }

    /// Write a key, and the comma that precedes it once past the first field.
    fn key(&mut self, key: &str) {
        if !self.empty {
            self.out.push(',');
        }
        self.empty = false;
        push_json_string(self.out, key);
        self.out.push(':');
    }

    /// A string field.
    pub fn str(&mut self, key: &str, value: &str) {
        self.key(key);
        push_json_string(self.out, value);
    }

    /// An unsigned integer field.
    pub fn u64(&mut self, key: &str, value: u64) {
        self.key(key);
        let _ = write!(self.out, "{value}");
    }

    /// A signed integer field. A timestamp is seconds since the epoch and reaches back
    /// before it, so it is signed.
    pub fn i64(&mut self, key: &str, value: i64) {
        self.key(key);
        let _ = write!(self.out, "{value}");
    }

    /// A boolean field.
    pub fn bool(&mut self, key: &str, value: bool) {
        self.key(key);
        self.out.push_str(if value { "true" } else { "false" });
    }

    /// A field whose value is already JSON, spliced in as a value rather than as a string —
    /// so a document one layer rendered is never escaped a second time by the layer that
    /// carries it.
    ///
    /// The caller is stating that `value` is a well-formed JSON value. Nothing here checks
    /// it, because the only producer that should reach this is another writer of this kind.
    pub fn raw(&mut self, key: &str, value: &str) {
        self.key(key);
        self.out.push_str(value);
    }

    /// A byte-string field — a filesystem name, a symbolic link's target — rendered as text.
    ///
    /// When the rendering is not the bytes themselves, a `<key>_hex` field carries them
    /// exactly. The hex field is absent where it would say nothing new, so its presence is
    /// itself the signal that the name is not text.
    ///
    /// A name that *is* text needs no companion even when it holds a character a terminal
    /// acts on: the escaper writes that character as the `\uXXXX` escape the grammar
    /// defines, which a parser reads back as the character the name held. The document
    /// carries the name exactly and nothing acts on it on the way.
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
            push_json_string(self.out, v);
        }
        self.out.push(']');
    }

    /// An array of whole numbers — a list of addresses, offsets, or counts.
    ///
    /// The counterpart of [`strings`](Self::strings), for the lists a document holds that are
    /// numbers rather than words. Both are here rather than as an [`Array`] because an array
    /// of scalars needs no builder: there is nothing to nest and nothing to close in order.
    pub fn u64s(&mut self, key: &str, values: &[u64]) {
        self.key(key);
        self.out.push('[');
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            self.out.push_str(&v.to_string());
        }
        self.out.push(']');
    }

    /// A nested object.
    pub fn obj(&mut self, key: &str) -> Object<'_> {
        self.key(key);
        Object::new(self.out)
    }

    /// A nested array of objects.
    pub fn arr(&mut self, key: &str) -> Array<'_> {
        self.key(key);
        Array::new(self.out)
    }

    /// Close the object.
    pub fn end(self) {
        self.out.push('}');
    }
}

/// A JSON array of objects being written into a string.
///
/// Every array this crate emits holds objects, so this is the only element kind — a list of
/// scalars is [`Object::strings`], which needs no builder.
pub struct Array<'a> {
    out: &'a mut String,
    empty: bool,
}

impl<'a> Array<'a> {
    /// Begin an array, writing its opening bracket into `out`.
    pub fn new(out: &'a mut String) -> Self {
        out.push('[');
        Self { out, empty: true }
    }

    /// Begin one object element.
    pub fn obj(&mut self) -> Object<'_> {
        if !self.empty {
            self.out.push(',');
        }
        self.empty = false;
        Object::new(self.out)
    }

    /// Close the array.
    pub fn end(self) {
        self.out.push(']');
    }
}

#[cfg(test)]
mod tests {
    use super::{Array, Object};

    #[test]
    fn an_object_carries_the_value_kinds_a_document_holds() {
        let mut out = String::new();
        let mut o = Object::new(&mut out);
        o.u64("blocks", 16384);
        o.i64("created", -1);
        o.bool("clean", true);
        o.str("uuid", "f0e1");
        o.strings("features", &["extent", "64bit"]);
        // A document another layer rendered is spliced as a value, not as a string: it is
        // already JSON, and escaping it again would make it a string of JSON.
        o.raw("scan", "{\"clean\":true}");
        o.end();
        assert_eq!(
            out,
            r#"{"blocks":16384,"created":-1,"clean":true,"uuid":"f0e1","features":["extent","64bit"],"scan":{"clean":true}}"#
        );
    }

    #[test]
    fn every_string_a_document_carries_goes_through_the_escaper() {
        // The rules and their cases are `escape`'s, and are tested there. What is asserted
        // here is that this writer puts every string through them: a key, a value, and an
        // array element alike. A direction override is the sharp case, because it is valid
        // UTF-8 and category `Cf` rather than a control, so it survives every other check a
        // document makes and reorders the line for whoever prints it.
        let mut out = String::new();
        let mut o = Object::new(&mut out);
        o.str("label\u{1b}", "photo\u{202e}gnp.exe");
        o.strings("features", &["a\u{9b}[31m"]);
        o.end();
        assert_eq!(
            out,
            r#"{"label\u001b":"photo\u202egnp.exe","features":["a\u009b[31m"]}"#
        );
    }

    #[test]
    fn a_name_that_is_not_text_carries_its_bytes_as_well() {
        let mut out = String::new();
        let mut o = Object::new(&mut out);
        o.bytes("name", b"/etc/hostname");
        o.end();
        assert_eq!(
            out, r#"{"name":"/etc/hostname"}"#,
            "a name that is text says so once"
        );

        let mut out = String::new();
        let mut o = Object::new(&mut out);
        o.bytes("name", b"/od\xffd");
        o.end();
        // The lossy rendering is what a person reads; the hex is what a machine recovers the
        // exact name from, and it appears only when the two differ.
        assert_eq!(
            out,
            r#"{"name":"/od\u{fffd}d","name_hex":"2f6f64ff64"}"#.replace("\\u{fffd}", "\u{fffd}")
        );
    }

    #[test]
    fn nested_objects_and_arrays() {
        let mut out = String::new();
        let mut o = Object::new(&mut out);
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

    #[test]
    fn an_empty_object_and_an_empty_array_are_still_well_formed() {
        let mut out = String::new();
        Object::new(&mut out).end();
        assert_eq!(out, "{}");
        let mut out = String::new();
        Array::new(&mut out).end();
        assert_eq!(out, "[]");
    }
}
