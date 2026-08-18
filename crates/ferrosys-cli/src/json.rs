//! The JSON documents this tool emits: the envelope every one of them shares.
//!
//! The writer itself — objects, arrays, the value kinds, and the escaping of every string
//! that goes into one — is the library's [`ferrosys::json`], re-exported here rather than
//! reimplemented. A document this tool emits and the findings report the library renders
//! into it are read by the same consumer through the same `jq`, so one writer builds both
//! and there is nowhere for comma placement or escaping to drift to.
//!
//! What is this tool's own is the envelope: which schema version a document declares, and
//! that it ends in a newline.

/// The version of the document shapes this tool emits, carried as the `schema` field at the
/// head of every one of them.
///
/// A downstream parser depends on the shape, and no signature describes it, so the shape
/// names its own version — and it is named the same thing in every document the tool emits,
/// including the library's own findings report (`ferrosys::FINDINGS_SCHEMA_VERSION`), so a
/// consumer reads one field wherever it looks. The tool's version says what wrote a
/// document; this says what the document *is*, and the two move independently.
pub const SCHEMA_VERSION: u64 = 2;

/// The library's JSON writer, which is what builds every document here. It escapes every
/// string it is given through the library's own escaper, so a name out of an image reaches a
/// document by the same route whichever layer wrote the document.
pub use ferrosys::json::Object;

/// One whole document, ready to emit: the object `build` fills, opened with the
/// [`SCHEMA_VERSION`] field every document leads with and closed by the newline every one
/// ends in.
///
/// Both of those are contract rather than convention — a consumer reads the schema field
/// wherever it looks, and a document that did not end in a newline would run into whatever
/// followed it on a stream. Stamping them here makes them properties of the writer instead
/// of a step each command has to remember.
pub fn document(build: impl FnOnce(&mut Object<'_>)) -> String {
    let mut out = String::new();
    let mut o = Object::new(&mut out);
    o.u64("schema", SCHEMA_VERSION);
    build(&mut o);
    o.end();
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::document;

    #[test]
    fn every_document_declares_its_schema_and_ends_in_a_newline() {
        // The two properties this module adds to the library's writer. A consumer reads the
        // schema field wherever it looks, and a document that did not end in a newline would
        // run into whatever followed it on a stream.
        let out = document(|o| o.bool("written", true));
        assert_eq!(out, "{\"schema\":2,\"written\":true}\n");
        // Empty but for the envelope is still a document.
        assert_eq!(document(|_| {}), "{\"schema\":2}\n");
    }
}
