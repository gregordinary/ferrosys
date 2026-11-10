//! LZVN and LZFSE decoders in safe Rust.
//!
//! LZVN and LZFSE are two of the encodings an APFS compressed file keeps its content in, one
//! stream per chunk of the file. This crate undoes one stream into a buffer the caller sizes.
//! It is what the `lzvn` and `lzfse` features of [`ferrosys`](https://crates.io/crates/ferrosys)
//! compile, and ferrosys is what finds the streams in a volume and decides how many bytes each
//! expands to.
//!
//! The decoders are derived from the ones in Apple's reference implementation, the `lzfse`
//! project (copyright 2015-2016 Apple Inc.), and are distributed under its BSD-3-Clause license,
//! whose text `LICENSE` carries.
//!
//! # One signature, and a bound that is the caller's
//!
//! Each decoder fills a caller-supplied slice and reports how much of it was filled. A stream is
//! untrusted input, so the slice bounds the work: a stream that would expand past it is
//! [`Error::Overrun`], and a decoder allocates nothing on the strength of a length the stream
//! declares. Producing fewer bytes than the slice holds is not an error here; whether a short
//! stream is a fault is the caller's to say, since the caller knows what it asked for.
//!
//! ```
//! // An LZVN stream: a literal of five bytes, then the end-of-stream instruction.
//! let stream = [0xE5, b'h', b'e', b'l', b'l', b'o', 0x06, 0, 0, 0, 0, 0, 0, 0];
//! let mut out = [0u8; 16];
//! let produced = ferrosys_lzfse::decompress_lzvn(&stream, &mut out)?;
//! assert_eq!(&out[..produced], b"hello");
//! # Ok::<(), ferrosys_lzfse::Error>(())
//! ```
//!
//! Both decoders are pure: bytes in, bytes out, no I/O.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The crate's README, compiled as a doctest so the example on its front page is the example
/// this crate's API accepts. The item exists only while rustdoc is collecting doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;

mod lzfse;
mod lzvn;

/// Why a stream could not be turned back into the bytes it stands for.
///
/// The two are kept apart because they say different things about the stream: one is not a
/// well-formed stream of its kind, and the other is one that expands to more than the caller
/// was told it holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The stream is not a well-formed one of its kind.
    #[error("the stream does not decode: {fault}")]
    #[non_exhaustive]
    Malformed {
        /// What was wrong with it.
        fault: &'static str,
    },
    /// The stream expands past the buffer it was given.
    #[error("the stream expands past the {expected} bytes it was given")]
    #[non_exhaustive]
    Overrun {
        /// The buffer's length.
        expected: usize,
    },
}

/// Undo one LZVN stream into `out`, returning how many bytes it produced.
///
/// The stream ends at its end-of-stream instruction; bytes after it are not read.
///
/// # Errors
///
/// [`Error::Overrun`] where the stream expands past `out`, and [`Error::Malformed`] where it is
/// not a well-formed LZVN stream.
pub fn decompress_lzvn(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    lzvn::decompress(input, out)
}

/// Undo one LZFSE stream into `out`, returning how many bytes it produced.
///
/// The stream ends at its end block; bytes after it are not read.
///
/// # Errors
///
/// [`Error::Overrun`] where the stream expands past `out`, and [`Error::Malformed`] where it is
/// not a well-formed LZFSE stream.
pub fn decompress_lzfse(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    lzfse::decompress(input, out)
}

/// Write the `count` bytes from `distance` back at `at` of `out`, a byte at a time: a copy may
/// reach into the run it is producing, so a distance of one and a count of ten is ten copies of
/// one byte, and a block move would read bytes not yet written. `false`, copying nothing, where
/// the distance is zero or reaches before the output's start. The caller holds `at + count` to
/// the output's length.
fn copy_back(out: &mut [u8], at: usize, distance: usize, count: usize) -> bool {
    if distance == 0 || distance > at {
        return false;
    }
    for i in at..at + count {
        out[i] = out[i - distance];
    }
    true
}

/// Drive `decode` over every one-byte change of `stream`, a stream it decodes whole, and every
/// cut of it, into `room` bytes, and hold it to the one property every decoder here has:
/// whatever it is handed, it either produces bytes inside the buffer it was given or refuses.
///
/// Arbitrary bytes seldom get past a format's first length field, so a sweep of them reaches
/// the header and little after it. A stream the decoder reads whole, changed one byte at a
/// time, reaches every field after the header: a table, a count, a distance, the last block.
#[cfg(test)]
fn sweep_changes_of(
    stream: &[u8],
    room: usize,
    mut decode: impl FnMut(&[u8], &mut [u8]) -> Result<usize, Error>,
) {
    const GUARD: u8 = 0xee;
    let mut held = |bytes: &[u8], what: &dyn Fn() -> String| {
        let mut out = vec![GUARD; room + 64];
        if let Ok(produced) = decode(bytes, &mut out[..room]) {
            assert!(produced <= room, "{} reported {produced} of {room}", what());
        }
        assert!(
            out[room..].iter().all(|&b| b == GUARD),
            "{} wrote past the buffer it was given",
            what()
        );
    };
    let mut changed = stream.to_vec();
    for at in 0..stream.len() {
        for value in [
            stream[at] ^ 0x01,
            stream[at] ^ 0x80,
            !stream[at],
            0x00,
            0x7F,
            0xFF,
        ] {
            changed[at] = value;
            held(&changed, &|| format!("byte {at} as {value:#04x}"));
        }
        changed[at] = stream[at];
    }
    for len in 0..stream.len() {
        held(&stream[..len], &|| format!("the first {len} bytes"));
    }
}
