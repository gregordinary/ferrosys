//! LZVN, decoded.
//!
//! The algorithm is small and fixed, the input is a filesystem's own bytes and therefore
//! untrusted, and every bound the decoder reads is one this crate's gates hold it to. The
//! decoder is derived from the one in Apple's reference implementation, the `lzfse` project
//! (copyright 2015-2016 Apple Inc., under the BSD-3-Clause license, whose notice the crate's
//! `THIRD-PARTY-NOTICES` carries).
//!
//! This module is pure — bytes in, bytes out, no I/O — and what it decodes is one *stream*.
//! How a filesystem cuts a file into streams, and where each begins, is that format's framing
//! and belongs to it.
//!
//! # The encoding
//!
//! A stream is a sequence of instructions, each producing a **literal** — bytes that follow the
//! instruction in the stream — a **match** — bytes repeated from what has already been
//! produced, named by a distance back and a length — or a literal followed by a match. The
//! first byte of an instruction says which, and how the rest of its fields are packed:
//!
//! | First byte | Instruction | Fields |
//! |---|---|---|
//! | `LLMMMDDD`, `DDD` not 6 or 7 | literal and match, short distance | `D` widened by the next byte to 11 bits |
//! | `LLMMM111` | literal and match, long distance | a 16-bit distance in the next two bytes |
//! | `LLMMM110` | literal and match, the previous distance | none |
//! | `101LLMMM` | literal and match, medium distance | two more bytes: two more length bits, a 14-bit distance |
//! | `1110LLLL` | literal of 1 to 15 bytes; `11100000` is 16 to 271, from the next byte | |
//! | `1111MMMM` | match of 1 to 15 bytes at the previous distance; `11110000` is 16 to 271 | |
//! | `00000110` | the end of the stream, eight bytes long | |
//! | `00001110`, `00010110` | nothing | |
//!
//! `LL` is a literal of 0 to 3 bytes and `MMM` a match of 3 to 10. Every other first byte is
//! undefined, as are these that the first three rows' patterns would otherwise take: `0x70` to
//! `0x7F`, `0xD0` to `0xDF`, and `0x1E`, `0x26`, `0x2E`, `0x36` and `0x3E`. A stream holding
//! an undefined first byte is refused.
//!
//! # What a match may point at
//!
//! Backwards into what has already been produced, and never before its start; a distance of
//! zero names nothing. A match may overlap the run it is producing — a distance of one repeats
//! one byte — so the copy is a byte at a time and the overlapping case is ordinary. Every match
//! is held to this, including the two that take their distance from the instruction before.

use super::{Algorithm, Error};

/// What a stream says it is wrong about.
fn malformed(fault: &'static str) -> Error {
    Error::Malformed {
        algorithm: Algorithm::Lzvn,
        fault,
    }
}

/// The bytes the end-of-stream instruction takes.
const END_LEN: usize = 8;

/// Undo one LZVN stream into `out`, returning how many bytes it produced.
///
/// The stream ends at its end marker; bytes after the marker are not read.
pub(super) fn decompress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    decode_from(input, out, 0).map(|(_, end)| end)
}

/// Undo one LZVN stream into `out` from byte `start`, the bytes before it being output a match
/// may reach back into as well, and say where the stream's end marker ends and where its
/// output does. An LZFSE stream holds LZVN blocks that reach back into the blocks before them.
#[cfg_attr(not(feature = "lzfse"), allow(dead_code))]
pub(super) fn decode_from(
    input: &[u8],
    out: &mut [u8],
    start: usize,
) -> Result<(usize, usize), Error> {
    let mut src = 0usize;
    let mut dst = start;
    // The distance the last match used, which two instructions take as their own.
    let mut distance = 0usize;
    loop {
        let op = *input
            .get(src)
            .ok_or_else(|| malformed("the stream ends without its end marker"))?;
        let byte = |at: usize| {
            input
                .get(src + at)
                .map(|b| usize::from(*b))
                .ok_or_else(|| malformed("an instruction runs past the end of the stream"))
        };
        // (header bytes, literal length, match length, distance for the match)
        let (header, literal, matched, at) = match op {
            0x06 => {
                if input.len() - src < END_LEN {
                    return Err(malformed("the end marker is cut short"));
                }
                return Ok((src + END_LEN, dst));
            }
            0x0E | 0x16 => (1, 0, 0, distance),
            0x1E | 0x26 | 0x2E | 0x36 | 0x3E | 0x70..=0x7F | 0xD0..=0xDF => {
                return Err(malformed("an instruction the encoding does not define"));
            }
            0xE0 => (2, byte(1)? + 16, 0, distance),
            0xE1..=0xEF => (1, usize::from(op & 0x0F), 0, distance),
            0xF0 => (2, 0, byte(1)? + 16, distance),
            0xF1..=0xFF => (1, 0, usize::from(op & 0x0F), distance),
            0xA0..=0xBF => {
                let word = byte(1)? | (byte(2)? << 8);
                let literal = usize::from((op >> 3) & 0x3);
                let matched = ((usize::from(op & 0x7) << 2) | (word & 0x3)) + 3;
                (3, literal, matched, word >> 2)
            }
            _ => {
                let literal = usize::from(op >> 6);
                let matched = usize::from((op >> 3) & 0x7) + 3;
                match op & 0x7 {
                    7 => (3, literal, matched, byte(1)? | (byte(2)? << 8)),
                    6 => (1, literal, matched, distance),
                    high => (2, literal, matched, (usize::from(high) << 8) | byte(1)?),
                }
            }
        };

        // The instruction, its literal, and the first byte of the next instruction must all be
        // in the stream: every stream ends in a marker, so one ending anywhere else was cut.
        let body = src + header;
        if input.len() <= body + literal {
            return Err(malformed("an instruction runs past the end of the stream"));
        }
        if out.len() - dst < literal + matched {
            return Err(Error::Overrun {
                algorithm: Algorithm::Lzvn,
                expected: out.len(),
            });
        }
        out[dst..dst + literal].copy_from_slice(&input[body..body + literal]);
        dst += literal;
        src = body + literal;

        if matched > 0 {
            if !super::copy_back(out, dst, at, matched) {
                return Err(malformed("a match reaches before the start of the output"));
            }
            dst += matched;
            distance = at;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The end-of-stream instruction.
    const END: [u8; 8] = [0x06, 0, 0, 0, 0, 0, 0, 0];

    fn decode(stream: &[u8], room: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; room];
        let n = decompress(stream, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    #[test]
    fn a_literal_alone_is_its_bytes() {
        let mut stream = vec![0xE5];
        stream.extend_from_slice(b"hello");
        stream.extend_from_slice(&END);
        assert_eq!(decode(&stream, 16).unwrap(), b"hello");
        // The long form: a length of 16 plus the next byte.
        let mut stream = vec![0xE0, 4];
        stream.extend_from_slice(&[b'x'; 20]);
        stream.extend_from_slice(&END);
        assert_eq!(decode(&stream, 32).unwrap(), vec![b'x'; 20]);
    }

    #[test]
    fn a_short_distance_match_repeats_and_may_overlap_itself() {
        // LL = 2, MMM = 3 (a match of six), DDD = 0 and the next byte 2: a literal "ab", then
        // six bytes from two back, each produced before the next is copied.
        let op = (2 << 6) | (3 << 3);
        let mut stream = vec![op, 2, b'a', b'b'];
        stream.extend_from_slice(&END);
        assert_eq!(decode(&stream, 16).unwrap(), b"abababab");
    }

    #[test]
    fn the_previous_distance_and_a_match_alone_take_the_last_distance() {
        // "xy", repeat at distance 2 for 3, then a bare match of 4 at the same distance, then a
        // previous-distance instruction with a literal of one and a match of 3.
        let first = 2 << 6; // LL = 2, MMM = 0 (three), DDD = 0
        let mut stream = vec![first, 2, b'x', b'y', 0xF4, (1 << 6) | 6, b'z'];
        stream.extend_from_slice(&END);
        // "xy", "xyx" from two back, "yxyx" from two back, the literal "z", and "xzx" from two
        // back.
        assert_eq!(decode(&stream, 32).unwrap(), b"xyxyxyxyxzxzx");
    }

    #[test]
    fn a_medium_and_a_long_distance_reach_back_as_far_as_they_say() {
        // 300 literal bytes, then a long-distance match of 3 at distance 300, then a medium
        // one of 3 at distance 4.
        let source: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let mut stream = vec![0xE0, (268 - 16) as u8];
        stream.extend_from_slice(&source[..268]);
        stream.extend_from_slice(&[0xE0, (32 - 16) as u8]);
        stream.extend_from_slice(&source[268..]);
        stream.extend_from_slice(&[0x07, 0x2C, 0x01]); // LL 0, MMM 0, distance 300
        stream.extend_from_slice(&[0xA0, 4 << 2, 0]); // medium: match 3 at distance 4
        stream.extend_from_slice(&END);
        let out = decode(&stream, 400).unwrap();
        assert_eq!(&out[..300], &source[..]);
        assert_eq!(&out[300..303], &source[..3]);
        assert_eq!(&out[303..306], &out[299..302]);
    }

    #[test]
    fn a_stream_of_every_instruction_changed_a_byte_at_a_time_refuses_or_fits() {
        // A short and a long literal, a small, a medium and a long distance, the previous
        // distance, and a bare match, then the end: each field of each form is a byte of it.
        let mut stream = vec![0xE5];
        stream.extend_from_slice(b"hello");
        stream.extend_from_slice(&[0xE0, 4]);
        stream.extend_from_slice(&[b'x'; 20]);
        stream.extend_from_slice(&[(2 << 6) | (3 << 3), 2, b'a', b'b']);
        stream.extend_from_slice(&[0xA0, 4 << 2, 0]);
        stream.extend_from_slice(&[0x07, 0x1C, 0x00]);
        stream.extend_from_slice(&[0xF4, (1 << 6) | 6, b'z', 0xF3]);
        stream.extend_from_slice(&END);
        let whole = decode(&stream, 128).expect("the stream decodes");
        crate::compress::sweep_changes_of(&stream, whole.len() + 16, decompress);
    }

    #[test]
    fn a_match_before_the_start_or_at_no_distance_is_refused() {
        let mut stream = vec![0x08 | 0x01, 5];
        stream.extend_from_slice(&END);
        assert!(matches!(decode(&stream, 16), Err(Error::Malformed { .. })));
        // A bare match with no distance yet established.
        let mut stream = vec![0xF3];
        stream.extend_from_slice(&END);
        assert!(matches!(decode(&stream, 16), Err(Error::Malformed { .. })));
    }

    #[test]
    fn a_stream_without_its_end_or_past_its_room_is_refused() {
        assert!(matches!(
            decode(&[0xE2, b'a', b'b'], 16),
            Err(Error::Malformed { .. })
        ));
        let mut stream = vec![0xE5];
        stream.extend_from_slice(b"hello");
        stream.extend_from_slice(&END);
        assert!(matches!(decode(&stream, 4), Err(Error::Overrun { .. })));
        assert!(matches!(
            decode(&[0x70, 0, 0], 16),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn a_stream_continuing_an_output_reaches_into_what_came_before_it() {
        // Four bytes already produced, then a stream of one match of four from four back,
        // ending eight bytes after its two-byte instruction.
        let mut out = *b"abcd\0\0\0\0";
        let mut stream = vec![0x08, 0x04];
        stream.extend_from_slice(&END);
        stream.extend_from_slice(b"trailing");
        assert_eq!(decode_from(&stream, &mut out, 4), Ok((10, 8)));
        assert_eq!(&out, b"abcdabcd");
        // From its own start, the same stream has nothing to reach back into.
        assert!(matches!(
            decode_from(&stream, &mut out, 0),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn nothing_between_instructions_is_skipped() {
        let mut stream = vec![0x0E, 0x16, 0xE1, b'q'];
        stream.extend_from_slice(&END);
        assert_eq!(decode(&stream, 4).unwrap(), b"q");
    }
}
