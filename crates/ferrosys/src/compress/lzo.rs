//! LZO1X, decoded.
//!
//! Written here rather than taken as a dependency, which is what [`crc32c`](crate::crc32c()) and
//! the directory hashes are and for the same reasons: the algorithm is small and fixed, the
//! input is a filesystem's own bytes and therefore untrusted, and every bound it reads is one
//! this crate's gates can hold it to.
//!
//! This module is pure — bytes in, bytes out, no I/O — and what it decodes is one *stream*.
//! How a filesystem cuts a run of bytes into streams, and where each begins, is that format's
//! framing and belongs to it.
//!
//! # The encoding
//!
//! A stream is a sequence of instructions, each copying bytes into the output from one of two
//! places:
//!
//! - a **literal run**, whose bytes follow the instruction in the stream; or
//! - a **match**, which repeats bytes already produced, named by how far back they begin and
//!   how many to take.
//!
//! The first byte of an instruction says which it is and, for a match, which of four encodings
//! carries the pair. Each trades reach against length: the widest reach spends four bytes and
//! keeps its length in three bits, and the narrowest spends two and reaches 2 KiB.
//!
//! Three of the four also carry, in their low two bits, the length of a literal run that
//! follows *with no instruction byte of its own*. That is what makes this a small state machine
//! rather than a loop over independent instructions, and the state is exactly what the previous
//! instruction left: `0` at the start, `4` after a literal run, and `1`–`3` after a match that
//! carried a short run. A first byte under 16 means a literal run in the first state, a
//! short-reach match in the middle three, and a match against the widest of the four reaches in
//! the last — the same bits reading three ways.
//!
//! A length that does not fit its instruction's field is extended by a run of zero bytes, each
//! worth 255, then one nonzero byte worth its own value. That run is the one place a malformed
//! stream could ask for unbounded work, and what bounds it is the input ending.
//!
//! A stream ends with a marker rather than at the end of its input: the widest match encoding
//! spelling a distance of zero, which no real match can, at a length of exactly three. The
//! bytes are `11 00 00`, and a stream that stops without them is a stream that was cut short.
//!
//! # What a match may point at
//!
//! Backwards into what has already been produced, and never before the start of it. A match may
//! also overlap the run it is producing — a distance of one and a length of ten is how this
//! format spells ten copies of one byte — so the copy is a byte at a time and the overlapping
//! case is ordinary rather than an edge.
//!
//! # What this decodes, and what it does not
//!
//! LZO1X as it is written by `lzo1x_1_compress`, which is what the filesystems reading through
//! this module store. The run-length extension some other users of this algorithm negotiate
//! through a two-byte header is not part of that, and a stream carrying one is refused as the
//! ordinary instructions it would otherwise be read as.

use super::{Algorithm, Error};

/// The reach of the two-byte match encodings, which the widest-of-the-short forms measures its
/// distance from rather than from the output's end.
const M2_MAX_OFFSET: usize = 0x0800;

/// What the four-byte encoding subtracts from every distance it names, so that a distance of
/// zero is free to mean the end of the stream.
const M4_DISTANCE_BIAS: usize = 0x4000;

/// The fewest bytes a stream can be: the end marker alone, which is what an empty run
/// compresses to.
const MIN_STREAM: usize = 3;

/// The length the end marker carries. A marker with any other is a stream that ends in an
/// instruction resembling one rather than in one.
const END_MARKER_LENGTH: usize = 3;

/// Undo one LZO1X stream into `out`, returning how many bytes it produced.
///
/// `out` bounds the work: an instruction that would write past it is [`Error::Overrun`], so a
/// stream can never ask for more room than the record that framed it declared. Producing fewer
/// bytes than `out` holds is not an error here — a caller that asked for a whole run compares
/// the two and says so itself.
///
/// # Errors
///
/// [`Error::Overrun`] where the stream expands past `out`, and [`Error::Malformed`] where an
/// instruction reads past the end of the input, a match names bytes before the start of the
/// output, the stream ends without its marker, or bytes follow the marker.
pub(crate) fn decompress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    Decoder {
        input,
        read: 0,
        out,
        written: 0,
    }
    .run()
}

/// A refusal about the stream itself rather than about the room it was given.
const fn malformed(fault: &'static str) -> Error {
    Error::Malformed {
        algorithm: Algorithm::Lzo,
        fault,
    }
}

/// One stream being decoded: how far reading has reached in it, and how far writing has reached
/// in the output.
struct Decoder<'a> {
    input: &'a [u8],
    read: usize,
    out: &'a mut [u8],
    written: usize,
}

/// What state the previous instruction left, which decides how the next one reads.
///
/// The values are the format's own — a literal run leaves `4` and a match leaves the length of
/// the short run it carried — so they are kept as the numbers rather than renamed.
const STATE_AFTER_LITERAL_RUN: usize = 4;

impl Decoder<'_> {
    /// Every instruction in the stream, until its end marker.
    fn run(mut self) -> Result<usize, Error> {
        if self.input.len() < MIN_STREAM {
            return Err(malformed("a stream is at least an end marker"));
        }
        let mut state = 0usize;

        // The opening instruction has a form no other has: any first byte over 17 is itself
        // the length of a literal run, less 17, with no further instruction. It is what an
        // encoder emits when a run's first bytes match nothing yet, which is every run that
        // begins a file.
        if self.input[0] > 17 {
            let count = self.byte()? as usize - 17;
            if count < STATE_AFTER_LITERAL_RUN {
                // The short form, whose run is the one a match carries and whose next
                // instruction is therefore read as a match rather than as a run.
                state = count;
                self.literals(count)?;
            } else {
                self.literals(count)?;
                state = STATE_AFTER_LITERAL_RUN;
            }
        }

        loop {
            let instruction = self.byte()? as usize;
            let (distance, length, next) = if instruction < 16 {
                match state {
                    // A literal run, whose length is the instruction plus three and whose
                    // field is extended where the instruction is zero.
                    0 => {
                        let count = if instruction == 0 {
                            15 + self.extension()?
                        } else {
                            instruction
                        } + 3;
                        self.literals(count)?;
                        state = STATE_AFTER_LITERAL_RUN;
                        continue;
                    }
                    // The narrowest match: two bytes from within the last kibibyte, and the
                    // short literal run its low bits carry.
                    STATE_AFTER_LITERAL_RUN => {
                        let next = instruction & 3;
                        let far = self.byte()? as usize;
                        let distance = 1 + M2_MAX_OFFSET + (instruction >> 2) + (far << 2);
                        (distance, 3, next)
                    }
                    _ => {
                        let next = instruction & 3;
                        let far = self.byte()? as usize;
                        let distance = 1 + (instruction >> 2) + (far << 2);
                        (distance, 2, next)
                    }
                }
            } else if instruction >= 64 {
                // Two bytes: a length of three to eight in the top three bits, and a reach of
                // 2 KiB across the rest of the instruction and the byte after it.
                let far = self.byte()? as usize;
                (
                    1 + ((instruction >> 2) & 7) + (far << 3),
                    (instruction >> 5) + 1,
                    instruction & 3,
                )
            } else if instruction >= 32 {
                // Three bytes: a length of three upwards in the low five bits, extended where
                // they are all zero, and a reach of 16 KiB in the pair that follows.
                let mut length = (instruction & 31) + 2;
                if length == 2 {
                    length += 31 + self.extension()?;
                }
                let pair = self.pair()?;
                (1 + (pair >> 2), length, pair & 3)
            } else {
                // Four bytes, and the only encoding that reaches past 16 KiB: one bit of the
                // instruction is the distance's highest, its low three are the length, and the
                // pair carries the rest of a distance every one of these is biased by.
                let mut length = (instruction & 7) + 2;
                if length == 2 {
                    length += 7 + self.extension()?;
                }
                let pair = self.pair()?;
                let distance = ((instruction & 8) << 11) + (pair >> 2);
                if distance == 0 {
                    // The end marker, which is the one distance the bias puts out of a real
                    // match's reach. Its length is fixed, so an instruction that lands here
                    // carrying any other is a stream that ends in something else.
                    if length != END_MARKER_LENGTH {
                        return Err(malformed("the end marker carries a length that is not its"));
                    }
                    if self.read != self.input.len() {
                        return Err(malformed("bytes follow the end of the stream"));
                    }
                    return Ok(self.written);
                }
                (distance + M4_DISTANCE_BIAS, length, pair & 3)
            };
            self.copy_match(distance, length)?;
            // Whichever encoding it was, its low two bits are a literal run that follows with
            // no instruction of its own, and the count is also the state it leaves.
            state = next;
            self.literals(next)?;
        }
    }

    /// One byte of the stream.
    fn byte(&mut self) -> Result<u8, Error> {
        let byte = *self
            .input
            .get(self.read)
            .ok_or(malformed("an instruction reads past the end of the stream"))?;
        self.read += 1;
        Ok(byte)
    }

    /// The little-endian pair carrying a distance in the two wider encodings.
    fn pair(&mut self) -> Result<usize, Error> {
        let low = self.byte()? as usize;
        let high = self.byte()? as usize;
        Ok(low | (high << 8))
    }

    /// A length's extension past the field that could not hold it: each zero byte is worth 255
    /// and the first nonzero one, which ends the run, is worth itself.
    ///
    /// Two things bound it. The input running out ends the run, so a stream of zeros is a
    /// refusal rather than a loop; and the addition is checked, so one long enough to wrap the
    /// total into a small number is refused rather than becoming one.
    fn extension(&mut self) -> Result<usize, Error> {
        let mut total = 0usize;
        loop {
            let byte = self.byte()?;
            let step = if byte == 0 { 255 } else { byte as usize };
            total = total
                .checked_add(step)
                .ok_or(malformed("a length extension overflows"))?;
            if byte != 0 {
                return Ok(total);
            }
        }
    }

    /// Copy `count` bytes from the stream straight into the output.
    fn literals(&mut self, count: usize) -> Result<(), Error> {
        let from = self
            .read
            .checked_add(count)
            .and_then(|end| self.input.get(self.read..end))
            .ok_or(malformed("a literal run reads past the end of the stream"))?;
        // The refusal is built before the borrow, because it names the room there was and the
        // borrow is what takes it.
        let overrun = Error::Overrun {
            algorithm: Algorithm::Lzo,
            expected: self.out.len(),
        };
        let into = self
            .written
            .checked_add(count)
            .and_then(|end| self.out.get_mut(self.written..end))
            .ok_or(overrun)?;
        into.copy_from_slice(from);
        self.read += count;
        self.written += count;
        Ok(())
    }

    /// Repeat `count` bytes of the output beginning `distance` back from where writing has
    /// reached.
    ///
    /// A byte at a time, because a match may reach into the run it is producing: a distance of
    /// one and a length of ten is how this format spells ten copies of one byte, and a block
    /// move would read the bytes that are not there yet.
    fn copy_match(&mut self, distance: usize, count: usize) -> Result<(), Error> {
        if distance > self.written {
            return Err(malformed(
                "a match names bytes before the start of the output",
            ));
        }
        if count > self.out.len() - self.written {
            return Err(Error::Overrun {
                algorithm: Algorithm::Lzo,
                expected: self.out.len(),
            });
        }
        for from in (self.written - distance..).take(count) {
            self.out[self.written] = self.out[from];
            self.written += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The end marker on its own, which is what an empty run compresses to.
    const END: &[u8] = &[0x11, 0x00, 0x00];

    /// Compress with an implementation this crate shares no code with.
    ///
    /// The whole point of the round trips below: a decoder held against streams its own encoder
    /// produced is a decoder checked against itself, and this algorithm has no specification
    /// apart from an implementation.
    fn foreign(data: &[u8]) -> Vec<u8> {
        lzokay::compress::compress(data).expect("a second implementation compresses it")
    }

    fn round_trip(data: &[u8]) {
        let stream = foreign(data);
        let mut out = vec![0u8; data.len()];
        let produced = decompress(&stream, &mut out)
            .unwrap_or_else(|e| panic!("{} bytes did not decode: {e}", data.len()));
        assert_eq!(produced, data.len(), "short by {}", data.len() - produced);
        assert_eq!(out, data);
    }

    #[test]
    fn an_empty_run_is_the_end_marker_and_nothing_else() {
        let mut out = [0u8; 8];
        assert_eq!(decompress(END, &mut out), Ok(0));
        // And a stream that stops before it is one that was cut short, rather than one that
        // decoded to what it had produced so far.
        assert!(matches!(
            decompress(&END[..2], &mut out),
            Err(Error::Malformed { .. })
        ));

        // The one input the two implementations disagree about, and the disagreement is
        // recorded rather than accommodated. The encoder used by the round trips below writes
        // an opening literal run of *zero* as the byte 17, which the direct form's own rule
        // excludes — it is every byte **over** 17 — so what it emits for no bytes at all is a
        // stream neither this decoder nor the one in the kernel that defines this format can
        // read. It is not a case any filesystem reaches: an empty run is not compressed.
        assert!(matches!(
            decompress(&[0x11, 0x11, 0x00, 0x00], &mut out),
            Err(Error::Malformed { .. })
        ));
        assert_eq!(foreign(b""), [0x11, 0x11, 0x00, 0x00]);
    }

    #[test]
    fn runs_a_second_implementation_produced_decode_to_what_went_in() {
        // The shapes that reach different encodings. Incompressible bytes are literal runs
        // throughout; one repeated byte is a match overlapping its own output; a long run of
        // a repeated block reaches the wider distances; and the lengths around each field's
        // width are where an off-by-one in an extension lives.
        round_trip(b"f");
        round_trip(b"ferrosys");
        round_trip(&b"ferrosys".repeat(4096));
        round_trip(&vec![0x5au8; 70_000]);

        // A block that repeats after a gap, at three gaps chosen to land on either side of
        // each encoding's reach: within 2 KiB, past it, and past 16 KiB. Which encoding the
        // second copy's match takes follows from how far back the first one is, so this is
        // what reaches the wider two at all — a repeated *short* block never does, however
        // long the run of it.
        for gap in [1000usize, 5000, 40_000] {
            let block = b"a-block-worth-matching-against-later";
            let filler: Vec<u8> = (0..gap).map(|at| (at * 181 + 3) as u8).collect();
            let mut data = Vec::new();
            data.extend_from_slice(block);
            data.extend_from_slice(&filler);
            data.extend_from_slice(block);
            round_trip(&data);
        }
        for len in [1usize, 2, 3, 4, 17, 18, 19, 33, 34, 255, 256, 257, 512] {
            // Every byte a function of its position, so nothing matches anything and the
            // stream is literal runs at each length around a field boundary.
            let data: Vec<u8> = (0..len).map(|at| (at * 7 + 13) as u8).collect();
            round_trip(&data);
            // And the same length as one repeated byte, which is all match.
            round_trip(&vec![0xa5u8; len]);
        }
    }

    #[test]
    fn a_run_of_every_length_up_to_a_kibibyte_survives_the_round_trip() {
        // Exhaustive rather than sampled over the range where the encodings change, which is
        // where a length field's boundary is. Two shapes per length: one that compresses to
        // matches and one that cannot compress at all.
        for len in 1..1024usize {
            round_trip(&vec![0xc3u8; len]);
            let data: Vec<u8> = (0..len).map(|at| (at * 31 + 7) as u8).collect();
            round_trip(&data);
        }
    }

    #[test]
    fn a_stream_that_expands_past_the_room_it_was_given_is_refused() {
        let data = b"ferrosys".repeat(64);
        let stream = foreign(&data);
        let mut out = vec![0u8; data.len() - 1];
        assert!(matches!(
            decompress(&stream, &mut out),
            Err(Error::Overrun { .. })
        ));
    }

    #[test]
    fn a_match_that_reaches_before_the_start_of_the_output_is_refused() {
        // A three-byte match at a distance of one, as the first instruction: there is nothing
        // behind the output to copy from, and a decoder that wrapped the subtraction would
        // read whatever the buffer held.
        //
        // `0x20 | 1` is the three-byte encoding at a length of three, and the pair that
        // follows names a distance of one.
        let stream = [0x21, 0x04, 0x00];
        let mut out = [0u8; 16];
        assert!(matches!(
            decompress(&stream, &mut out),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn a_length_extension_that_never_ends_is_bounded_by_the_input() {
        // A literal run whose length field is zero, extended by a run of zeros that reaches
        // the end of the stream. The decoder must stop when the input does rather than read
        // on, and it must not have written anything on the strength of the length.
        let mut stream = vec![0u8; 4096];
        stream[0] = 0;
        let mut out = [0u8; 64];
        assert!(matches!(
            decompress(&stream, &mut out),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_never_write_past_the_room_they_were_given() {
        // The property that matters most for a decoder over a filesystem's bytes, held by the
        // sweep every layer of this shares.
        crate::compress::sweep_arbitrary_bytes(1, decompress);
    }
}
