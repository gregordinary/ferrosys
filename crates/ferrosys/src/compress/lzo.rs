//! LZO1X, decoded.
//!
//! The algorithm is small and fixed, the input is a filesystem's own bytes and therefore
//! untrusted, and every bound the decoder reads is one this crate's gates hold it to, as for
//! [`crc32c`](crate::crc32c()) and the directory hashes.
//!
//! This module is pure — bytes in, bytes out, no I/O — and what it decodes is one *stream*.
//! How a filesystem cuts a run of bytes into streams, and where each begins, is that format's
//! framing and belongs to it.
//!
//! # Sources
//!
//! The format's one public description is the Linux kernel documentation's *LZO stream format
//! as understood by Linux's LZO decompressor* (docs.kernel.org, `staging/lzo`), which says of
//! itself that it describes what one decoder accepts, no specification being public. Every
//! instruction here is read by that page's table of byte sequences, and every length by its
//! variable-length rule. Where the page is silent the rule here is observed, and says so. Every
//! stream is also held to a second implementation, `lzokay` (MIT), used here only to compress.
//!
//! # The encoding
//!
//! A stream is a run of instructions. Each one either copies the bytes that follow it in the
//! stream (a **literal** run) or repeats bytes already produced, named by a distance back and a
//! length (a **copy**). A copy also names, in two bits of its own, up to three literals that
//! follow it with no instruction of their own.
//!
//! What an instruction is depends on the range its first byte falls in and, in the lowest range
//! only, on how many literals the instruction before it copied:
//!
//! | First byte | After | Instruction | Then |
//! |---|---|---|---|
//! | 0–15 | no literals | literal run, 4 bytes or more | the run |
//! | 0–15 | 1 to 3 literals | copy of 2 bytes, 1 to 1024 back | one byte |
//! | 0–15 | 4 literals or more | copy of 3 bytes, 2049 to 3072 back | one byte |
//! | 16–31 | anything | copy of 3 bytes or more, 16385 to 49151 back, or the end | a 16-bit word |
//! | 32–63 | anything | copy of 3 bytes or more, 1 to 16384 back | a 16-bit word |
//! | 64–127 | anything | copy of 3 or 4 bytes, 1 to 2048 back | one byte |
//! | 128–255 | anything | copy of 5 to 8 bytes, 1 to 2048 back | one byte |
//!
//! A 16-bit word is little-endian, and carries a distance in its upper fourteen bits and the
//! literals that follow in its lower two.
//!
//! The rows whose length is open-ended hold it in a field of the first byte. A field of zero
//! means the length did not fit: it is the field's largest value plus an extension, a run of
//! zero bytes each worth 255 ended by one nonzero byte worth itself. That run is the one place a
//! malformed stream could ask for unbounded work, and what bounds it is the input ending.
//!
//! A stream's first byte has a form of its own. From 18 up it is a literal run of that byte
//! less 17, and the instruction after it reads by how many that was, as after any other run.
//! Below 18 it is an ordinary instruction, read as after no literals.
//!
//! # How a stream ends
//!
//! At the 16–31 row's copy whose distance is exactly 16384, which no copy uses (the page). The
//! distance alone ends it: what else that instruction holds, its length field and the low two
//! bits of its word, changes nothing once the stream is over. Every encoder observed writes the
//! end as the three bytes `11 00 00` — every stream in a btrfs extent a Linux kernel wrote, and
//! every stream `lzokay` writes. A stream that stops before an end was cut short, and bytes
//! after its end are bytes its framing should not have given it, which is what refuses an end
//! read in the middle of a damaged stream.
//!
//! # What a copy may reach
//!
//! Backwards into what has already been produced, and never before the start of it. The table
//! allows a copy longer than its distance — five to eight bytes from one back — so a copy may
//! overlap the bytes it is producing, a distance of one repeating one byte. It runs a byte at a
//! time, and the overlapping case is ordinary rather than an edge.
//!
//! # Which version
//!
//! The page describes two: the original, and one that adds a run of zeros as an instruction and
//! announces itself with a first byte of 17 and a version byte. The filesystems reading through
//! this module store the original — no stream observed from one opens with 17 — and it is the
//! one decoded here. A stream announcing the other is refused: read as an ordinary instruction,
//! its header copies from an output that is still empty, or ends the stream with bytes still to
//! follow.

use super::{Algorithm, Error};

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
/// instruction reads past the end of the input, a copy names bytes before the start of the
/// output, the stream stops before its end, or bytes follow the end.
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

/// A length too long to count, which only a stream of extension bytes as long as memory could
/// spell.
const LENGTH_OVERFLOWS: Error = malformed("a length extension overflows");

/// One stream being decoded: how far reading has reached in it, and how far writing has reached
/// in the output.
struct Decoder<'a> {
    input: &'a [u8],
    read: usize,
    out: &'a mut [u8],
    written: usize,
}

/// How many literals an instruction copied, which is all the next one needs to know of it: the
/// lowest range of first bytes reads three ways by it, and every other range ignores it.
#[derive(Clone, Copy)]
enum Copied {
    /// None: the start of a stream, or a copy that carried no literals.
    None,
    /// One to three: the literals a copy carried, or a short opening run.
    Few,
    /// Four or more: a literal run.
    Many,
}

impl Copied {
    /// What copying `count` literals leaves.
    const fn after(count: usize) -> Self {
        match count {
            0 => Copied::None,
            1..=3 => Copied::Few,
            _ => Copied::Many,
        }
    }
}

/// One instruction, read and not yet carried out.
enum Instruction {
    /// Copy this many bytes from the stream.
    Literals(usize),
    /// Repeat `length` bytes from `distance` back, then copy `literals` bytes from the stream.
    Copy {
        distance: usize,
        length: usize,
        literals: usize,
    },
    /// The stream is over.
    End,
}

impl Decoder<'_> {
    /// Every instruction in the stream, until its end.
    fn run(mut self) -> Result<usize, Error> {
        let mut copied = self.opening()?;
        loop {
            copied = match self.instruction(copied)? {
                Instruction::Literals(count) => {
                    self.literals(count)?;
                    Copied::after(count)
                }
                Instruction::Copy {
                    distance,
                    length,
                    literals,
                } => {
                    self.repeat(distance, length)?;
                    self.literals(literals)?;
                    Copied::after(literals)
                }
                Instruction::End if self.read == self.input.len() => return Ok(self.written),
                Instruction::End => return Err(malformed("bytes follow the end of the stream")),
            };
        }
    }

    /// The first byte's own form: from 18 up, a literal run of that byte less 17 (the page's
    /// first-byte encoding). A lower byte is left where it is, to be read as an ordinary
    /// instruction after no literals.
    fn opening(&mut self) -> Result<Copied, Error> {
        match self.input.first() {
            Some(&first) if first >= 18 => {
                self.read += 1;
                let count = usize::from(first - 17);
                self.literals(count)?;
                Ok(Copied::after(count))
            }
            _ => Ok(Copied::None),
        }
    }

    /// One instruction, read by the row of the page's table its first byte falls in. Each
    /// row's bit layout is written above it, most significant bit first, in the page's letters:
    /// `L` a length field, `D` and `H` the low and high parts of a distance, `S` the literals
    /// that follow a copy.
    fn instruction(&mut self, copied: Copied) -> Result<Instruction, Error> {
        let first = self.byte()?;
        let bits = usize::from(first);
        Ok(match first {
            // 0000LLLL after no literals: a run of 3 + L, with L extended where it is zero.
            0..=15 if matches!(copied, Copied::None) => {
                Instruction::Literals(self.length(bits, 4, 3)?)
            }
            // 0000DDSS, then H: two bytes from (H << 2) + D + 1 back after one to three
            // literals, and three bytes from (H << 2) + D + 2049 back after four or more.
            0..=15 => {
                let high = usize::from(self.byte()?);
                let near = (high << 2) + ((bits >> 2) & 3);
                let (distance, length) = if matches!(copied, Copied::Few) {
                    (near + 1, 2)
                } else {
                    (near + 2049, 3)
                };
                Instruction::Copy {
                    distance,
                    length,
                    literals: bits & 3,
                }
            }
            // 0001HLLL, then a word: 2 + L bytes from 16384 + (H << 14) + D back. A distance of
            // exactly 16384 is the end of the stream.
            16..=31 => {
                let length = self.length(bits, 3, 2)?;
                let word = self.word()?;
                let distance = 16384 + (((bits >> 3) & 1) << 14) + (word >> 2);
                if distance == 16384 {
                    return Ok(Instruction::End);
                }
                Instruction::Copy {
                    distance,
                    length,
                    literals: word & 3,
                }
            }
            // 001LLLLL, then a word: 2 + L bytes from D + 1 back.
            32..=63 => {
                let length = self.length(bits, 5, 2)?;
                let word = self.word()?;
                Instruction::Copy {
                    distance: (word >> 2) + 1,
                    length,
                    literals: word & 3,
                }
            }
            // 01LDDDSS, then H: 3 + L bytes from (H << 3) + D + 1 back.
            64..=127 => Instruction::Copy {
                distance: self.far(bits)?,
                length: 3 + ((bits >> 5) & 1),
                literals: bits & 3,
            },
            // 1LLDDDSS, then H: 5 + L bytes from (H << 3) + D + 1 back.
            128..=255 => Instruction::Copy {
                distance: self.far(bits)?,
                length: 5 + ((bits >> 5) & 3),
                literals: bits & 3,
            },
        })
    }

    /// The distance the two widest rows share: three bits `D` of the first byte, then a byte
    /// `H`, making (H << 3) + D + 1.
    fn far(&mut self, bits: usize) -> Result<usize, Error> {
        let high = usize::from(self.byte()?);
        Ok((high << 3) + ((bits >> 2) & 7) + 1)
    }

    /// A length by the page's variable-length rule: the low `width` bits of the first byte
    /// where they are nonzero, and their largest value plus an extension where they are zero;
    /// then the row's `base` on top.
    fn length(&mut self, bits: usize, width: u32, base: usize) -> Result<usize, Error> {
        let largest = (1usize << width) - 1;
        let field = match bits & largest {
            0 => largest
                .checked_add(self.extension()?)
                .ok_or(LENGTH_OVERFLOWS)?,
            field => field,
        };
        field.checked_add(base).ok_or(LENGTH_OVERFLOWS)
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

    /// The little-endian 16-bit word two of the copy rows carry.
    fn word(&mut self) -> Result<usize, Error> {
        let low = self.byte()?;
        let high = self.byte()?;
        Ok(usize::from(u16::from_le_bytes([low, high])))
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
            total = total.checked_add(step).ok_or(LENGTH_OVERFLOWS)?;
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
    /// A byte at a time, because a copy may reach into the run it is producing: a distance of
    /// one and a length of ten is ten copies of one byte, and a block move would read the bytes
    /// that are not there yet.
    fn repeat(&mut self, distance: usize, count: usize) -> Result<(), Error> {
        if distance == 0 || distance > self.written {
            return Err(malformed(
                "a copy names bytes before the start of the output",
            ));
        }
        if count > self.out.len() - self.written {
            return Err(Error::Overrun {
                algorithm: Algorithm::Lzo,
                expected: self.out.len(),
            });
        }
        super::copy_back(self.out, self.written, distance, count);
        self.written += count;
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
    /// produced is a decoder checked against itself, and the format's one description says of
    /// itself that it is not a specification.
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
        // an opening literal run of *zero* as the byte 17, which the opening form excludes —
        // it starts at 18 — and which in a stream under five bytes the page gives no version
        // header either. Read as an ordinary instruction it is a copy from an output that is
        // still empty. It is not a case any filesystem reaches: an empty run is not compressed.
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
    fn a_copy_that_reaches_before_the_start_of_the_output_is_refused() {
        // A three-byte copy at a distance of two, as the first instruction: there is nothing
        // behind the output to copy from, and a decoder that wrapped the subtraction would
        // read whatever the buffer held.
        //
        // `0x21` is the 32–63 row with a length field of one, so three bytes, and the word
        // `04 00` names a distance of two: D + 1, with D the word's upper fourteen bits.
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

    /// A stream that opens with four literals, `abcd`, and leaves them to copy from.
    const ABCD: [u8; 5] = [17 + 4, b'a', b'b', b'c', b'd'];

    /// Decode `stream` into room for `room` bytes, wanting it to succeed.
    fn decoded(stream: &[u8], room: usize) -> Vec<u8> {
        let mut out = vec![0u8; room];
        let produced = decompress(stream, &mut out).expect("the stream decodes");
        out.truncate(produced);
        out
    }

    /// A literal run of exactly `count` bytes after no literals: the 0–15 row with a zero field,
    /// extended. `count` must be past what the field holds alone.
    fn long_run(count: usize) -> Vec<u8> {
        let mut extension = count - 3 - 15;
        let mut stream = vec![0x00];
        while extension > 255 {
            stream.push(0);
            extension -= 255;
        }
        stream.push(extension as u8);
        stream.extend((0..count).map(|at| (at * 7 + 1) as u8));
        stream
    }

    #[test]
    fn every_row_of_the_table_reads_as_the_page_gives_it() {
        // Each stream is built by hand from the page's table, so these hold the decoder to the
        // description itself rather than to what one encoder happens to emit.
        let end = [0x11, 0x00, 0x00];

        // 1LLDDDSS: LL = 3, D = 0, so 5 + 3 = 8 bytes from one back.
        let stream = [&ABCD[..], &[0b1110_0000, 0], &end].concat();
        assert_eq!(decoded(&stream, 64), b"abcddddddddd");

        // 01LDDDSS with S = 2: L = 1, D = 3, so 4 bytes from four back, then two literals; and
        // those two make the next 0000DDSS a two-byte copy, here from one back.
        let stream = [&ABCD[..], &[0b0110_1110, 0, b'x', b'y', 0x00, 0], &end].concat();
        assert_eq!(decoded(&stream, 64), b"abcdabcdxyyy");

        // 001LLLLL: L = 1, so 3 bytes; the word names D = 3, so four back.
        let stream = [&ABCD[..], &[0x21, 3 << 2, 0], &end].concat();
        assert_eq!(decoded(&stream, 64), b"abcdabc");

        // 001LLLLL with L = 0: 2 + 31 + an extension of one, so 34 bytes from one back.
        let stream = [&ABCD[..], &[0x20, 1, 0, 0], &end].concat();
        let mut want = b"abcd".to_vec();
        want.extend([b'd'; 34]);
        assert_eq!(decoded(&stream, 64), want);

        // An opening byte of 18 is one literal, which makes the 0000DDSS after it the
        // two-byte copy: D = 0 and H = 0, one back.
        assert_eq!(decoded(&[18, b'a', 0x00, 0, 0x11, 0, 0], 8), b"aaa");

        // After a literal run 0000DDSS is the three-byte copy from (H << 2) + D + 2049 back:
        // with D = 1 and H = 0, 2050 back, which after a run of 2051 is its second byte.
        let run = long_run(2051);
        let stream = [&run[..], &[0b0000_0100, 0], &end].concat();
        let produced = decoded(&stream, 4096);
        assert_eq!(produced.len(), 2054);
        assert_eq!(produced[2051..], produced[1..4]);

        // 0001HLLL: H = 0, L = 1, D = 1: three bytes from 16385 back. And H = 1, with D = 1
        // again, reaches 32769 back. One byte more of run than the distance puts each copy at
        // the run's second byte.
        for (instruction, back) in [(0x11u8, 16_385usize), (0x19, 32_769)] {
            let run = long_run(back + 1);
            let stream = [&run[..], &[instruction, 1 << 2, 0], &end].concat();
            let produced = decoded(&stream, back + 4);
            assert_eq!(produced[back + 1..], produced[1..4], "{instruction:#04x}");
        }
    }

    #[test]
    fn the_stream_ends_at_the_distance_the_page_gives() {
        // The page ends a stream at the 16–31 row's distance of 16384 and gives the rest of the
        // instruction no say. `11 00 00` is what every encoder observed writes; the other
        // spellings of that distance end the stream too: literals in the word's low bits, a
        // longer length, an extended one.
        for ending in [
            &[0x11u8, 0x00, 0x00][..],
            &[0x11, 0x01, 0x00],
            &[0x11, 0x03, 0x00],
            &[0x12, 0x00, 0x00],
            &[0x17, 0x02, 0x00],
            &[0x10, 0x01, 0x00, 0x00],
        ] {
            let stream = [&ABCD[..], ending].concat();
            assert_eq!(decoded(&stream, 64), b"abcd", "{ending:02x?}");
        }

        let mut out = [0u8; 64];
        // H set is 16384 further, a copy and not an end, and here one from before the start.
        // An end followed by anything is refused, which is what catches an end read in the
        // middle of a stream.
        for stream in [
            [&ABCD[..], &[0x19, 0x00, 0x00]].concat(),
            [&ABCD[..], &[0x11, 0x00, 0x00, 0x00]].concat(),
            [&ABCD[..], &[0x11, 0x00, 0x00], &ABCD[..]].concat(),
        ] {
            assert!(
                matches!(decompress(&stream, &mut out), Err(Error::Malformed { .. })),
                "{stream:02x?}"
            );
        }
        // And the version header the page describes, which this decoder does not read: it is
        // at least five bytes, so it either ends the stream with bytes to follow or copies from
        // an output that is still empty.
        for header in [
            &[0x11u8, 0x01, 0x00, 0x00, 0x00][..],
            &[0x11, 0x01, 0x04, 0x11, 0, 0],
        ] {
            assert!(matches!(
                decompress(header, &mut out),
                Err(Error::Malformed { .. })
            ));
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_never_write_past_the_room_they_were_given() {
        // The property that matters most for a decoder over a filesystem's bytes, held by the
        // sweep every layer of this shares.
        crate::compress::sweep_arbitrary_bytes(1, decompress);
    }
}
