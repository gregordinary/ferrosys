//! LZBITMAP, decoded.
//!
//! The input is a filesystem's own bytes and therefore untrusted, and every bound the decoder
//! reads is one this crate's gates hold it to. The layout is the one libzbitmap decodes
//! (copyright 2022 Corellium LLC, under the MIT license, whose notice the crate's
//! `THIRD-PARTY-NOTICES` carries in attribution), in this module's own structure; every rule
//! beyond that layout is observed, from what libcompression's encoder writes and what its
//! decoder accepts and produces on macOS 15, 26 and 27.
//!
//! This module is pure — bytes in, bytes out, no I/O — and what it decodes is one *stream*.
//!
//! # The encoding
//!
//! A stream is the bytes `ZBM`, a fourth byte, and then blocks. Each block opens with two
//! 24-bit little-endian numbers: its length, these six bytes included, and the length of what
//! it decodes to, at most 32 KiB. A block that decodes to nothing is six bytes long and ends
//! the stream; bytes after it are not read. A block six bytes longer than what it decodes to
//! holds those bytes as they are. A shorter block is compressed, and a longer one is refused.
//!
//! The fourth byte says which blocks the stream holds. Under 8 or 9 it holds either kind, and
//! the two decode alike. Under 12 or 13 it holds only blocks stored as they are. Apple's
//! encoder writes 9.
//!
//! A compressed block carries three more 24-bit numbers, each an offset from the block's first
//! byte, which cut the rest of it into areas:
//!
//! | From | To | Holds |
//! |---|---|---|
//! | byte 15 | the first offset | literals |
//! | the first offset | the second | distances, each one or two bytes |
//! | the second offset | the table | masks, a byte each |
//! | the third offset | the block's end | selectors, four bits each, a byte's low half first |
//! | 17 bytes before the block's end | the block's end | a table of twelve ten-bit entries |
//!
//! The block is produced eight bytes at a time, each eight by one *step*. A step's selector
//! names a mask and how many distance bytes the step reads. Selectors 3 to 14 are the table's
//! entries, each an eight-bit mask and then a two-bit byte count, packed from the table's
//! lowest bit up. Selectors 0, 1 and 2 take the next byte of the masks, and read that many
//! distance bytes. Bit `i` of the mask, lowest first, is byte `i` of the step. Set, it is the
//! next literal; clear, it is the byte the *distance* back in the output, the blocks before
//! included. A step that reads distance bytes sets the distance to them, little-endian; one
//! that reads none keeps it. Every compressed block starts at a distance of 8, and its last
//! step stops at the block's length.
//!
//! A selector followed by a selector of 15 is repeated. The count is 4, plus each selector after
//! the 15 up to and including the first that is not 15. Where eight or fewer bytes of the block
//! remain, the selector after a step's own is not read as a count. Repetitions past the block's
//! end read nothing and produce nothing, and Apple's encoder writes counts up to seven past it.
//!
//! # What a stream is held to
//!
//! Each of these is a rule libcompression's decoder on macOS 26 and 27 was observed to hold a
//! stream to, by streams the probes changed one field at a time, and this decoder holds a stream
//! to it as well:
//!
//! - The literals start at byte 15, the distances where the literals end, and the masks where
//!   the distances end. The selectors start no earlier than the masks and before the table.
//! - The selectors take at most 2,048 bytes before the table, unused ones included: one for
//!   each step of a block of 32 KiB.
//! - The literals and the distances are used to their last byte.
//! - A mask is read from the masks or the selectors' bytes, never the table's. A selector is
//!   read from the selectors or the table's bytes.
//! - Selector 15 names no step. A table entry that would read three distance bytes is refused,
//!   whether a step names it or not.
//!
//! It refuses one more kind of stream, which that decoder answers with bytes from outside the
//! stream. A copy reaches back at least 8 bytes, and no further than the output's first byte.
//! A shorter copy reads bytes its own step produces, and libcompression leaves there what its
//! output buffer held before. It does the same for a distance of 0. Past the output's start, it
//! refuses some copies and gives others the output's first byte. Apple's encoder writes none
//! of these.
//!
//! macOS 15's decoder differs from that one only on streams Apple's encoder does not write. It
//! accepts most of what the rules above refuse, and refuses a few the later one reads.

use super::{Algorithm, Error};
use crate::bytes::get_u24;

/// What a stream says it is wrong about.
fn malformed(fault: &'static str) -> Error {
    Error::Malformed {
        algorithm: Algorithm::Lzbitmap,
        fault,
    }
}

/// The three bytes every stream opens with, before the fourth that says which blocks it holds.
const SIGNATURE: &[u8; 3] = b"ZBM";

/// The bytes a stream's signature takes.
const SIGNATURE_LEN: usize = 4;

/// The most bytes a block's selectors take before its table: one selector for each step of a
/// block of 32 KiB.
const MAX_SELECTOR_BYTES: usize = MAX_DECODED / STEP / 2;

/// The bytes every block's header takes: its length and what it decodes to.
const BLOCK_HEADER: usize = 6;

/// The bytes a compressed block's header takes: the block header and three offsets.
const COMPRESSED_HEADER: usize = 15;

/// The bytes the table at a compressed block's end takes.
const TABLE: usize = 17;

/// The table's entries, which are selectors 3 to 14.
const TABLE_ENTRIES: usize = 12;

/// The selector naming the table's first entry; those below it take a mask from the masks.
const FIRST_TABLE_SELECTOR: u8 = 3;

/// The selector that, after a step's own, says the step repeats.
const REPEAT: u8 = 15;

/// The fewest times a counted step runs.
const REPEAT_BASE: usize = 4;

/// The most one block decodes to.
const MAX_DECODED: usize = 32 * 1024;

/// The bytes one step produces, and so the shortest distance a copy takes: a shorter one reads
/// bytes of its own step.
const STEP: usize = 8;

/// Undo one LZBITMAP stream into `out`, returning how many bytes it produced.
///
/// The stream ends at its end block; bytes after the end block are not read.
pub(super) fn decompress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if input.len() < SIGNATURE_LEN || &input[..SIGNATURE.len()] != SIGNATURE {
        return Err(malformed("the stream does not open with its signature"));
    }
    let raw_only = match input[SIGNATURE.len()] {
        0x08 | 0x09 => false,
        0x0C | 0x0D => true,
        _ => {
            return Err(malformed(
                "the stream's signature ends in a byte it does not take",
            ));
        }
    };
    let mut at = SIGNATURE_LEN;
    let mut produced = 0usize;
    loop {
        let header = input
            .get(at..)
            .and_then(|rest| rest.get(..BLOCK_HEADER))
            .ok_or_else(|| malformed("the stream ends without its end block"))?;
        let length = get_u24(header, 0) as usize;
        let decoded = get_u24(header, 3) as usize;
        let block = input
            .get(at..)
            .and_then(|rest| rest.get(..length))
            .ok_or_else(|| malformed("a block runs past the end of the stream"))?;
        if decoded > MAX_DECODED {
            return Err(malformed("a block decodes to more than 32 KiB"));
        }
        if length > decoded + BLOCK_HEADER {
            return Err(malformed(
                "a block is longer than the bytes it decodes to stored as they are",
            ));
        }
        if out.len() - produced < decoded {
            return Err(Error::Overrun {
                algorithm: Algorithm::Lzbitmap,
                expected: out.len(),
            });
        }
        let end = produced + decoded;
        if length == decoded + BLOCK_HEADER {
            out[produced..end].copy_from_slice(&block[BLOCK_HEADER..]);
        } else if raw_only {
            return Err(malformed(
                "a compressed block in a stream whose signature admits none",
            ));
        } else {
            compressed(block, &mut out[..end], produced)?;
        }
        if decoded == 0 {
            return Ok(produced);
        }
        produced = end;
        at += length;
    }
}

/// Undo the compressed block `block` into `out` from byte `start` to its end, the bytes
/// before `start` being the output of the blocks before it.
fn compressed(block: &[u8], out: &mut [u8], start: usize) -> Result<(), Error> {
    if block.len() < COMPRESSED_HEADER + TABLE {
        return Err(malformed(
            "a compressed block is shorter than its header and table",
        ));
    }
    let offset = |at| get_u24(block, at) as usize;
    let (literals_end, distances_end, selectors_at) = (offset(6), offset(9), offset(12));
    let mut literals = block
        .get(COMPRESSED_HEADER..literals_end)
        .ok_or_else(|| malformed("a block's literals are not a run of the block"))?;
    let mut distances = block
        .get(literals_end..distances_end)
        .ok_or_else(|| malformed("a block's distances are not a run of the block"))?;
    let table_at = block.len() - TABLE;
    if !(distances_end..table_at).contains(&selectors_at) {
        return Err(malformed(
            "a block's selectors do not start between its masks and its table",
        ));
    }
    if table_at - selectors_at > MAX_SELECTOR_BYTES {
        return Err(malformed(
            "a block's selectors take more bytes than its steps can use",
        ));
    }
    // Masks run up to the table, through the selectors' bytes; the selectors run to the
    // block's end, through the table's.
    let mut masks = &block[distances_end..table_at];
    let mut selectors = Nibbles {
        bytes: &block[selectors_at..],
        at: 0,
    };
    let table = table(&block[table_at..])?;

    let end = out.len();
    let mut at = start;
    let mut distance = STEP;
    while at < end {
        let selector = selectors.next()?;
        let repeats = if end - at <= STEP {
            1
        } else {
            selectors.count()?
        };
        for _ in 0..repeats {
            if at == end {
                break;
            }
            let (mask, width) = match selector {
                0..FIRST_TABLE_SELECTOR => {
                    let (&mask, rest) = masks
                        .split_first()
                        .ok_or_else(|| malformed("a step's mask lies in the block's table"))?;
                    masks = rest;
                    (mask, usize::from(selector))
                }
                REPEAT => return Err(malformed("a selector of 15 names no step")),
                _ => table[usize::from(selector - FIRST_TABLE_SELECTOR)],
            };
            if width > 0 {
                let (bytes, rest) = distances.split_at_checked(width).ok_or_else(|| {
                    malformed("a step's distance lies past the block's distances")
                })?;
                distances = rest;
                distance = bytes
                    .iter()
                    .rev()
                    .fold(0, |sum, &b| (sum << 8) | usize::from(b));
            }
            let n = (end - at).min(STEP);
            let copies = !mask & (0xFFu8 >> (STEP - n));
            if copies != 0 && (distance < STEP || distance > at) {
                return Err(malformed(
                    "a copy reaches into its own step or before the output's start",
                ));
            }
            for i in 0..n {
                out[at] = if mask >> i & 1 == 1 {
                    let (&byte, rest) = literals.split_first().ok_or_else(|| {
                        malformed("a step's literal lies past the block's literals")
                    })?;
                    literals = rest;
                    byte
                } else {
                    out[at - distance]
                };
                at += 1;
            }
        }
    }
    if !literals.is_empty() {
        return Err(malformed("a block's literals are not all used"));
    }
    if !distances.is_empty() {
        return Err(malformed("a block's distances are not all used"));
    }
    Ok(())
}

/// The table at a compressed block's end: each entry's mask and its count of distance bytes.
fn table(bytes: &[u8]) -> Result<[(u8, usize); TABLE_ENTRIES], Error> {
    let mut word = [0u8; 16];
    word[..15].copy_from_slice(&bytes[..15]);
    let bits = u128::from_le_bytes(word);
    let mut table = [(0u8, 0usize); TABLE_ENTRIES];
    for (i, entry) in table.iter_mut().enumerate() {
        let field = (bits >> (10 * i)) as u16 & 0x3FF;
        let width = usize::from(field >> 8);
        if width > 2 {
            return Err(malformed("a table entry reads three distance bytes"));
        }
        *entry = (field as u8, width);
    }
    Ok(table)
}

/// The selectors: four bits each, a byte's low half first.
struct Nibbles<'a> {
    bytes: &'a [u8],
    /// The next selector's index, two to a byte.
    at: usize,
}

impl Nibbles<'_> {
    fn peek(&self) -> Result<u8, Error> {
        let byte = self
            .bytes
            .get(self.at / 2)
            .ok_or_else(|| malformed("a block's selectors run past its end"))?;
        Ok(if self.at.is_multiple_of(2) {
            byte & 0x0F
        } else {
            byte >> 4
        })
    }

    fn next(&mut self) -> Result<u8, Error> {
        let selector = self.peek()?;
        self.at += 1;
        Ok(selector)
    }

    /// How many times the step whose selector was just read runs: once, or as many as the
    /// count after a selector of 15 says.
    fn count(&mut self) -> Result<usize, Error> {
        if self.peek()? != REPEAT {
            return Ok(1);
        }
        self.at += 1;
        let mut total = REPEAT_BASE;
        loop {
            let more = self.next()?;
            total += usize::from(more);
            if more != REPEAT {
                return Ok(total);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const END: [u8; 6] = [6, 0, 0, 0, 0, 0];
    const LIT8: (u8, u8) = (0xFF, 0);
    const COPY8: (u8, u8) = (0x00, 0);

    fn u24(n: usize) -> [u8; 3] {
        [n as u8, (n >> 8) as u8, (n >> 16) as u8]
    }

    /// Selectors packed two to a byte, the low half first.
    fn nibbles(selectors: &[u8]) -> Vec<u8> {
        selectors
            .chunks(2)
            .map(|pair| pair[0] | pair.get(1).map_or(0, |hi| hi << 4))
            .collect()
    }

    /// A table of `entries`, each a mask and a count of distance bytes, the rest zero.
    fn table_of(entries: &[(u8, u8)]) -> Vec<u8> {
        let mut bits = 0u128;
        for (i, &(mask, width)) in entries.iter().enumerate() {
            bits |= u128::from(u16::from(mask) | u16::from(width) << 8) << (10 * i);
        }
        let mut out = bits.to_le_bytes()[..15].to_vec();
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// A compressed block: its areas in order, then `pad`, then its table. `offsets`, where
    /// given, replaces the three offsets the areas' lengths make.
    #[derive(Default)]
    struct Block<'a> {
        decoded: usize,
        literals: &'a [u8],
        distances: &'a [u8],
        masks: &'a [u8],
        selectors: &'a [u8],
        pad: &'a [u8],
        table: &'a [(u8, u8)],
        offsets: Option<[usize; 3]>,
    }

    impl Block<'_> {
        fn bytes(&self) -> Vec<u8> {
            let o1 = COMPRESSED_HEADER + self.literals.len();
            let o2 = o1 + self.distances.len();
            let o3 = o2 + self.masks.len();
            let [o1, o2, o3] = self.offsets.unwrap_or([o1, o2, o3]);
            let mut body = [self.literals, self.distances, self.masks].concat();
            body.extend_from_slice(&nibbles(self.selectors));
            body.extend_from_slice(self.pad);
            body.extend_from_slice(&table_of(self.table));
            let length = COMPRESSED_HEADER + body.len();
            [
                &u24(length)[..],
                &u24(self.decoded),
                &u24(o1),
                &u24(o2),
                &u24(o3),
                &body,
            ]
            .concat()
        }
    }

    fn stream(blocks: &[Vec<u8>]) -> Vec<u8> {
        [&b"ZBM\x09"[..], &blocks.concat(), &END].concat()
    }

    fn raw(bytes: &[u8]) -> Vec<u8> {
        [
            &u24(bytes.len() + BLOCK_HEADER)[..],
            &u24(bytes.len()),
            bytes,
        ]
        .concat()
    }

    fn decode(stream: &[u8], room: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; room];
        let n = decompress(stream, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn fault(stream: &[u8], room: usize) -> &'static str {
        match decode(stream, room) {
            Err(Error::Malformed { fault, .. }) => fault,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The text libcompression's encoder was given for the streams below.
    fn line_text(len: usize, seed: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut line = 0;
        while out.len() < len {
            out.extend_from_slice(
                format!(
                    "line {line:06} of seed {seed}: the quick brown fox jumps over the lazy dog\n"
                )
                .as_bytes(),
            );
            line += 1;
        }
        out.truncate(len);
        out
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn streams_libcompression_wrote_decode_to_what_it_was_given() {
        // libcompression's encoding on macOS 15, 26 and 27 of 145 bytes of `a`: eight literals,
        // then one entry of mask 0 counted 23 times, five past the block's end.
        let run = hex(concat!(
            "5a424d092b0000910000170000170000170000616161616161616134ff0400fc0300000000000000",
            "00000000000000060000000000"
        ));
        assert_eq!(decode(&run, 145).unwrap(), vec![b'a'; 145]);
        // And of 145 bytes of text, whose steps read distances and masks from the table.
        let text = hex(concat!(
            "5a424d096700009100004b00004f00004f00006c696e6520303030303030206f662073656420313a",
            "74686520717569636b62726f776e2066786a756d70736f7665726c617a7920646f670a6c696e310d",
            "1e1f45776a4b5897f30a00ac038f3fffec059867fb010000000000060000000000"
        ));
        assert_eq!(decode(&text, 145).unwrap(), line_text(145, 100));
    }

    #[test]
    fn a_block_of_literals_and_copies_decodes_a_step_at_a_time() {
        // Eight literals, then mask 0 counted 7 times: 56 bytes copied from 8 back.
        let block = Block {
            decoded: 64,
            literals: b"abcdefgh",
            distances: &[],
            masks: &[],
            selectors: &[3, 4, 15, 3],
            table: &[LIT8, COPY8],
            ..Block::default()
        };
        assert_eq!(
            decode(&stream(&[block.bytes()]), 64).unwrap(),
            b"abcdefgh".repeat(8)
        );
    }

    #[test]
    fn a_step_reads_its_mask_and_distance_where_its_selector_says() {
        // Sixteen literals, then selector 1: a mask byte from the masks, 0x0F, and one distance
        // byte, 16. Its first four bytes are literals and its last four copies from 16 back;
        // then a count of 4 copy steps runs on at that distance.
        let block = Block {
            decoded: 56,
            literals: b"ABCDEFGHIJKLMNOPwxyz",
            distances: &[16],
            masks: &[0x0F],
            selectors: &[3, 3, 1, 4, 15, 0],
            table: &[LIT8, COPY8],
            ..Block::default()
        };
        let out = decode(&stream(&[block.bytes()]), 56).unwrap();
        assert_eq!(&out[..24], b"ABCDEFGHIJKLMNOPwxyzEFGH");
        assert_eq!(&out[24..40], b"IJKLMNOPwxyzEFGH");
    }

    #[test]
    fn a_later_block_reaches_into_those_before_it_and_starts_at_distance_eight() {
        let first = raw(b"0123456789abcdef");
        let second = Block {
            decoded: 32,
            literals: &[],
            distances: &[16],
            masks: &[0x00],
            selectors: &[1, 4, 15, 0],
            table: &[LIT8, COPY8],
            ..Block::default()
        };
        // Its first step copies from 16 back, into the raw block, and the steps after it
        // keep that distance.
        let out = decode(&stream(&[first.clone(), second.bytes()]), 48).unwrap();
        assert_eq!(&out[16..], b"0123456789abcdef0123456789abcdef");
        // A copy step that reads no distance copies from 8 back however the block before it
        // ended.
        let third = Block {
            decoded: 32,
            literals: &[],
            distances: &[],
            masks: &[],
            selectors: &[4, 15, 0],
            table: &[LIT8, COPY8],
            ..Block::default()
        };
        let out = decode(&stream(&[first, second.bytes(), third.bytes()]), 80).unwrap();
        assert_eq!(&out[48..], b"89abcdef".repeat(4));
    }

    #[test]
    fn a_count_ends_at_the_first_selector_that_is_not_fifteen() {
        // 4 + 15 + 2 = 21 copy steps after the literals: 176 bytes.
        let block = Block {
            decoded: 176,
            literals: b"abcdefgh",
            distances: &[],
            masks: &[],
            selectors: &[3, 4, 15, 15, 2],
            table: &[LIT8, COPY8],
            ..Block::default()
        };
        assert_eq!(
            decode(&stream(&[block.bytes()]), 176).unwrap(),
            b"abcdefgh".repeat(22)
        );
        // With eight bytes left, the selector after a step's own is not read as a count, so the
        // fifteen after the last step is never read at all.
        let block = Block {
            decoded: 48,
            literals: b"abcdefgh",
            distances: &[],
            masks: &[],
            selectors: &[3, 4, 15, 0, 4, 15, 2],
            table: &[LIT8, COPY8],
            ..Block::default()
        };
        assert_eq!(
            decode(&stream(&[block.bytes()]), 48).unwrap(),
            b"abcdefgh".repeat(6)
        );
    }

    #[test]
    fn a_last_step_with_eight_bytes_left_reads_no_count_past_the_block() {
        // Every selector is 0: two in the selector area, thirty in the table, four in its last
        // two bytes. The last is the block's last half-byte, and a count read after it would
        // read past the block's end.
        let masks = [&[0xFF][..], &[0; 35]].concat();
        let block = Block {
            decoded: 288,
            literals: b"abcdefgh",
            masks: &masks,
            selectors: &[0, 0],
            ..Block::default()
        };
        assert_eq!(
            decode(&stream(&[block.bytes()]), 288).unwrap(),
            b"abcdefgh".repeat(36)
        );
    }

    #[test]
    fn literals_and_distances_left_over_are_refused() {
        let mut block = Block {
            decoded: 64,
            literals: b"abcdefghi",
            distances: &[],
            masks: &[],
            selectors: &[3, 4, 15, 3],
            table: &[LIT8, COPY8],
            ..Block::default()
        };
        assert_eq!(
            fault(&stream(&[block.bytes()]), 64),
            "a block's literals are not all used"
        );
        block.literals = b"abcdefgh";
        block.distances = &[8];
        assert_eq!(
            fault(&stream(&[block.bytes()]), 64),
            "a block's distances are not all used"
        );
    }

    #[test]
    fn a_copy_into_its_own_step_or_before_the_output_is_refused() {
        for (distance, refused) in [(0, true), (7, true), (8, false), (16, false), (17, true)] {
            let block = Block {
                decoded: 64,
                literals: b"0123456789abcdef",
                distances: &[distance],
                masks: &[0x00],
                selectors: &[3, 3, 1, 4, 15, 1],
                table: &[LIT8, COPY8],
                ..Block::default()
            };
            let out = decode(&stream(&[block.bytes()]), 64);
            assert_eq!(out.is_err(), refused, "distance {distance}: {out:?}");
        }
    }

    #[test]
    fn a_block_longer_than_its_bytes_stored_as_they_are_is_refused() {
        // Sixteen literals in two steps take 49 bytes compressed and 22 stored as they are.
        let block = Block {
            decoded: 16,
            literals: b"0123456789abcdef",
            distances: &[],
            masks: &[],
            selectors: &[3, 3],
            table: &[LIT8],
            ..Block::default()
        };
        assert_eq!(
            fault(&stream(&[block.bytes()]), 16),
            "a block is longer than the bytes it decodes to stored as they are"
        );
    }

    #[test]
    fn the_stream_is_framed_by_its_signature_and_its_end_block() {
        let whole = stream(&[raw(b"hello")]);
        assert_eq!(decode(&whole, 5).unwrap(), b"hello");
        // Bytes after the end block are not read.
        let mut trailing = whole.clone();
        trailing.extend_from_slice(&raw(b"after"));
        assert_eq!(decode(&trailing, 16).unwrap(), b"hello");
        // A stream without its end block, or of another signature, is not one.
        assert_eq!(
            fault(&whole[..whole.len() - 6], 16),
            "the stream ends without its end block"
        );
        let mut other = whole.clone();
        other[0] = b'z';
        assert_eq!(
            fault(&other, 16),
            "the stream does not open with its signature"
        );
        // A block decoding past 32 KiB, or past the room it is given.
        assert_eq!(
            fault(&stream(&[raw(&vec![0; MAX_DECODED + 1])]), 2 * MAX_DECODED),
            "a block decodes to more than 32 KiB"
        );
        assert!(matches!(decode(&whole, 4), Err(Error::Overrun { .. })));
    }

    #[test]
    fn a_selector_of_fifteen_and_a_table_entry_reading_three_bytes_are_refused() {
        let block = Block {
            decoded: 48,
            literals: b"abcdefgh",
            distances: &[],
            masks: &[],
            selectors: &[3, 4, 15, 0, 15],
            table: &[LIT8, COPY8],
            ..Block::default()
        };
        assert_eq!(
            fault(&stream(&[block.bytes()]), 48),
            "a selector of 15 names no step"
        );
        let block = Block {
            decoded: 64,
            literals: b"abcdefgh",
            distances: &[],
            masks: &[],
            selectors: &[3, 4, 15, 3],
            table: &[LIT8, COPY8, (0, 3)],
            ..Block::default()
        };
        assert_eq!(
            fault(&stream(&[block.bytes()]), 64),
            "a table entry reads three distance bytes"
        );
    }

    #[test]
    fn the_fourth_signature_byte_says_which_blocks_the_stream_holds() {
        let block = Block {
            decoded: 64,
            literals: b"abcdefgh",
            selectors: &[3, 4, 15, 3],
            table: &[LIT8, COPY8],
            ..Block::default()
        };
        let compressed = stream(&[block.bytes()]);
        let raw_only = stream(&[raw(b"hello")]);
        let with = |whole: &[u8], byte: u8| [&whole[..3], &[byte], &whole[4..]].concat();
        for byte in [0x08, 0x09] {
            assert_eq!(
                decode(&with(&compressed, byte), 64).unwrap(),
                b"abcdefgh".repeat(8)
            );
        }
        for byte in [0x0C, 0x0D] {
            assert_eq!(decode(&with(&raw_only, byte), 5).unwrap(), b"hello");
            assert_eq!(
                fault(&with(&compressed, byte), 64),
                "a compressed block in a stream whose signature admits none"
            );
        }
        for byte in [0x00, 0x01, 0x04, 0x0A, 0xFF] {
            assert_eq!(
                fault(&with(&raw_only, byte), 5),
                "the stream's signature ends in a byte it does not take"
            );
        }
    }

    /// Two steps of literals, a step of selector 0 whose mask is the selectors' first byte, 0x33,
    /// and 30 steps of copies: the mask area starts where the selectors do.
    fn mask_from_the_selectors() -> Block<'static> {
        Block {
            decoded: 264,
            literals: b"ABCDEFGHIJKLMNOPwxyz",
            selectors: &[3, 3, 0, 4, 15, 15, 11],
            table: &[LIT8, COPY8],
            offsets: Some([35, 35, 35]),
            ..Block::default()
        }
    }

    #[test]
    fn a_mask_is_read_through_the_selectors_and_never_from_the_table() {
        let out = decode(&stream(&[mask_from_the_selectors().bytes()]), 264).unwrap();
        assert_eq!(&out[..24], b"ABCDEFGHIJKLMNOPwxKLyzOP");
        assert_eq!(&out[24..], b"wxKLyzOP".repeat(30));
        // Eight steps of selector 0 read the seven selector bytes as masks, and then the
        // table's first byte.
        let block = Block {
            decoded: 320,
            literals: &[b'q'; 40],
            selectors: &[3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 4, 15, 15, 11],
            table: &[LIT8, COPY8],
            offsets: Some([55, 55, 55]),
            ..Block::default()
        };
        assert_eq!(
            fault(&stream(&[block.bytes()]), 320),
            "a step's mask lies in the block's table"
        );
    }

    #[test]
    fn a_selector_is_read_through_the_table() {
        // Three selector bytes end with a copy step; the next selector is the table's first
        // byte, 0x33: entry 0, whose mask takes four literals and copies four.
        let block = Block {
            decoded: 264,
            literals: b"ABCDEFGHwxyz",
            selectors: &[4, 5, 15, 15, 11, 5],
            table: &[(0x33, 0), LIT8, COPY8],
            ..Block::default()
        };
        let out = decode(&stream(&[block.bytes()]), 264).unwrap();
        assert_eq!(&out[..8], b"ABCDEFGH");
        assert_eq!(&out[256..], b"wxCDyzGH");
    }

    #[test]
    fn the_selectors_start_between_the_masks_and_the_table() {
        let fault_of =
            |block: &[u8], room| fault(&stream(&[raw(b"0123456789abcdef"), block.to_vec()]), room);
        // Selectors starting among the literals, whose first three bytes are the selectors.
        let selectors = nibbles(&[3, 4, 15, 15, 11, 3]);
        let literals = [&selectors[..], b"DEFGHIJKLMNOP"].concat();
        let block = Block {
            decoded: 256,
            literals: &literals,
            table: &[LIT8, COPY8],
            offsets: Some([31, 31, 15]),
            ..Block::default()
        };
        assert_eq!(
            fault_of(&block.bytes(), 272),
            "a block's selectors do not start between its masks and its table"
        );
        // Selectors starting at the table, which the block's three offsets all name.
        let block = Block {
            decoded: 32,
            table: &[(0xF4, 0), COPY8],
            ..Block::default()
        };
        assert_eq!(
            fault_of(&block.bytes(), 48),
            "a block's selectors do not start between its masks and its table"
        );
    }

    #[test]
    fn the_selectors_take_at_most_one_byte_for_two_steps_of_a_whole_block() {
        // Literals, then a count of 4,095 copy steps, in 138 selector bytes; then unused
        // selector bytes up to 2,048 and to one more.
        let mut selectors = vec![3, 4, 15];
        selectors.extend([15; 272]);
        selectors.push(11);
        let used = nibbles(&selectors).len();
        for (area, refused) in [(MAX_SELECTOR_BYTES, false), (MAX_SELECTOR_BYTES + 1, true)] {
            let pad = vec![0u8; area - used];
            let block = Block {
                decoded: MAX_DECODED,
                literals: b"abcdefgh",
                selectors: &selectors,
                pad: &pad,
                table: &[LIT8, COPY8],
                ..Block::default()
            };
            let out = decode(&stream(&[block.bytes()]), MAX_DECODED);
            match out {
                Ok(out) => assert!(!refused && out == b"abcdefgh".repeat(4096)),
                Err(Error::Malformed { fault, .. }) => assert!(
                    refused
                        && fault == "a block's selectors take more bytes than its steps can use"
                ),
                Err(e) => panic!("{e:?}"),
            }
        }
    }

    #[test]
    fn streams_libcompression_wrote_changed_a_byte_at_a_time_refuse_or_fit() {
        // The two streams above: one entry counted past the block's end, and steps reading
        // distances and masks from the table.
        for stream in [
            hex(concat!(
                "5a424d092b0000910000170000170000170000616161616161616134ff0400fc0300000000000000",
                "00000000000000060000000000"
            )),
            hex(concat!(
                "5a424d096700009100004b00004f00004f00006c696e6520303030303030206f662073656420313a",
                "74686520717569636b62726f776e2066786a756d70736f7665726c617a7920646f670a6c696e310d",
                "1e1f45776a4b5897f30a00ac038f3fffec059867fb010000000000060000000000"
            )),
        ] {
            super::super::sweep_changes_of(&stream, 145 + 16, decompress);
        }
    }

    #[test]
    fn arbitrary_bytes_are_an_lzbitmap_stream_that_refuses_or_fits() {
        // Arbitrary bytes seldom open with the signature, so each is given it to open with.
        super::super::sweep_arbitrary_bytes(9, |bytes, out| {
            decompress(&[&b"ZBM\x09"[..], bytes].concat(), out)
        });
    }
}
