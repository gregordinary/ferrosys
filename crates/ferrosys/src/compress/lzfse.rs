//! LZFSE, decoded.
//!
//! The input is a filesystem's own bytes and therefore untrusted, and every bound the decoder
//! reads is one this crate's gates hold it to. The decoder is derived from the one in Apple's
//! reference implementation, the `lzfse` project (copyright 2015-2016 Apple Inc., under the
//! BSD-3-Clause license, whose notice the crate's `THIRD-PARTY-NOTICES` carries): its value
//! tables, the build of its decoding tables and its bit reader follow that decoder's.
//!
//! This module is pure — bytes in, bytes out, no I/O — and what it decodes is one *stream*.
//!
//! # The encoding
//!
//! A stream is a run of blocks, each opening with four bytes that say what it is:
//!
//! | Magic | Block | What follows the magic |
//! |---|---|---|
//! | `bvx-` | raw bytes | their count, then the bytes |
//! | `bvxn` | an LZVN stream | the bytes it produces and its own length, then the stream |
//! | `bvx2` | entropy-coded | a header with packed frequency tables, the literals, the commands |
//! | `bvx$` | the end of the stream | nothing |
//!
//! Every count is a little-endian 32-bit word. A block's matches reach back into everything the
//! stream has produced, the blocks before it included. `bvx1`, an entropy-coded block whose
//! tables are stored whole, is refused by name: every stream the decoder is held to is made of
//! the four kinds above.
//!
//! # An entropy-coded block
//!
//! The block's literal bytes and its commands are coded with finite-state entropy: a decoder is
//! in one of a power-of-two number of states, each state stands for a symbol, and moving to the
//! next state takes a few bits from the stream. The header gives, for each of four alphabets,
//! how many states each symbol has — the literal bytes (256 symbols, 1024 states), literal
//! lengths `L` (20, 64), match lengths `M` (20, 64) and match distances `D` (64, 256) — and the
//! state each decoder starts in. A symbol's states are consecutive, the first symbol's first.
//!
//! The literals are decoded first, four decoders taking turns, into a buffer of their own. Then
//! each command is a triplet: copy `L` of those literals, then `M` bytes from `D` back. An `L`,
//! `M` or `D` symbol stands for a base value plus a number of bits read after the state's own; a
//! `D` of zero repeats the distance before. Both bit streams are read backwards, from the last
//! byte of their payload, and each is opened with the count of bits its last byte holds.
//!
//! # What a match may point at
//!
//! As for LZVN: backwards into what the stream has produced, and never before its start. The
//! first command of a stream has no distance before it to repeat.

use super::{Algorithm, Error, lzvn};
use crate::bytes::{get_u32, get_u64};

/// What a stream says it is wrong about.
fn malformed(fault: &'static str) -> Error {
    Error::Malformed {
        algorithm: Algorithm::Lzfse,
        fault,
    }
}

/// The output buffer is full and the stream goes on.
fn overrun(out: &[u8]) -> Error {
    Error::Overrun {
        algorithm: Algorithm::Lzfse,
        expected: out.len(),
    }
}

const END: u32 = u32::from_le_bytes(*b"bvx$");
const RAW: u32 = u32::from_le_bytes(*b"bvx-");
const LZVN: u32 = u32::from_le_bytes(*b"bvxn");
const TABLES_WHOLE: u32 = u32::from_le_bytes(*b"bvx1");
const TABLES_PACKED: u32 = u32::from_le_bytes(*b"bvx2");

/// Symbols and states of each alphabet: literal lengths, match lengths, distances, literals.
const L_SYMBOLS: usize = 20;
const M_SYMBOLS: usize = 20;
const D_SYMBOLS: usize = 64;
const LITERAL_SYMBOLS: usize = 256;
const L_STATES: usize = 64;
const M_STATES: usize = 64;
const D_STATES: usize = 256;
const LITERAL_STATES: usize = 1024;

/// The most commands, and literal bytes, one block holds.
const MAX_MATCHES: u32 = 10_000;
const MAX_LITERALS: u32 = 4 * MAX_MATCHES;

/// The bits read after a symbol's state, and the value those bits are added to, for each
/// symbol of the three command alphabets.
const L_EXTRA: [u8; L_SYMBOLS] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const L_BASE: [u32; L_SYMBOLS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60,
];
const M_EXTRA: [u8; M_SYMBOLS] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
const M_BASE: [u32; M_SYMBOLS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312,
];
const D_EXTRA: [u8; D_SYMBOLS] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14,
    14, 14, 15, 15, 15, 15,
];
const D_BASE: [u32; D_SYMBOLS] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220,
    252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092,
    5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148,
    57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
];

/// Undo one LZFSE stream into `out`, returning how many bytes it produced.
///
/// The stream ends at its end block; bytes after it are not read.
pub(super) fn decompress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut src = 0usize;
    let mut dst = 0usize;
    loop {
        let word = |at: usize| {
            input
                .get(at..at + 4)
                .map(|b| get_u32(b, 0))
                .ok_or_else(|| malformed("the stream ends without its end block"))
        };
        match word(src)? {
            END => return Ok(dst),
            RAW => {
                let n = word(src + 4)? as usize;
                let body = src + 8;
                // A length the stream records, added where it cannot pass the address space:
                // on a 32-bit target a 32-bit length can.
                let bytes = body
                    .checked_add(n)
                    .and_then(|end| input.get(body..end))
                    .ok_or_else(|| malformed("a raw block runs past the end of the stream"))?;
                if out.len() - dst < n {
                    return Err(overrun(out));
                }
                out[dst..dst + n].copy_from_slice(bytes);
                dst += n;
                src = body + n;
            }
            LZVN => {
                let raw = word(src + 4)? as usize;
                let payload = word(src + 8)? as usize;
                let body = src + 12;
                let stream = body
                    .checked_add(payload)
                    .and_then(|end| input.get(body..end))
                    .ok_or_else(|| malformed("an LZVN block runs past the end of the stream"))?;
                let end = dst.checked_add(raw).filter(|end| *end <= out.len());
                let end = end.ok_or_else(|| overrun(out))?;
                // The LZVN stream may reach back into every block before it, and must produce
                // exactly the bytes its block says and end exactly where its payload does.
                let (used, reached) = lzvn::decode_from(stream, &mut out[..end], dst)
                    .map_err(|_| malformed("an LZVN block does not decode"))?;
                if used != payload || reached != end {
                    return Err(malformed(
                        "an LZVN block's stream is not the length its block records",
                    ));
                }
                dst = end;
                src = body + payload;
            }
            TABLES_PACKED => {
                let block = Block::read(&input[src..])?;
                dst = block.decode(input, src, out, dst)?;
                src += block.header_len + block.literal_bytes + block.command_bytes;
            }
            TABLES_WHOLE => {
                return Err(malformed(
                    "a block whose tables are stored whole, which no stream observed carries",
                ));
            }
            _ => return Err(malformed("a block of a kind the encoding does not define")),
        }
    }
}

/// An entropy-coded block's header, decoded.
struct Block {
    /// The bytes the block produces.
    raw: usize,
    /// Its header, frequency tables included.
    header_len: usize,
    /// Literal bytes, a multiple of four, and the bytes their bit stream takes.
    literals: usize,
    literal_bytes: usize,
    /// The bits of the literal stream's last byte, 1 to 8, and the four decoders' first states.
    literal_bits: u32,
    literal_states: [u16; 4],
    /// Commands, and the bytes their bit stream takes.
    matches: usize,
    command_bytes: usize,
    /// The bits of the command stream's last byte, and the three decoders' first states.
    command_bits: u32,
    l_state: u16,
    m_state: u16,
    d_state: u16,
    /// How many states each symbol of each alphabet has.
    l_freq: [u16; L_SYMBOLS],
    m_freq: [u16; M_SYMBOLS],
    d_freq: [u16; D_SYMBOLS],
    literal_freq: [u16; LITERAL_SYMBOLS],
}

/// The bytes of a packed header before its frequency tables.
const PACKED_HEADER: usize = 32;

/// Bits `at..at + width` of `word`.
const fn field(word: u64, at: u32, width: u32) -> u64 {
    (word >> at) & ((1 << width) - 1)
}

impl Block {
    /// Read the header at the start of `bytes`, which opens with its magic.
    fn read(bytes: &[u8]) -> Result<Self, Error> {
        let short = || malformed("a block header runs past the end of the stream");
        let fixed = bytes.get(..PACKED_HEADER).ok_or_else(short)?;
        let raw = get_u32(fixed, 4) as usize;
        let (v0, v1, v2) = (get_u64(fixed, 8), get_u64(fixed, 16), get_u64(fixed, 24));
        let header_len = field(v2, 0, 32) as usize;
        if header_len < PACKED_HEADER {
            return Err(malformed("a block header shorter than its fixed part"));
        }
        let tables = bytes.get(PACKED_HEADER..header_len).ok_or_else(short)?;
        let state = |word: u64, at: u32| field(word, at, 10) as u16;
        let mut block = Block {
            raw,
            header_len,
            literals: field(v0, 0, 20) as usize,
            literal_bytes: field(v0, 20, 20) as usize,
            literal_bits: field(v0, 60, 3) as u32,
            literal_states: [state(v1, 0), state(v1, 10), state(v1, 20), state(v1, 30)],
            matches: field(v0, 40, 20) as usize,
            command_bytes: field(v1, 40, 20) as usize,
            command_bits: field(v1, 60, 3) as u32,
            l_state: state(v2, 32),
            m_state: state(v2, 42),
            d_state: state(v2, 52),
            l_freq: [0; L_SYMBOLS],
            m_freq: [0; M_SYMBOLS],
            d_freq: [0; D_SYMBOLS],
            literal_freq: [0; LITERAL_SYMBOLS],
        };
        if block.literals > MAX_LITERALS as usize
            || block.matches > MAX_MATCHES as usize
            || !block.literals.is_multiple_of(4)
        {
            return Err(malformed("a block holding more than a block may"));
        }
        // A literal state's ten bits never reach past its 1,024 states; the commands' do, and a
        // block whose commands start outside their states is refused before anything decodes,
        // whether or not it holds a command.
        if usize::from(block.l_state) >= L_STATES
            || usize::from(block.m_state) >= M_STATES
            || usize::from(block.d_state) >= D_STATES
        {
            return Err(malformed(
                "a block whose commands start in a state they do not have",
            ));
        }
        if !tables.is_empty() {
            block.read_tables(tables)?;
        }
        Ok(block)
    }

    /// The frequency tables, in the order lengths, match lengths, distances, literals, each
    /// value in a variable-length code read from the low bits up.
    fn read_tables(&mut self, tables: &[u8]) -> Result<(), Error> {
        let mut accum = 0u32;
        let mut held = 0u32;
        let mut next = 0usize;
        let mut values = [0u16; L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS];
        for value in &mut values {
            while next < tables.len() && held + 8 <= 32 {
                accum |= u32::from(tables[next]) << held;
                held += 8;
                next += 1;
            }
            let (decoded, width) = frequency(accum);
            if width > held {
                return Err(malformed("a frequency table ends mid-value"));
            }
            *value = decoded;
            accum >>= width;
            held -= width;
        }
        if held >= 8 || next != tables.len() {
            return Err(malformed(
                "a frequency table is not the length its header records",
            ));
        }
        let (l, rest) = values.split_at(L_SYMBOLS);
        let (m, rest) = rest.split_at(M_SYMBOLS);
        let (d, literal) = rest.split_at(D_SYMBOLS);
        self.l_freq.copy_from_slice(l);
        self.m_freq.copy_from_slice(m);
        self.d_freq.copy_from_slice(d);
        self.literal_freq.copy_from_slice(literal);
        Ok(())
    }

    /// Decode the block, which begins at `start` in `input`, into `out` from `dst`, and say
    /// where its output ends.
    fn decode(
        &self,
        input: &[u8],
        start: usize,
        out: &mut [u8],
        dst: usize,
    ) -> Result<usize, Error> {
        let literal_start = start + self.header_len;
        let literal_end = literal_start + self.literal_bytes;
        let command_end = literal_end + self.command_bytes;
        if command_end > input.len() {
            return Err(malformed(
                "a block's payload runs past the end of the stream",
            ));
        }
        let end = dst.checked_add(self.raw).filter(|end| *end <= out.len());
        let end = end.ok_or_else(|| overrun(out))?;

        // The literals, four decoders taking turns, read backwards from the end of their
        // payload. The stream may begin as early as the start of the input.
        let symbols = SymbolTable::new(LITERAL_STATES, &self.literal_freq)?;
        let mut bits = Bits::open(input, 0, literal_end, self.literal_bits)?;
        let mut states = self.literal_states;
        let mut literals = vec![0u8; self.literals];
        for quad in literals.chunks_mut(4) {
            bits.refill()?;
            for (byte, state) in quad.iter_mut().zip(states.iter_mut()) {
                *byte = symbols.step(state, &mut bits)?;
            }
        }

        // The commands, read backwards from the end of their own payload.
        let l = ValueTable::new(L_STATES, &self.l_freq, &L_EXTRA, &L_BASE)?;
        let m = ValueTable::new(M_STATES, &self.m_freq, &M_EXTRA, &M_BASE)?;
        let d = ValueTable::new(D_STATES, &self.d_freq, &D_EXTRA, &D_BASE)?;
        let mut bits = Bits::open(input, literal_end, command_end, self.command_bits)?;
        let (mut l_state, mut m_state, mut d_state) = (self.l_state, self.m_state, self.d_state);
        let mut lit = 0usize;
        let mut at = dst;
        let mut distance: Option<usize> = None;
        for _ in 0..self.matches {
            bits.refill()?;
            let length = l.step(&mut l_state, &mut bits)? as usize;
            let matched = m.step(&mut m_state, &mut bits)? as usize;
            let new = d.step(&mut d_state, &mut bits)? as usize;
            if new != 0 {
                distance = Some(new);
            }
            let source = literals
                .get(lit..lit + length)
                .ok_or_else(|| malformed("a command copies more literals than the block holds"))?;
            if end - at < length + matched {
                return Err(malformed("a block produces more than it records"));
            }
            out[at..at + length].copy_from_slice(source);
            lit += length;
            at += length;
            let back = distance.unwrap_or(0);
            if !super::copy_back(out, at, back, matched) {
                return Err(malformed("a match reaches before the start of the output"));
            }
            at += matched;
        }
        if at != end {
            return Err(malformed("a block produces other than it records"));
        }
        Ok(end)
    }
}

/// A frequency from the low bits of `bits`, and how many bits its code takes.
fn frequency(bits: u32) -> (u16, u32) {
    const WIDTH: [u8; 32] = [
        2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3,
        2, 14,
    ];
    const VALUE: [u8; 32] = [
        0, 2, 1, 4, 0, 3, 1, 0, 0, 2, 1, 5, 0, 3, 1, 0, 0, 2, 1, 6, 0, 3, 1, 0, 0, 2, 1, 7, 0, 3,
        1, 0,
    ];
    let low = (bits & 31) as usize;
    match WIDTH[low] {
        8 => (8 + ((bits >> 4) & 0xF) as u16, 8),
        14 => (24 + ((bits >> 4) & 0x3FF) as u16, 14),
        width => (u16::from(VALUE[low]), u32::from(width)),
    }
}

/// What one state of a finite-state table stands for, and how a decoder leaves it.
#[derive(Clone, Copy)]
struct State {
    /// The symbol it stands for.
    symbol: usize,
    /// The bits leaving it reads.
    bits: u32,
    /// What those bits are added to, giving the next state.
    base: u32,
}

/// Each state of a table of `states` states whose symbols hold `freq` of them each, a symbol's
/// states consecutive and the first symbol's first: the part every table here shares. `None`
/// for a state no symbol was given.
fn transitions(states: usize, freq: &[u16]) -> Result<Vec<Option<State>>, Error> {
    let total: usize = freq.iter().map(|f| usize::from(*f)).sum();
    if total > states {
        return Err(malformed(
            "a frequency table gives out more states than it has",
        ));
    }
    let n_log = states.trailing_zeros();
    let mut table = vec![None; states];
    let mut next = 0usize;
    for (symbol, &f) in freq.iter().enumerate() {
        let f = u32::from(f);
        if f == 0 {
            continue;
        }
        // The shift that brings the symbol's count to between the state count and twice it.
        let k = n_log - (31 - f.leading_zeros());
        let j0 = ((2 * states as u32) >> k) - f;
        for j in 0..f {
            table[next] = Some(if j < j0 {
                State {
                    symbol,
                    bits: k,
                    base: ((f + j) << k) - states as u32,
                }
            } else {
                State {
                    symbol,
                    bits: k - 1,
                    base: (j - j0) << (k - 1),
                }
            });
            next += 1;
        }
    }
    Ok(table)
}

/// The literal alphabet's table: each state's symbol, and how to reach the next state.
struct SymbolTable(Vec<Option<State>>);

impl SymbolTable {
    fn new(states: usize, freq: &[u16]) -> Result<Self, Error> {
        transitions(states, freq).map(SymbolTable)
    }

    /// The symbol `state` stands for, moving `state` on.
    fn step(&self, state: &mut u16, bits: &mut Bits<'_>) -> Result<u8, Error> {
        let entry = self
            .0
            .get(usize::from(*state))
            .copied()
            .flatten()
            .ok_or_else(|| malformed("a state no symbol was given"))?;
        *state = (entry.base + bits.pull(entry.bits)? as u32) as u16;
        Ok(entry.symbol as u8)
    }
}

/// A command alphabet's table: each state's symbol, as the bits it reads and the value it
/// stands for, and how to reach the next state.
struct ValueTable {
    states: Vec<Option<State>>,
    extra: &'static [u8],
    base: &'static [u32],
}

impl ValueTable {
    fn new(
        states: usize,
        freq: &[u16],
        extra: &'static [u8],
        base: &'static [u32],
    ) -> Result<Self, Error> {
        Ok(ValueTable {
            states: transitions(states, freq)?,
            extra,
            base,
        })
    }

    /// The value `state` stands for, its extra bits read, moving `state` on. The state's bits
    /// and the value's are one read, the state's the higher.
    fn step(&self, state: &mut u16, bits: &mut Bits<'_>) -> Result<u32, Error> {
        let entry = self
            .states
            .get(usize::from(*state))
            .copied()
            .flatten()
            .ok_or_else(|| malformed("a state no symbol was given"))?;
        let symbol = entry.symbol;
        let extra = u32::from(self.extra[symbol]);
        let read = bits.pull(entry.bits + extra)?;
        *state = (entry.base + (read >> extra) as u32) as u16;
        Ok(self.base[symbol] + (read & ((1 << extra) - 1)) as u32)
    }
}

/// A bit stream read backwards: bytes are taken from the end of its payload towards the start,
/// and bits from the top of what has been taken.
struct Bits<'a> {
    input: &'a [u8],
    /// The earliest byte the stream may take.
    floor: usize,
    /// The next byte to take is the one before this.
    at: usize,
    accum: u64,
    held: u32,
}

impl<'a> Bits<'a> {
    /// Open the stream whose payload ends at `end`, with its last byte holding `last` bits
    /// (stored as the count less one, so 0 to 7 stands for 1 to 8), taking no byte before
    /// `floor`. It begins holding 56 to 63 bits.
    fn open(input: &'a [u8], floor: usize, end: usize, last: u32) -> Result<Self, Error> {
        let short = || malformed("a bit stream is shorter than its first read");
        // The stored count is the bits beyond a whole number of bytes, offset by seven.
        let missing = 7 - last;
        let take = if missing == 0 { 7 } else { 8 };
        let at = end
            .checked_sub(take)
            .filter(|at| *at >= floor)
            .ok_or_else(short)?;
        let mut accum = 0u64;
        for (i, byte) in input[at..end].iter().enumerate() {
            accum |= u64::from(*byte) << (8 * i);
        }
        let held = 8 * take as u32 - missing;
        if !(56..64).contains(&held) || accum >> held != 0 {
            return Err(malformed(
                "a bit stream's first byte holds bits it says it does not",
            ));
        }
        Ok(Bits {
            input,
            floor,
            at,
            accum,
            held,
        })
    }

    /// Take whole bytes until 56 to 63 bits are held.
    fn refill(&mut self) -> Result<(), Error> {
        let bytes = ((63 - self.held) / 8) as usize;
        if bytes == 0 {
            return Ok(());
        }
        let at = self
            .at
            .checked_sub(bytes)
            .filter(|at| *at >= self.floor)
            .ok_or_else(|| malformed("a bit stream runs past the start of its payload"))?;
        let mut incoming = 0u64;
        for (i, byte) in self.input[at..self.at].iter().enumerate() {
            incoming |= u64::from(*byte) << (8 * i);
        }
        self.accum = (self.accum << (8 * bytes)) | incoming;
        self.held += 8 * bytes as u32;
        self.at = at;
        Ok(())
    }

    /// The next `n` bits, the highest held first.
    fn pull(&mut self, n: u32) -> Result<u64, Error> {
        if n > self.held {
            return Err(malformed("a bit stream runs out mid-symbol"));
        }
        self.held -= n;
        let value = self.accum >> self.held;
        self.accum &= (1u64 << self.held) - 1;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes `values` take in a packed header's frequency code, lowest bits first.
    fn packed_frequencies(values: &[u16]) -> Vec<u8> {
        let (mut bits, mut held, mut out) = (0u64, 0u32, Vec::new());
        for &v in values {
            let (code, width) = match v {
                0 => (0b00, 2),
                1 => (0b10, 2),
                2 => (0b001, 3),
                3 => (0b101, 3),
                4 => (0b00011, 5),
                5 => (0b01011, 5),
                6 => (0b10011, 5),
                7 => (0b11011, 5),
                8..=23 => ((u64::from(v) - 8) << 4 | 0b0111, 8),
                _ => ((u64::from(v) - 24) << 4 | 0b1111, 14),
            };
            bits |= code << held;
            held += width;
            while held >= 8 {
                out.push(bits as u8);
                bits >>= 8;
                held -= 8;
            }
        }
        if held > 0 {
            out.push(bits as u8);
        }
        out
    }

    /// A packed block producing `raw` bytes from `literals` literal bytes and `matches`
    /// commands, with the given tables, starting states and payloads, each payload's last byte
    /// holding all eight of its bits.
    #[allow(clippy::too_many_arguments)]
    fn packed_block(
        raw: u32,
        literals: u64,
        matches: u64,
        literal_states: [u64; 4],
        freqs: (&[u16], &[u16], &[u16], &[u16]),
        literal_payload: &[u8],
        command_payload: &[u8],
    ) -> Vec<u8> {
        let mut values = Vec::new();
        for table in [freqs.0, freqs.1, freqs.2, freqs.3] {
            values.extend_from_slice(table);
        }
        let tables = packed_frequencies(&values);
        let header_len = (PACKED_HEADER + tables.len()) as u64;
        let v0 = literals | (literal_payload.len() as u64) << 20 | matches << 40 | 7 << 60;
        let v1 = literal_states[0]
            | literal_states[1] << 10
            | literal_states[2] << 20
            | literal_states[3] << 30
            | (command_payload.len() as u64) << 40
            | 7 << 60;
        let v2 = header_len;
        let mut out = b"bvx2".to_vec();
        out.extend_from_slice(&raw.to_le_bytes());
        for word in [v0, v1, v2] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(&tables);
        out.extend_from_slice(literal_payload);
        out.extend_from_slice(command_payload);
        out
    }

    fn table<const N: usize>(entries: &[(usize, u16)]) -> [u16; N] {
        let mut t = [0u16; N];
        for (symbol, f) in entries {
            t[*symbol] = *f;
        }
        t
    }

    /// The block the tests below decode: eight literals from two literal symbols, `a` and `b`,
    /// each holding half the states so each state reads one bit; then one command, a literal
    /// length of 8, a match length of 4, and a distance whose one extra bit is the command
    /// stream's top bit.
    fn the_block(raw: u32, l_symbol: usize, d_symbol: usize) -> Vec<u8> {
        let l: [u16; L_SYMBOLS] = table(&[(l_symbol, 64)]);
        let m: [u16; M_SYMBOLS] = table(&[(4, 64)]);
        let d: [u16; D_SYMBOLS] = table(&[(d_symbol, 256)]);
        let lit: [u16; LITERAL_SYMBOLS] =
            table(&[(usize::from(b'a'), 512), (usize::from(b'b'), 512)]);
        // A state below 512 is `a`; with every bit zero, the next state is twice the state's
        // place within its symbol. So 300 is `a` then `b`, 600 `b` then `a`, 0 `a` twice,
        // 812 `b` twice, and the four decoders taking turns give `ababbaab`.
        packed_block(
            raw,
            8,
            1,
            [300, 600, 0, 812],
            (&l, &m, &d, &lit),
            &[0; 7],
            &[0, 0, 0, 0, 0, 0, 0x80],
        )
    }

    fn decode(stream: &[u8], room: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; room];
        let n = decompress(stream, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn ended(mut stream: Vec<u8>) -> Vec<u8> {
        stream.extend_from_slice(b"bvx$");
        stream
    }

    #[test]
    fn raw_blocks_are_their_bytes_and_the_stream_ends_at_its_end_block() {
        let mut stream = b"bvx-".to_vec();
        stream.extend_from_slice(&5u32.to_le_bytes());
        stream.extend_from_slice(b"hello");
        stream.extend_from_slice(b"bvx-\x03\0\0\0abc");
        let mut stream = ended(stream);
        stream.extend_from_slice(b"anything after the end");
        assert_eq!(decode(&stream, 16), Ok(b"helloabc".to_vec()));
        assert_eq!(decode(b"bvx$", 4), Ok(Vec::new()));
    }

    #[test]
    fn an_lzvn_block_reaches_back_into_the_blocks_before_it() {
        // "abcd" raw, then an LZVN block of a match of four at distance four.
        let mut stream = b"bvx-\x04\0\0\0abcd".to_vec();
        let lzvn = [0x08, 0x04, 0x06, 0, 0, 0, 0, 0, 0, 0];
        stream.extend_from_slice(b"bvxn");
        stream.extend_from_slice(&4u32.to_le_bytes());
        stream.extend_from_slice(&(lzvn.len() as u32).to_le_bytes());
        stream.extend_from_slice(&lzvn);
        assert_eq!(decode(&ended(stream.clone()), 16), Ok(b"abcdabcd".to_vec()));
        // A block whose stream is not the length it records is refused.
        let len_at = 12 + 8;
        stream[len_at] = 11;
        stream.push(0);
        assert!(matches!(
            decode(&ended(stream), 16),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn a_packed_block_decodes_its_literals_and_then_its_commands() {
        // "ababbaab", then four bytes from five back, the distance's extra bit being one.
        let stream = ended(the_block(12, 8, 4));
        assert_eq!(decode(&stream, 12), Ok(b"ababbaabbbaa".to_vec()));
        // Room for less than the block produces is an overrun.
        assert!(matches!(decode(&stream, 11), Err(Error::Overrun { .. })));
    }

    #[test]
    fn a_distance_of_zero_repeats_the_one_before() {
        // Two commands, each a literal length of 4 and a match length of 4. The distance
        // decoder has two symbols, 0 and 3, each holding half its states and so reading a bit;
        // it starts in state 138, symbol 3, and with every bit zero moves to state 20, symbol
        // 0, which repeats the distance of 3. The second command takes a byte the first read
        // left, so each payload has one past the seven the first read takes.
        let l: [u16; L_SYMBOLS] = table(&[(4, 64)]);
        let m: [u16; M_SYMBOLS] = table(&[(4, 64)]);
        let d: [u16; D_SYMBOLS] = table(&[(0, 128), (3, 128)]);
        let lit: [u16; LITERAL_SYMBOLS] =
            table(&[(usize::from(b'a'), 512), (usize::from(b'b'), 512)]);
        let mut block = packed_block(
            16,
            8,
            2,
            [300, 600, 0, 812],
            (&l, &m, &d, &lit),
            &[0; 8],
            &[0; 8],
        );
        // The distance decoder's first state, in the third packed word.
        let at = 24;
        let mut v2 = u64::from_le_bytes(block[at..at + 8].try_into().expect("a word"));
        v2 |= 138 << 52;
        block[at..at + 8].copy_from_slice(&v2.to_le_bytes());
        // "abab", four from three back, "baab", four from three back again.
        assert_eq!(decode(&ended(block), 16), Ok(b"ababbabbbaabaaba".to_vec()));
    }

    #[test]
    fn a_packed_block_is_held_to_what_it_records() {
        // A block recording a byte more than it produces.
        assert!(matches!(
            decode(&ended(the_block(13, 8, 4)), 16),
            Err(Error::Malformed { .. })
        ));
        // A literal length of 15 copies more literals than the block holds.
        assert!(matches!(
            decode(&ended(the_block(19, 15, 4)), 32),
            Err(Error::Malformed { .. })
        ));
        // Distance symbol 8 is 12 and two extra bits, here 0b10: fourteen back from the eighth
        // byte reaches before the first.
        assert!(matches!(
            decode(&ended(the_block(12, 8, 8)), 16),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn streams_of_every_block_changed_a_byte_at_a_time_refuse_or_fit() {
        // Raw blocks, an LZVN block reaching into one before it, and a packed block, each with
        // its end block: a table, a state, a payload and a header length are each bytes of one.
        let mut raw_then_lzvn = b"bvx-\x04\0\0\0abcd".to_vec();
        let lzvn = [0x08, 0x04, 0x06, 0, 0, 0, 0, 0, 0, 0];
        raw_then_lzvn.extend_from_slice(b"bvxn");
        raw_then_lzvn.extend_from_slice(&4u32.to_le_bytes());
        raw_then_lzvn.extend_from_slice(&(lzvn.len() as u32).to_le_bytes());
        raw_then_lzvn.extend_from_slice(&lzvn);
        for stream in [ended(raw_then_lzvn), ended(the_block(12, 8, 4))] {
            let whole = decode(&stream, 64).expect("the stream decodes");
            crate::compress::sweep_changes_of(&stream, whole.len() + 16, decompress);
        }
    }

    #[test]
    fn a_block_this_decoder_does_not_read_is_refused_by_what_it_is() {
        for stream in [
            &b"bvx1\0\0\0\0"[..],
            b"bvx9",
            b"bvx-\x09\0\0\0short",
            b"bvx-\x01\0\0\0x",
        ] {
            assert!(
                matches!(decode(stream, 16), Err(Error::Malformed { .. })),
                "{stream:?}"
            );
        }
        let mut too_many = vec![0u16; L_SYMBOLS];
        too_many[0] = 65;
        assert!(transitions(L_STATES, &too_many).is_err());
    }

    #[test]
    fn a_command_state_outside_its_alphabet_is_refused_at_the_header() {
        // Each command decoder's starting state set one past its last, in a block that decodes
        // otherwise, and so whether or not a command would read it.
        assert!(decode(&ended(the_block(12, 8, 4)), 16).is_ok());
        for (at, past) in [(32, L_STATES), (42, M_STATES), (52, D_STATES)] {
            let mut block = the_block(12, 8, 4);
            let v2 = get_u64(&block, 24) | (past as u64) << at;
            block[24..32].copy_from_slice(&v2.to_le_bytes());
            assert!(
                matches!(decode(&ended(block), 16), Err(Error::Malformed { .. })),
                "state at bit {at}"
            );
        }
    }
}
