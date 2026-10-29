//! The LZVN, LZFSE and LZBITMAP decoders held to the reference implementations, stream by
//! stream.
//!
//! `ci/build-codec-reference.sh` builds `codec-reference`, a command line over Apple's lzfse
//! project and libzbitmap. The differential has the reference encoders write streams of
//! plaintexts of many shapes, then changes and cuts those streams, and asks both sides to
//! decode every one into the same room. Two rules hold over every case:
//!
//! - where a decoder here returns bytes, the reference decodes the stream to its end and
//!   returns the same bytes. libzbitmap is not Apple's decoder, and this decoder keeps rules
//!   of Apple's that go past it, so for LZBITMAP the rule is the same bytes wherever both
//!   decode;
//! - every stream a reference encoder writes decodes here to its plaintext.
//!
//! A decoder here may refuse a stream the reference decodes: that is the strictness each
//! records, and the counts below are what it comes to over these cases.
//!
//! Run where `FERROSYS_CODEC_DIFFERENTIAL` is set, which the optimized workspace run of CI and
//! of `ci/preflight.sh` sets. Where it is set, `codec-reference` must be on `PATH` at the pin.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use super::{Error, lzbitmap, lzfse, lzvn};
use crate::bytes::get_u32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Codec {
    Lzvn = 1,
    Lzfse = 2,
    Lzbitmap = 3,
}

impl Codec {
    fn decode(self, input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Codec::Lzvn => lzvn::decompress(input, out),
            Codec::Lzfse => lzfse::decompress(input, out),
            Codec::Lzbitmap => lzbitmap::decompress(input, out),
        }
    }
}

/// What the reference answered for one request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    /// Decoded to the stream's end, or encoded, within the room.
    Done,
    Refused,
    /// The room filled before the stream ended.
    Full,
}

struct Request {
    codec: Codec,
    encode: bool,
    room: usize,
    input: Vec<u8>,
}

/// The reference's answer to each of `requests`, in order.
fn ask(requests: &[Request]) -> Vec<(Status, Vec<u8>)> {
    let mut child = Command::new("codec-reference")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("codec-reference runs");
    let mut stdin = child.stdin.take().expect("a pipe");
    let mut stdout = child.stdout.take().expect("a pipe");
    let answers = std::thread::scope(|scope| {
        // Written from a thread of its own, so a full pipe one way never waits on the other.
        scope.spawn(move || {
            for r in requests {
                let mut head = vec![r.codec as u8, u8::from(r.encode)];
                head.extend_from_slice(&u32::try_from(r.room).expect("a room").to_le_bytes());
                head.extend_from_slice(
                    &u32::try_from(r.input.len())
                        .expect("a length")
                        .to_le_bytes(),
                );
                stdin.write_all(&head).expect("a request written");
                stdin.write_all(&r.input).expect("a request written");
            }
        });
        let mut answers = Vec::with_capacity(requests.len());
        for _ in requests {
            let mut head = [0u8; 5];
            stdout.read_exact(&mut head).expect("an answer");
            let n = get_u32(&head, 1) as usize;
            let mut bytes = vec![0u8; n];
            stdout.read_exact(&mut bytes).expect("an answer's bytes");
            let status = match head[0] {
                0 => Status::Done,
                1 => Status::Refused,
                2 => Status::Full,
                other => panic!("codec-reference answered status {other}"),
            };
            answers.push((status, bytes));
        }
        answers
    });
    let status = child.wait().expect("codec-reference ends");
    assert!(status.success(), "codec-reference exited {status}");
    answers
}

/// A deterministic source of numbers, so every run asks the same questions.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// A plaintext of `len` bytes of the shape `kind` names: runs a compressor shortens, bytes it
/// cannot, and the mixtures between.
fn plaintext(rng: &mut Rng, kind: usize, len: usize) -> Vec<u8> {
    const WORDS: &[&[u8]] = &[
        b"the ",
        b"volume ",
        b"extent ",
        b"of ",
        b"a ",
        b"block ",
        b"tree\n",
        b"record ",
        b"node ",
        b"0x1f ",
        b"checksum ",
        b"and ",
    ];
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        match kind % 6 {
            0 => out.push(0),
            1 => out.push(b'a' + (out.len() % 3) as u8),
            2 => out.extend_from_slice(WORDS[rng.below(WORDS.len())]),
            3 => out.push(rng.next() as u8),
            4 => {
                // Text and bytes that do not compress, in runs of a few hundred.
                let run = 1 + rng.below(400);
                if rng.below(2) == 0 {
                    (0..run).for_each(|_| out.push(rng.next() as u8));
                } else {
                    (0..run).for_each(|i| out.push(b"abcdefgh"[i % 8]));
                }
            }
            _ => {
                // A small alphabet, so short matches at every distance.
                out.push(b"xyz"[rng.below(3)]);
            }
        }
    }
    out.truncate(len);
    out
}

/// The lengths a plaintext takes: around every boundary the encoders and the formats change
/// shape at, and some between.
fn lengths(rng: &mut Rng) -> Vec<usize> {
    let mut lens = vec![
        0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 64, 100, 255, 256, 271, 272, 1000, 2048, 4095,
        4096, 4097, 8192, 10_000, 16_383, 16_384, 32_767, 32_768, 32_769, 65_536,
    ];
    lens.extend((0..40).map(|_| rng.below(20_000)));
    lens
}

/// What the differential found, counted.
#[derive(Default, Debug, PartialEq, Eq)]
struct Tally {
    /// Streams a reference encoder wrote.
    encoded: usize,
    /// Cases decoded on both sides.
    cases: usize,
    /// Cases both sides decoded, to the same bytes.
    agreed: usize,
    /// Cases decoded here that the reference also refused or did not finish (LZBITMAP only).
    here_only: usize,
    /// Cases the reference decoded that a decoder here refused, by what it refused them for.
    reference_only: BTreeMap<&'static str, usize>,
}

fn differential(codec: Codec, seed: u64) -> (Tally, Vec<String>) {
    let mut rng = Rng(seed);
    let mut plains = Vec::new();
    for (i, len) in lengths(&mut rng).into_iter().enumerate() {
        for kind in 0..6 {
            plains.push(plaintext(&mut rng, kind + i, len));
        }
    }
    let encodes: Vec<Request> = plains
        .iter()
        .map(|p| Request {
            codec,
            encode: true,
            room: p.len() * 2 + 4096,
            input: p.clone(),
        })
        .collect();
    let streams = ask(&encodes);
    let mut problems = Vec::new();
    let mut tally = Tally::default();
    let mut cases = Vec::new();
    for (plain, (status, stream)) in plains.iter().zip(streams) {
        if status != Status::Done {
            continue;
        }
        tally.encoded += 1;
        let mut out = vec![0u8; plain.len()];
        match codec.decode(&stream, &mut out) {
            Ok(n) if out[..n] == plain[..] => {}
            other => problems.push(format!(
                "{codec:?}: the reference's stream of {} bytes decodes here as {other:?}",
                plain.len()
            )),
        }
        // The stream itself, then changed bytes, then cuts, each into rooms around the
        // plaintext's length.
        let mut variants = vec![stream.clone()];
        let changes = if stream.len() > 4096 { 24 } else { 96 };
        for _ in 0..changes {
            let mut changed = stream.clone();
            let at = rng.below(changed.len());
            changed[at] ^= 1 + rng.below(255) as u8;
            variants.push(changed);
        }
        for _ in 0..8 {
            variants.push(stream[..rng.below(stream.len())].to_vec());
        }
        for input in variants {
            let room = match rng.below(4) {
                0 => plain.len(),
                1 => plain.len().saturating_sub(1),
                2 => plain.len() + 1 + rng.below(64),
                _ => plain.len() * 2 + 16,
            };
            cases.push(Request {
                codec,
                encode: false,
                room,
                input,
            });
        }
    }
    // Bytes the encoder never wrote, behind the opening each stream of the kind has.
    for _ in 0..20_000 {
        let len = 1 + rng.below(600);
        let mut input: Vec<u8> = match codec {
            Codec::Lzvn => Vec::new(),
            Codec::Lzfse => [b"bvxn", b"bvx2", b"bvx-", b"bvx1"][rng.below(4)].to_vec(),
            Codec::Lzbitmap => b"ZBM\x09".to_vec(),
        };
        input.extend((0..len).map(|_| rng.next() as u8));
        cases.push(Request {
            codec,
            encode: false,
            room: 1 + rng.below(4096),
            input,
        });
    }
    let answers = ask(&cases);
    // A stream decoded here that filled the reference's room exactly: the reference stops
    // when its output is full, before it reads what follows, so it is asked again with room
    // to spare and holds to the same rule there.
    let mut again = Vec::new();
    let mut verdicts = Vec::with_capacity(cases.len());
    for (case, (status, theirs)) in cases.iter().zip(answers) {
        let mut out = vec![0u8; case.room];
        let ours = codec.decode(&case.input, &mut out).map(|n| {
            out.truncate(n);
            out
        });
        if let (Ok(here), Status::Full) = (&ours, status)
            && here.len() == case.room
        {
            again.push(Request {
                codec,
                encode: false,
                room: case.room + 4096,
                input: case.input.clone(),
            });
            verdicts.push((case, ours, None));
            continue;
        }
        verdicts.push((case, ours, Some((status, theirs))));
    }
    let mut again = ask(&again).into_iter();
    for (case, ours, answer) in verdicts {
        let (status, theirs) = answer.unwrap_or_else(|| again.next().expect("an answer"));
        tally.cases += 1;
        match (ours, status) {
            (Ok(here), Status::Done) if here == theirs => tally.agreed += 1,
            (Ok(here), Status::Done) => problems.push(format!(
                "{codec:?}: a {}-byte stream into {} bytes: {} bytes here, {} from the \
                 reference, and they differ",
                case.input.len(),
                case.room,
                here.len(),
                theirs.len()
            )),
            (Ok(_), _) if codec == Codec::Lzbitmap => tally.here_only += 1,
            (Ok(here), status) => problems.push(format!(
                "{codec:?}: a {}-byte stream into {} bytes: {} bytes here, and the reference \
                 answered {status:?}",
                case.input.len(),
                case.room,
                here.len()
            )),
            (Err(Error::Malformed { fault, .. }), Status::Done) => {
                *tally.reference_only.entry(fault).or_default() += 1;
            }
            // A block whose header records more than the room, refused before it is decoded.
            (Err(Error::Overrun { .. }), Status::Done) => {
                *tally.reference_only.entry("overrun").or_default() += 1;
            }
            (Err(e), Status::Done) => problems.push(format!(
                "{codec:?}: a {}-byte stream into {} bytes: the reference decoded it, and here \
                 it is {e:?}",
                case.input.len(),
                case.room
            )),
            (Err(_), _) => {}
        }
    }
    (tally, problems)
}

/// The pin `ci/build-codec-reference.sh` builds, which the binary on `PATH` must report.
fn pinned() -> String {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/build-codec-reference.sh");
    let out = Command::new("bash")
        .arg(script)
        .arg("--print-version")
        .output()
        .expect("ci/build-codec-reference.sh answers");
    assert!(
        out.status.success(),
        "ci/build-codec-reference.sh --print-version failed"
    );
    format!(
        "codec-reference ({})",
        String::from_utf8(out.stdout).expect("UTF-8").trim()
    )
}

#[test]
fn every_decoder_agrees_with_its_reference_wherever_it_decodes() {
    if std::env::var_os("FERROSYS_CODEC_DIFFERENTIAL").is_none() {
        return;
    }
    let banner = Command::new("codec-reference")
        .arg("--version")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    let pin = pinned();
    assert!(
        banner.contains(&pin),
        "the decoder differential needs `{pin}` on PATH, built by ci/build-codec-reference.sh; \
         it found {banner:?}"
    );
    let mut problems = Vec::new();
    let mut tallies = Vec::new();
    for (codec, seed) in [
        (Codec::Lzvn, 0x6c7a_766e),
        (Codec::Lzfse, 0x6c7a_6673),
        (Codec::Lzbitmap, 0x7a62_6d39),
    ] {
        let (tally, found) = differential(codec, seed);
        problems.extend(found.into_iter().take(12));
        tallies.push((codec, tally));
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
    // What the pinned references give over these cases: a run that compared less, or whose
    // decoders refuse otherwise, fails here, and the numbers move beside the change that moved
    // them.
    let expected = [
        (
            Codec::Lzvn,
            (426, 55_370, 21_283, 0),
            &[("a match reaches before the start of the output", 16)][..],
        ),
        (
            Codec::Lzfse,
            (426, 57_602, 9_301, 0),
            &[
                ("a bit stream runs past the start of its payload", 5),
                ("a block holding more than a block may", 34),
                ("a block produces more than it records", 98),
                ("a block produces other than it records", 491),
                ("a command copies more literals than the block holds", 1_337),
                ("a state no symbol was given", 100),
                ("overrun", 448),
            ][..],
        ),
        (
            Codec::Lzbitmap,
            (426, 56_018, 12_190, 1),
            &[
                (
                    "a block is longer than the bytes it decodes to stored as they are",
                    2,
                ),
                ("a block's distances are not a run of the block", 22),
                ("a block's distances are not all used", 24),
                ("a block's literals are not a run of the block", 3),
                ("a block's literals are not all used", 185),
                (
                    "a block's selectors do not start between its masks and its table",
                    26,
                ),
                (
                    "a copy reaches into its own step or before the output's start",
                    45,
                ),
                ("a step's distance lies past the block's distances", 13),
                ("a step's literal lies past the block's literals", 598),
            ][..],
        ),
    ];
    for ((codec, tally), (want, counts, refused)) in tallies.iter().zip(expected) {
        assert_eq!(*codec, want);
        assert_eq!(
            (tally.encoded, tally.cases, tally.agreed, tally.here_only),
            counts,
            "{codec:?}: {tally:?}"
        );
        assert_eq!(
            tally.reference_only,
            refused.iter().copied().collect::<BTreeMap<_, _>>(),
            "{codec:?}"
        );
    }
}
