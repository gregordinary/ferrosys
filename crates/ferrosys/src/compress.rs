//! Undoing the three encodings a filesystem stores a run of bytes in fewer of them.
//!
//! A format that compresses records, per run of bytes, which algorithm produced them and how
//! many bytes they expand to. Everything above this module knows that much and no more: it
//! hands over the bytes on the volume and a buffer the size the record declared, and what
//! comes back is the file's own bytes or a refusal naming what could not be undone.
//!
//! This module is pure — bytes in, bytes out, no I/O — and it is at the crate root rather than
//! inside a family for the reason [`crc32c`](crate::crc32c()) is: an encoding is a property of a
//! run of bytes rather than of the format around it, and the same three algorithms appear in
//! more than one filesystem. What is *not* here is how a format frames them — how many streams
//! one extent is cut into, and where each begins — which is the format's own and belongs to
//! it.
//!
//! # One signature, three algorithms, and a bound that is the caller's
//!
//! Each decoder fills a caller-supplied slice and reports how much of it was filled. That
//! shape is deliberate: the expected length is a number the *image* supplied, so the only
//! place it can be judged is above this module, where what the format allows is known. A
//! decoder here never allocates on the strength of it, and so cannot be asked for a gibibyte
//! by a record claiming one.
//!
//! Producing fewer bytes than the buffer holds is not an error here, and may be one to the
//! caller: what it means is that the stream ended early, and whether that is a fault depends
//! on what the caller asked for. So the comparison, and the name for what it found, are the
//! caller's.
//!
//! # Each algorithm is a feature, and a build without one says so
//!
//! [`Algorithm`] names all three whatever a build carries, because *recognizing* an encoding
//! and *undoing* it are different questions and a reader has to answer the first either way: a
//! file this build cannot decode is reported as one it cannot decode, naming the algorithm,
//! rather than as a file whose bytes are what the volume holds.

/// Which encoding a run of bytes on a volume is in.
///
/// Every variant exists in every build. What a feature decides is whether
/// [`decompress`] can undo it, which [`Algorithm::available`] answers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Algorithm {
    /// DEFLATE, as `zlib` frames it.
    Zlib,
    /// LZO1X.
    Lzo,
    /// Zstandard.
    Zstd,
}

impl Algorithm {
    /// The name this algorithm is known by, which is the word a refusal names it with.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Algorithm::Zlib => "zlib",
            Algorithm::Lzo => "lzo",
            Algorithm::Zstd => "zstd",
        }
    }

    /// Whether this build can undo this encoding.
    ///
    /// A caller asks before it reaches for bytes it would have to refuse: a filesystem whose
    /// *feature word* says some extent is LZO-compressed is one a build without that decoder
    /// should decline as a whole, rather than open and fail partway through a walk.
    pub(crate) const fn available(self) -> bool {
        match self {
            Algorithm::Zlib => cfg!(feature = "zlib"),
            Algorithm::Lzo => cfg!(feature = "lzo"),
            Algorithm::Zstd => cfg!(feature = "zstd"),
        }
    }
}

/// Why a run of compressed bytes could not be turned back into the bytes it stands for.
///
/// The three are kept apart because they mean different things about the image: a stream this
/// build has no decoder for is a filesystem that is *fine* and beyond this build, and a stream
/// that does not decode, or that decodes to more than the record framing it declared, is
/// damage.
///
/// A stream that decodes to *fewer* bytes than the record declared is not here, and that is
/// deliberate: what a caller asked for decides whether a short run is a fault, so it is the
/// caller that compares the two and names it in its own terms.
// A build carrying no decoder constructs only `Unavailable` — which is the honest state of
// such a build rather than an oversight, so the other two are allowed to go unbuilt there.
#[cfg_attr(
    not(any(feature = "zlib", feature = "lzo", feature = "zstd")),
    allow(dead_code)
)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum Error {
    /// This build carries no decoder for the algorithm.
    #[error("{} is an algorithm this build does not decode", .0.name())]
    Unavailable(Algorithm),
    /// The stream is not a well-formed one of its kind.
    #[error("the {} stream does not decode: {fault}", .algorithm.name())]
    #[non_exhaustive]
    Malformed {
        /// Which encoding it claimed to be.
        algorithm: Algorithm,
        /// What was wrong with it.
        fault: &'static str,
    },
    /// The stream expands past the buffer it was given, so the record's declared length is
    /// not the length of what it holds.
    #[error(
        "the {} stream expands past the {expected} bytes the record declares",
        .algorithm.name()
    )]
    #[non_exhaustive]
    Overrun {
        /// Which encoding it was.
        algorithm: Algorithm,
        /// The buffer's length, which is what the record said the run expands to.
        expected: usize,
    },
}

/// Undo one stream into `out`, returning how many bytes it produced.
///
/// `out` is sized by the caller from what the format recorded, and it bounds the work: a
/// stream that would expand past it is [`Error::Overrun`] rather than an allocation.
///
/// # Errors
///
/// [`Error::Unavailable`] where this build carries no decoder for `algorithm`, and otherwise
/// whatever the stream turns out to be wrong about.
// A build carrying none of the three reaches only the last arm, which needs neither the bytes
// nor the room. The names stay, because they are the signature every build offers.
#[cfg_attr(
    not(any(feature = "zlib", feature = "lzo", feature = "zstd")),
    allow(unused_variables)
)]
pub(crate) fn decompress(
    algorithm: Algorithm,
    input: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    match algorithm {
        #[cfg(feature = "zlib")]
        Algorithm::Zlib => zlib::decompress(input, out),
        #[cfg(feature = "lzo")]
        Algorithm::Lzo => lzo::decompress(input, out),
        #[cfg(feature = "zstd")]
        Algorithm::Zstd => zstd::decompress(input, out),
        // Whichever of the three this build did not take. Reached only through a caller that
        // did not ask `available` first, which is a caller reporting a file it cannot read
        // rather than one refusing a filesystem it cannot open.
        #[allow(unreachable_patterns)]
        other => Err(Error::Unavailable(other)),
    }
}

#[cfg(feature = "zlib")]
mod zlib {
    use super::{Algorithm, Error};

    /// Undo one zlib-framed DEFLATE stream into `out`.
    ///
    /// The whole stream at once rather than in pieces: a compressed run is bounded by what
    /// the format allows an extent to expand to, which is measured in kibibytes.
    pub(super) fn decompress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        use miniz_oxide::inflate::TINFLStatus;

        // `zlib_header = true` because the format stores the two-byte wrapper, and the
        // trailing Adler-32 is checked rather than ignored: it costs nothing here and it is a
        // second opinion on bytes a filesystem's own checksum has already covered.
        miniz_oxide::inflate::decompress_slice_iter_to_slice(
            out,
            core::iter::once(input),
            true,
            false,
        )
        .map_err(|status| match status {
            // The decoder stops with this exactly where the output buffer filled, which for
            // this caller means the record's declared length is short of what the stream
            // expands to.
            TINFLStatus::HasMoreOutput => Error::Overrun {
                algorithm: Algorithm::Zlib,
                expected: out.len(),
            },
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                Error::Malformed {
                    algorithm: Algorithm::Zlib,
                    fault: "the stream ends mid-symbol",
                }
            }
            TINFLStatus::BadParam => Error::Malformed {
                algorithm: Algorithm::Zlib,
                fault: "the stream's own parameters are not ones the format defines",
            },
            TINFLStatus::Adler32Mismatch => Error::Malformed {
                algorithm: Algorithm::Zlib,
                fault: "the stream's own checksum does not cover what it decoded to",
            },
            _ => Error::Malformed {
                algorithm: Algorithm::Zlib,
                fault: "the stream is not well-formed",
            },
        })
    }
}

#[cfg(feature = "zstd")]
mod zstd {
    use std::io::Read as _;

    use super::{Algorithm, Error};

    /// The smallest window the Zstandard format defines, which floors the clamp below.
    const MIN_WINDOW: u64 = 1 << 10;

    /// Undo one Zstandard frame into `out`.
    ///
    /// Read into the buffer rather than to the end of the stream, and one byte past it: what
    /// distinguishes a frame that fills the record exactly from one that expands past it is
    /// whether anything follows, and a decoder asked only for `out.len()` bytes cannot say.
    pub(super) fn decompress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let malformed = |fault| Error::Malformed {
            algorithm: Algorithm::Zstd,
            fault,
        };
        // A frame declares its own window, and the decoder allocates that declaration before
        // producing a byte — the one number in the stream that could otherwise buy an
        // allocation this module's contract says no image-supplied number buys. It is clamped
        // to the caller's buffer: a stream never needs a window past what it decodes to, and
        // an encoder that knows its input sizes the window down to the input's next power of
        // two, so no frame a real writer produces is refused. The format's own floor is kept
        // for the smallest buffers.
        let window_cap = (out.len() as u64).next_power_of_two().max(MIN_WINDOW);
        let mut decoder =
            ruzstd::decoding::StreamingDecoder::new_with_max_window_size(input, window_cap)
                .map_err(|error| match error {
                    ruzstd::decoding::errors::FrameDecoderError::WindowSizeTooBig { .. } => {
                        malformed("the frame declares a window larger than what it decodes into")
                    }
                    _ => malformed("the frame header is not one the format defines"),
                })?;

        let mut filled = 0;
        while filled < out.len() {
            match decoder.read(&mut out[filled..]) {
                Ok(0) => return Ok(filled),
                Ok(n) => filled += n,
                Err(_) => return Err(malformed("the frame does not decode")),
            }
        }
        // One more byte, into a buffer of its own. Anything at all here is a frame longer
        // than the record says it is.
        let mut past = [0u8; 1];
        match decoder.read(&mut past) {
            Ok(0) => Ok(filled),
            Ok(_) => Err(Error::Overrun {
                algorithm: Algorithm::Zstd,
                expected: out.len(),
            }),
            Err(_) => Err(malformed("the frame does not decode")),
        }
    }
}

#[cfg(feature = "lzo")]
pub(crate) mod lzo;

/// Drive `decode` over arbitrary bytes and hold it to the one property every layer of this
/// has: whatever it is handed, it either produces bytes inside the buffer it was given or
/// refuses.
///
/// Shared because there is more than one layer to hold to it — a stream, and the framing that
/// cuts an extent into streams — and each reads lengths out of the image that a decoder must
/// check rather than trust. `salt` moves the generator, so two callers sweep different inputs
/// rather than the same ones twice.
///
/// Deterministic and cheap, so it runs on every `cargo test` rather than only under a fuzzer.
/// The buffer is longer than the room offered and the tail is a fixed byte, which is what
/// turns "wrote past the end" from a memory fault into an assertion.
///
/// Compiled with any algorithm whose decoder sweeps: each of the three streams runs it over
/// its own decode, and the LZO framing runs it a second time over the segmenting around the
/// stream.
#[cfg(all(test, any(feature = "lzo", feature = "zlib", feature = "zstd")))]
pub(crate) fn sweep_arbitrary_bytes<E>(
    salt: u32,
    mut decode: impl FnMut(&[u8], &mut [u8]) -> Result<usize, E>,
) {
    const GUARD: u8 = 0xee;
    for seed in 0..2048u32 {
        let mut bytes = Vec::new();
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(salt);
        for _ in 0..(seed as usize % 160) + 1 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            bytes.push((x >> 16) as u8);
        }
        let mut out = [GUARD; 512];
        let room = out.len() - 64;
        if let Ok(produced) = decode(&bytes, &mut out[..room]) {
            assert!(
                produced <= room,
                "seed {seed} reported {produced} of {room}"
            );
        }
        assert!(
            out[room..].iter().all(|&b| b == GUARD),
            "seed {seed} wrote past the buffer it was given"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_algorithm_is_named_whether_or_not_this_build_decodes_it() {
        // Recognizing an encoding and undoing it are different questions, and a build that
        // answers only the second cannot tell a caller what it is declining.
        for (algorithm, name) in [
            (Algorithm::Zlib, "zlib"),
            (Algorithm::Lzo, "lzo"),
            (Algorithm::Zstd, "zstd"),
        ] {
            assert_eq!(algorithm.name(), name);
            // And the refusal a build without the decoder gives names it too.
            assert_eq!(
                Error::Unavailable(algorithm).to_string(),
                format!("{name} is an algorithm this build does not decode")
            );
        }
    }

    #[test]
    fn an_algorithm_this_build_does_not_carry_is_refused_rather_than_attempted() {
        // The one property this dispatch has in every configuration: what it will not do is
        // decode a stream with the wrong decoder. Whichever of the three is absent here
        // reports itself absent, and whichever are present do not.
        for algorithm in [Algorithm::Zlib, Algorithm::Lzo, Algorithm::Zstd] {
            let mut out = [0u8; 8];
            let refused = decompress(algorithm, b"", &mut out);
            assert_eq!(
                matches!(refused, Err(Error::Unavailable(_))),
                !algorithm.available(),
                "{algorithm:?} reported itself {} and answered {refused:?}",
                if algorithm.available() {
                    "available"
                } else {
                    "unavailable"
                }
            );
        }
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn a_zlib_stream_decodes_to_what_it_stands_for() {
        // A stream produced outside this crate: the bytes below are what `python3 -c
        // "import zlib; zlib.compress(b'ferrosys' * 8, 9)"` emits, recorded here so the
        // decoder is held against an encoder it shares no code with.
        const STREAM: &[u8] = &[
            0x78, 0xda, 0x4b, 0x4b, 0x2d, 0x2a, 0xca, 0x2f, 0xae, 0x2c, 0x4e, 0x23, 0x93, 0x06,
            0x00, 0x88, 0x65, 0x1b, 0xe9,
        ];
        let want = b"ferrosys".repeat(8);
        let mut out = vec![0u8; want.len()];
        assert_eq!(
            decompress(Algorithm::Zlib, STREAM, &mut out),
            Ok(want.len())
        );
        assert_eq!(out, want);

        // A buffer one byte short of what the stream expands to: the record's declared
        // length disagreeing with its contents is a refusal, never a short read reported as
        // a whole one.
        let mut small = vec![0u8; want.len() - 1];
        assert!(matches!(
            decompress(Algorithm::Zlib, STREAM, &mut small),
            Err(Error::Overrun { .. })
        ));

        // And bytes that are not a stream at all.
        let mut out = vec![0u8; 64];
        assert!(matches!(
            decompress(Algorithm::Zlib, b"not a stream", &mut out),
            Err(Error::Malformed { .. })
        ));
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn a_zstd_frame_declaring_a_giant_window_is_refused_at_the_header() {
        // Six bytes: the magic, a descriptor saying a window descriptor follows, and that
        // descriptor naming a 64-mebibyte window. The record it would decode into holds four
        // kibibytes, and a stream never needs a window past what it decodes to — so the
        // declaration is refused at the header, before the decoder allocates what it names.
        // The fault names the window specifically: reaching the generic header refusal here
        // would mean the frame was *accepted* at the header and sixty-four mebibytes were
        // bought by six bytes of input.
        const FRAME: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x80];
        let mut out = vec![0u8; 4096];
        assert_eq!(
            decompress(Algorithm::Zstd, FRAME, &mut out),
            Err(Error::Malformed {
                algorithm: Algorithm::Zstd,
                fault: "the frame declares a window larger than what it decodes into",
            })
        );
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn a_zstd_frame_decodes_to_what_it_stands_for() {
        // As above, produced outside this crate: `zstd -19` over the same bytes.
        const FRAME: &[u8] = &[
            0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x40, 0x7d, 0x00, 0x00, 0x48, 0x66, 0x65, 0x72, 0x72,
            0x6f, 0x73, 0x79, 0x73, 0x66, 0x01, 0x00, 0x7c, 0xde, 0x23, 0x80, 0xc5, 0xf4, 0x04,
        ];
        let want = b"ferrosys".repeat(8);
        let mut out = vec![0u8; want.len()];
        assert_eq!(decompress(Algorithm::Zstd, FRAME, &mut out), Ok(want.len()));
        assert_eq!(out, want);

        let mut small = vec![0u8; want.len() - 1];
        assert!(matches!(
            decompress(Algorithm::Zstd, FRAME, &mut small),
            Err(Error::Overrun { .. })
        ));

        let mut out = vec![0u8; 64];
        assert!(matches!(
            decompress(Algorithm::Zstd, b"not a frame at all", &mut out),
            Err(Error::Malformed { .. })
        ));
    }

    // The deterministic never-panic sweeps, one per decoder this build carries: arbitrary
    // bytes either refuse or fit the buffer offered, and nothing is written past it. The
    // hand vectors above pin what a correct stream decodes to; these pin what every other
    // input does. The salts keep the three from sweeping the same bytes.

    #[cfg(feature = "zlib")]
    #[test]
    fn arbitrary_bytes_are_a_zlib_stream_that_refuses_or_fits() {
        sweep_arbitrary_bytes(2, |bytes, out| decompress(Algorithm::Zlib, bytes, out));
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn arbitrary_bytes_are_a_zstd_frame_that_refuses_or_fits() {
        sweep_arbitrary_bytes(3, |bytes, out| decompress(Algorithm::Zstd, bytes, out));
    }
}
