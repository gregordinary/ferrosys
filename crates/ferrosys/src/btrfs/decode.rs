//! How this format frames a compressed extent, and what bounds one.
//!
//! [`crate::compress`] undoes a *stream*. This module is everything between an extent record
//! and one of those: how many streams an extent's bytes are cut into, where each begins, and
//! what a well-formed one may claim. All of that is btrfs's own, which is why it is here and
//! not there.
//!
//! This module is pure — bytes in, bytes out, no I/O.
//!
//! # What bounds a compressed extent
//!
//! The format compresses in units of at most [`MAX_UNCOMPRESSED`] bytes and stores at most
//! [`MAX_COMPRESSED`], so an extent record claiming to expand to more than the first is not one
//! any implementation of this format wrote. That matters more here than the number does: the
//! expanded length is the size of a buffer, and it is a number the *image* supplied. Held to
//! the format's own limit, the worst a crafted record can cost is a buffer of that size.
//!
//! # Two of the three algorithms have no framing at all
//!
//! zlib and zstd store one stream per extent and nothing around it. LZO stores a length, then
//! a series of length-prefixed streams, each expanding to at most one sector — which exists so
//! that a reader can start anywhere in a large extent, and which means a reader must follow the
//! rule about where a segment header may sit:
//!
//! ```text
//! 0x0000  | total len |  seg len  | stream ...                       |
//! ...
//! 0x0ff0  |  seg len  | stream ...                             |0 0 0|
//! 0x1000  |  seg len  | stream ...                                   |
//!                                                               ^^^^^ padding
//! ```
//!
//! **A segment header never straddles a sector.** Where fewer than four bytes are left in the
//! sector a header would begin in, the writer pads to the next sector and puts it there. A
//! reader that walked segment to segment without that rule reads three padding zeros as the
//! start of a length and every segment after it at the wrong offset.

use super::ondisk::Compression;
use crate::compress::{self, Algorithm};

/// The most bytes of a file one compressed extent covers.
///
/// The bound this crate holds a record's expanded length to, because that length decides the
/// size of a buffer and comes from the image. A record claiming more is refused rather than
/// allocated for.
pub(crate) const MAX_UNCOMPRESSED: u64 = 128 << 10;

/// The most bytes of the volume one compressed extent occupies.
pub(crate) const MAX_COMPRESSED: u64 = 128 << 10;

/// Bytes of the length prefix the LZO framing puts before its total and before each segment.
const LZO_LEN: usize = 4;

/// Which algorithm a record's compression byte names, or `None` where the byte says the bytes
/// on the volume are the file's own.
///
/// A value the format has not defined is [`Some`] of nothing this build decodes, so it is
/// reported as an encoding rather than read as uncompressed — which is the difference between
/// declining a file and handing back the wrong bytes for it.
pub(crate) const fn algorithm(compression: Compression) -> Option<Option<Algorithm>> {
    match compression {
        Compression::None => None,
        Compression::Zlib => Some(Some(Algorithm::Zlib)),
        Compression::Lzo => Some(Some(Algorithm::Lzo)),
        Compression::Zstd => Some(Some(Algorithm::Zstd)),
        Compression::Unknown(_) => Some(None),
    }
}

/// Undo one extent's worth of compressed bytes into `out`, which the caller sized from the
/// record's expanded length.
///
/// `sector_size` is the filesystem's, and only the LZO framing reads it: it is what decides
/// where a segment header may sit and how much one segment may expand to.
///
/// # Errors
///
/// Whatever the stream or the framing turns out to be wrong about.
pub(crate) fn decode(
    algorithm: Algorithm,
    input: &[u8],
    out: &mut [u8],
    sector_size: u32,
) -> Result<usize, compress::Error> {
    match algorithm {
        // One stream, and the extent's bytes are all of it.
        Algorithm::Zlib | Algorithm::Zstd => compress::decompress(algorithm, input, out),
        Algorithm::Lzo => lzo_segments(input, out, sector_size),
    }
}

/// Undo the segmented form LZO extents take, concatenating what the segments expand to.
///
/// The three rules that make this more than a loop, each of which a reader gets wrong
/// silently: the total length includes its own prefix, a segment expands to at most one
/// sector, and a header never straddles a sector.
fn lzo_segments(input: &[u8], out: &mut [u8], sector_size: u32) -> Result<usize, compress::Error> {
    let malformed = |fault| compress::Error::Malformed {
        algorithm: Algorithm::Lzo,
        fault,
    };
    let sector = sector_size as usize;
    let total =
        length_at(input, 0).ok_or(malformed("the extent is shorter than its own length"))?;
    if total > input.len() || total < LZO_LEN {
        return Err(malformed("the extent's length is not the length it has"));
    }

    let mut read = LZO_LEN;
    let mut written = 0;
    while read < total {
        // Where a header may sit. Fewer than four bytes left in this sector means the writer
        // padded to the next one, so that is where the header is.
        let left_in_sector = sector - (read % sector);
        if left_in_sector < LZO_LEN {
            read += left_in_sector;
            if read >= total {
                break;
            }
        }
        let segment =
            length_at(input, read).ok_or(malformed("a segment header runs past the extent"))?;
        read += LZO_LEN;
        let stream = input
            .get(read..read.saturating_add(segment))
            .ok_or(malformed("a segment runs past the extent"))?;

        // One sector at most, whatever the record's total says: a segment that expanded
        // further would be one the format could not have written, and the room it is given
        // here is what makes that true rather than merely expected.
        let room = out
            .len()
            .checked_sub(written)
            .filter(|left| *left > 0)
            .ok_or(compress::Error::Overrun {
                algorithm: Algorithm::Lzo,
                expected: out.len(),
            })?
            .min(sector);
        let produced =
            compress::decompress(Algorithm::Lzo, stream, &mut out[written..written + room])?;
        written += produced;
        read += segment;
    }
    Ok(written)
}

/// The little-endian length prefix at `at`, or [`None`] where the input does not hold one.
///
/// The presence check is here rather than in the accessor because the offset is one this
/// module computes from the image's own numbers: every prefix past the first is at a position
/// the previous segment's length put it, so a length that runs off the end is the ordinary way
/// a crafted extent goes wrong rather than an unexpected one.
fn length_at(input: &[u8], at: usize) -> Option<usize> {
    let end = at.checked_add(LZO_LEN)?;
    if end > input.len() {
        return None;
    }
    Some(crate::bytes::get_u32(input, at) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bounds are the format's own, and a change to either is a change to what this crate
    /// will allocate for a record it has not verified.
    #[test]
    fn the_extent_bounds_are_the_ones_the_format_compresses_in() {
        assert_eq!(MAX_UNCOMPRESSED, 131_072);
        assert_eq!(MAX_COMPRESSED, 131_072);
    }

    #[test]
    fn an_undefined_compression_byte_is_an_encoding_rather_than_no_encoding() {
        // The distinction the return type exists for. `None` means the bytes on the volume
        // are the file's; `Some(None)` means they are encoded somehow and this build knows
        // neither how nor what to call it. Reading the second as the first would hand back a
        // compressed extent as though it were the file.
        assert!(algorithm(Compression::None).is_none());
        assert_eq!(algorithm(Compression::Zlib), Some(Some(Algorithm::Zlib)));
        assert_eq!(algorithm(Compression::Lzo), Some(Some(Algorithm::Lzo)));
        assert_eq!(algorithm(Compression::Zstd), Some(Some(Algorithm::Zstd)));
        assert_eq!(algorithm(Compression::Unknown(9)), Some(None));
    }

    #[cfg(feature = "lzo")]
    mod framing {
        use super::*;

        /// Frame `streams` as this format frames the segments of one extent, at `sector`.
        ///
        /// The writer's half of the rule under test, written out here because nothing in this
        /// crate writes a compressed extent: a reader is held to what a *writer* produces, so
        /// the fixture has to be one.
        fn frame(streams: &[Vec<u8>], sector: usize) -> Vec<u8> {
            let mut out = vec![0u8; LZO_LEN];
            for stream in streams {
                // The rule itself: a header never straddles a sector, so where fewer than
                // four bytes are left the writer pads to the next one.
                if sector - (out.len() % sector) < LZO_LEN {
                    let pad = sector - (out.len() % sector);
                    out.resize(out.len() + pad, 0);
                }
                out.extend_from_slice(&(stream.len() as u32).to_le_bytes());
                out.extend_from_slice(stream);
            }
            let total = out.len() as u32;
            out[..LZO_LEN].copy_from_slice(&total.to_le_bytes());
            out
        }

        fn compressed(data: &[u8]) -> Vec<u8> {
            lzokay::compress::compress(data).expect("a second implementation compresses it")
        }

        #[test]
        fn segments_concatenate_to_the_extent_the_writer_cut_up() {
            // Three sectors' worth, in the three-sector shape a writer produces: one segment
            // per sector of the *uncompressed* data, each an independent stream.
            let sector = 4096usize;
            let parts: Vec<Vec<u8>> = (0..3)
                .map(|which| {
                    (0..sector)
                        .map(|at| ((at / 64) + which * 7) as u8)
                        .collect()
                })
                .collect();
            let framed = frame(
                &parts.iter().map(|p| compressed(p)).collect::<Vec<_>>(),
                sector,
            );
            let want: Vec<u8> = parts.concat();

            let mut out = vec![0u8; want.len()];
            assert_eq!(
                decode(Algorithm::Lzo, &framed, &mut out, sector as u32),
                Ok(want.len())
            );
            assert_eq!(out, want);
        }

        #[test]
        fn a_segment_header_is_read_where_the_padding_puts_it() {
            // The rule that fails silently. Streams sized so that the second header would
            // begin two bytes before a sector ends: a reader without the rule reads the two
            // padding zeros and the first two bytes of the real header as a length, and every
            // segment after it lands somewhere else.
            let sector = 512usize;
            let mut streams = Vec::new();
            let mut length = LZO_LEN;
            // Fill the first sector to within two bytes of its end.
            while sector - (length % sector) > LZO_LEN + 2 {
                let part = vec![0xa7u8; 64];
                let stream = compressed(&part);
                length += LZO_LEN + stream.len();
                streams.push((part, stream));
            }
            let tail = vec![0x5eu8; 96];
            streams.push((tail.clone(), compressed(&tail)));

            let framed = frame(
                &streams.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>(),
                sector,
            );
            // The fixture is only a fixture if the padding is really there.
            assert!(
                framed.len() > sector,
                "the framing did not cross a sector: {} bytes",
                framed.len()
            );
            let want: Vec<u8> = streams.iter().flat_map(|(p, _)| p.clone()).collect();
            let mut out = vec![0u8; want.len()];
            assert_eq!(
                decode(Algorithm::Lzo, &framed, &mut out, sector as u32),
                Ok(want.len())
            );
            assert_eq!(out, want);
        }

        /// One compressed extent a Linux kernel wrote, taken off a filesystem it had mounted
        /// with `compress-force=lzo`.
        ///
        /// The only kernel-written compressed bytes this crate carries, and the reason it
        /// carries any: no host tool compresses. The pinned `mkfs.btrfs` never compresses what
        /// it copies in and is built without two of the three libraries, so every fixture
        /// above this one is framed by a writer in this file — which is a decoder checked
        /// against its own author's reading of the format. This one is not.
        ///
        /// It is 1796 bytes framing 32 segments that expand to the format's whole compression
        /// unit. What it does *not* reach is the padding rule, its framing being shorter than
        /// one sector; that stays a claim the test above makes against a written framing, and
        /// one a mounted filesystem makes, where the same rule is met twenty times over per
        /// extent.
        const KERNEL_LZO_EXTENT: &[u8] = include_bytes!("fixtures/lzo-extent.bin");

        #[test]
        fn an_extent_a_kernel_compressed_expands_to_what_it_wrote() {
            // The bytes the file held: the tier's own repeating unit, cut wherever the
            // compression unit falls. Stated as the rule rather than as 128 KiB of committed
            // bytes, which is what makes the fixture 1796 bytes rather than a hundred times
            // that.
            let unit = b"ferrosys-btrfs\n";
            let mut want = Vec::with_capacity(128 << 10);
            while want.len() < 128 << 10 {
                want.extend_from_slice(unit);
            }
            want.truncate(128 << 10);

            let mut out = vec![0u8; want.len()];
            assert_eq!(
                decode(Algorithm::Lzo, KERNEL_LZO_EXTENT, &mut out, 4096),
                Ok(want.len())
            );
            assert_eq!(out, want);
        }

        #[test]
        fn a_framing_that_claims_more_than_it_holds_is_refused() {
            let sector = 4096usize;
            let framed = frame(&[compressed(b"ferrosys")], sector);
            let mut out = [0u8; 64];

            // A total past the bytes there are.
            let mut wrong = framed.clone();
            wrong[..LZO_LEN].copy_from_slice(&(framed.len() as u32 + 1).to_le_bytes());
            assert!(decode(Algorithm::Lzo, &wrong, &mut out, sector as u32).is_err());

            // A segment past the bytes there are.
            let mut wrong = framed.clone();
            wrong[LZO_LEN..LZO_LEN * 2].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(decode(Algorithm::Lzo, &wrong, &mut out, sector as u32).is_err());

            // And an extent too short to hold its own length.
            assert!(decode(Algorithm::Lzo, &[0, 0], &mut out, sector as u32).is_err());
        }

        #[test]
        fn arbitrary_bytes_are_framing_that_refuses_or_fits() {
            // The same sweep the stream decoder has, one layer out: the framing reads three
            // lengths out of the image, and each is a number that has to be checked against
            // what is there rather than trusted.
            crate::compress::sweep_arbitrary_bytes(7, |bytes, out| {
                decode(Algorithm::Lzo, bytes, out, 512)
            });
        }
    }
}
