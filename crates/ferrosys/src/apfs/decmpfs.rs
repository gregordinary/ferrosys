//! How a compressed file stores its content: the compression header, and where each
//! compression type keeps the compressed chunks.
//!
//! A file whose BSD flags carry `UF_COMPRESSED` keeps its content outside its data stream. The
//! `com.apple.decmpfs` attribute holds a 16-byte header — the bytes `fpmc`, a compression type,
//! and the content's size — and the content, compressed, either after that header or in the
//! `com.apple.ResourceFork` attribute. None of this is in Apple File System Reference; every
//! rule here is observed, on files `ditto`, `afsctool` and libcompression compressed and on
//! files written with each type's layout, against the content macOS read back from them:
//! macOS 15, 26 and 27 for the layouts of types 3, 4, 7, 8 and 11 to 14, and macOS 14, 15, 26
//! and 27 for types 9 and 10, the attribute's limit, the header, and a type 7 chunk kept raw.
//!
//! - **The header** is 16 bytes: `fpmc` at byte 0, the compression type as a little-endian
//!   32-bit word at byte 4, and the content's size as a little-endian 64-bit word at byte 8. In
//!   every header macOS's own compressor, `ditto --hfsCompression`, wrote on macOS 14, 15 and
//!   26, the file's size sits at byte 8, found by searching the header for it; a number stored
//!   at byte 4 is the one the kernel names as the file's compression type; and the kernel reads
//!   exactly the size the word at byte 8 states, a shorter size reading the content's first
//!   bytes and a longer one padding it with zeros.
//! - The content is cut into chunks of 64 KiB, the last one shorter, and each chunk is one
//!   stream of the type's encoding that decodes to exactly its share of the content.
//! - **Types 3, 7, 9, 11 and 13** keep the content after the header, as one chunk: zlib for 3,
//!   LZVN for 7, LZFSE for 11, LZBITMAP for 13, and for 9 the content itself after a marker.
//!   Every file stored this way holds at most one chunk's content, in an attribute of at most
//!   [`MAX_INLINE`] bytes, header included: macOS does not keep the compressed flag on a file
//!   whose attribute is longer, whatever its type.
//! - **Types 8, 12 and 14** keep the content in the resource fork, LZVN-encoded for 8,
//!   LZFSE-encoded for 12 and LZBITMAP-encoded for 14. The fork opens with one little-endian
//!   32-bit offset per chunk and one more for the end: chunk `i` is the bytes from offset `i`
//!   to offset `i + 1`. The first offset is where the first chunk begins, the table's own
//!   length or past it: `ditto` writes the table's length, `afsctool` leaves room for twice
//!   the entries.
//! - **Type 4** keeps the content in the resource fork laid out as a classic resource fork: a
//!   header of four big-endian words, the first of them where the resource data begins; there,
//!   a big-endian length and then the one resource, a little-endian chunk count followed by
//!   each chunk's offset and length, the offsets counting from the resource's first byte. Each
//!   chunk is a zlib stream.
//! - **Type 10** keeps the content in the resource fork after a table of offsets, as types 8, 12
//!   and 14 do, each chunk being the content itself after a marker.
//! - The marker of types 9 and 10 is the byte `0xCC`, the one value of the 256 that macOS reads
//!   such a chunk with, and the rest of the chunk is its share of the content unchanged. macOS
//!   keeps tens of thousands of its own small files, of 111 bytes or fewer, as type 9.
//! - A zlib chunk whose first byte is `0xFF` holds its content raw after that byte: `afsctool`
//!   stores a one-byte last chunk so, and no zlib stream opens with that byte, which would name
//!   a compression method the encoding reserves.
//! - An LZVN chunk whose first byte is `0x06` holds its content raw after that byte: macOS's
//!   own compressor, `ditto --hfsCompression` on macOS 15 and 26, stores every chunk of type 8
//!   that does not compress so, a whole chunk and a short last one alike, and an LZVN stream
//!   opening with that byte ends at once, having produced nothing; the kernel reads each such
//!   file whole. Type 7's one chunk after the header is read the same way: macOS 14 to 27 read
//!   one opening with `0x06` back as the content that follows.
//!
//! Every other type is refused by its number.
//!
//! This module is pure: it reads bytes and does no I/O.

use crate::bytes::{get_u32, get_u64};
use crate::compress::Algorithm;

/// The bytes a compression header takes.
pub(crate) const HEADER_LEN: usize = 16;

/// The four bytes a compression header opens with.
pub(crate) const MAGIC: &[u8; 4] = b"fpmc";

/// The content one chunk decodes to, every chunk but the last.
pub(crate) const CHUNK: u64 = 64 * 1024;

/// The longest compression attribute, header included, that macOS keeps a file compressed
/// with. On a file whose attribute is a byte longer the compressed flag does not stay set,
/// whatever the type, so a compressed file with a longer one is not one macOS wrote.
pub(crate) const MAX_INLINE: u64 = 3_802;

/// What a compression header records.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Header {
    /// The compression type.
    pub(crate) method: u32,
    /// The content's size in bytes.
    pub(crate) size: u64,
}

impl Header {
    /// Recover a header from an attribute's bytes, or [`None`] where they are not one: `fpmc`
    /// at byte 0, the type as a little-endian 32-bit word at byte 4, and the size as a
    /// little-endian 64-bit word at byte 8. Each place is observed: `ditto --hfsCompression`
    /// writes the file's size at byte 8, the kernel reads exactly the size stored there, and it
    /// names the number stored at byte 4 as the file's compression type.
    pub(crate) fn read_from(bytes: &[u8]) -> Option<Self> {
        (bytes.len() >= HEADER_LEN && &bytes[..4] == MAGIC).then(|| Self {
            method: get_u32(bytes, 4),
            size: get_u64(bytes, 8),
        })
    }
}

/// Where a compression type keeps the compressed chunks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Layout {
    /// After the header in the compression attribute, as the content's one chunk.
    Inline,
    /// In the resource fork, after a table of one offset per chunk and one for the end.
    Offsets,
    /// In the resource fork laid out as a classic resource fork, whose one resource holds a
    /// chunk count and each chunk's offset and length.
    Resource,
}

/// What each chunk of a compression type is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Encoding {
    /// A stream of one of the compression algorithms.
    Compressed(Algorithm),
    /// The chunk's share of the content itself, after the marker [`STORED`].
    Stored,
}

impl Encoding {
    /// Whether this build can read chunks of this encoding.
    pub(crate) const fn available(self) -> bool {
        match self {
            Encoding::Compressed(algorithm) => algorithm.available(),
            Encoding::Stored => true,
        }
    }
}

/// Where compression type `method` keeps its chunks and the encoding each is in, for the types
/// this crate reads.
pub(crate) const fn layout(method: u32) -> Option<(Layout, Encoding)> {
    use Encoding::{Compressed, Stored};
    match method {
        3 => Some((Layout::Inline, Compressed(Algorithm::Zlib))),
        4 => Some((Layout::Resource, Compressed(Algorithm::Zlib))),
        7 => Some((Layout::Inline, Compressed(Algorithm::Lzvn))),
        8 => Some((Layout::Offsets, Compressed(Algorithm::Lzvn))),
        9 => Some((Layout::Inline, Stored)),
        10 => Some((Layout::Offsets, Stored)),
        11 => Some((Layout::Inline, Compressed(Algorithm::Lzfse))),
        12 => Some((Layout::Offsets, Compressed(Algorithm::Lzfse))),
        13 => Some((Layout::Inline, Compressed(Algorithm::Lzbitmap))),
        14 => Some((Layout::Offsets, Compressed(Algorithm::Lzbitmap))),
        _ => None,
    }
}

/// The byte a chunk of types 9 and 10 opens with, before its share of the content.
pub(crate) const STORED: u8 = 0xCC;

/// The byte a zlib chunk stored raw opens with.
const RAW_ZLIB: u8 = 0xFF;

/// The byte an LZVN chunk stored raw opens with: the encoding's end-of-stream instruction. A
/// chunk opening with it is the content that follows, after the header (type 7) and in the
/// resource fork (type 8) alike: macOS 14 to 27 read type 7's so, and macOS 15 and 26 read
/// type 8's that their `ditto --hfsCompression` writes (observed).
const RAW_LZVN: u8 = 0x06;

/// Why a chunk could not be turned into its share of the content.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub(crate) enum ChunkError {
    /// The chunk's stream does not decode.
    #[error(transparent)]
    Decode(#[from] crate::compress::Error),
    /// A chunk of types 9 and 10 opens with another byte than [`STORED`], or is empty.
    #[error("a stored chunk opens with {}, where its marker is {STORED:#04x}", opening(*.0))]
    Unmarked(Option<u8>),
    /// A chunk kept as its content holds more than the content's share.
    #[error(
        "a chunk kept as its content holds {held} bytes, past the {expected} its place gives it"
    )]
    Overrun {
        /// The bytes after the chunk's marker.
        held: usize,
        /// The chunk's share of the content.
        expected: usize,
    },
}

/// The byte a chunk opens with, as a refusal names it.
fn opening(byte: Option<u8>) -> String {
    byte.map_or_else(|| "nothing".into(), |b| format!("{b:#04x}"))
}

/// Decode one chunk stored as `stored` into `out`, and say how many bytes it produced.
pub(crate) fn decode_chunk(
    encoding: Encoding,
    stored: &[u8],
    out: &mut [u8],
) -> Result<usize, ChunkError> {
    match (encoding, stored.split_first()) {
        (Encoding::Stored, Some((&STORED, content))) => kept(content, out),
        (Encoding::Stored, opening) => Err(ChunkError::Unmarked(opening.map(|(b, _)| *b))),
        (Encoding::Compressed(Algorithm::Zlib), Some((&RAW_ZLIB, content))) => kept(content, out),
        // Type 7's chunk after the header and type 8's in the resource fork alike.
        (Encoding::Compressed(Algorithm::Lzvn), Some((&RAW_LZVN, content))) => kept(content, out),
        (Encoding::Compressed(algorithm), _) => {
            Ok(crate::compress::decompress(algorithm, stored, out)?)
        }
    }
}

/// The content a chunk kept after the header holds, where it holds the content itself rather
/// than an encoding of it: type 7's chunk opening with `0x06` and type 9's opening with its
/// marker.
///
/// macOS reads such a chunk to the size the header states, whatever the chunk's length: the
/// content cut there, or followed by zeros up to it (observed, macOS 14 to 27, on type 7's and
/// type 9's).
pub(crate) fn kept_inline(encoding: Encoding, stored: &[u8]) -> Option<&[u8]> {
    match (encoding, stored.split_first()) {
        (Encoding::Stored, Some((&STORED, content)))
        | (Encoding::Compressed(Algorithm::Lzvn), Some((&RAW_LZVN, content))) => Some(content),
        _ => None,
    }
}

/// A chunk kept as its share of the content, `content`, copied into `out`.
fn kept(content: &[u8], out: &mut [u8]) -> Result<usize, ChunkError> {
    let room = out.len();
    let to = out.get_mut(..content.len()).ok_or(ChunkError::Overrun {
        held: content.len(),
        expected: room,
    })?;
    to.copy_from_slice(content);
    Ok(content.len())
}

/// The chunks content of `size` bytes is cut into.
pub(crate) const fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK)
}

/// The content chunk `index` of content of `size` bytes decodes to.
pub(crate) const fn chunk_len(size: u64, index: u64) -> u64 {
    let start = index * CHUNK;
    if start >= size {
        0
    } else if size - start < CHUNK {
        size - start
    } else {
        CHUNK
    }
}

/// Read little-endian word `index` of a run of table entries.
pub(crate) fn word(entries: &[u8], index: usize) -> u64 {
    u64::from(get_u32(entries, 4 * index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_is_its_magic_type_and_size() {
        let mut bytes = b"fpmc".to_vec();
        bytes.extend_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(&204_800u64.to_le_bytes());
        assert_eq!(
            Header::read_from(&bytes),
            Some(Header {
                method: 8,
                size: 204_800
            })
        );
        bytes[0] = b'x';
        assert_eq!(Header::read_from(&bytes), None);
        assert_eq!(Header::read_from(b"fpmc"), None);
    }

    #[test]
    fn content_is_cut_into_whole_chunks_and_a_short_last_one() {
        // 204,800 bytes, as one of the files macOS compressed: three whole chunks and one of
        // 8,192 bytes, so a table of five offsets.
        assert_eq!(chunk_count(204_800), 4);
        assert_eq!(chunk_len(204_800, 0), CHUNK);
        assert_eq!(chunk_len(204_800, 3), 8_192);
        assert_eq!(chunk_len(204_800, 4), 0);
        assert_eq!(chunk_count(131_072), 2);
        assert_eq!(chunk_len(131_072, 1), CHUNK);
        assert_eq!(chunk_count(0), 0);
    }

    const ZLIB: Encoding = Encoding::Compressed(Algorithm::Zlib);

    #[test]
    fn a_zlib_chunk_opening_with_its_marker_is_its_content_raw() {
        let mut out = [0u8; 4];
        assert_eq!(decode_chunk(ZLIB, &[0xFF, b'e'], &mut out), Ok(1));
        assert_eq!(out[0], b'e');
        assert_eq!(
            decode_chunk(ZLIB, &[0xFF; 6], &mut out),
            Err(ChunkError::Overrun {
                held: 5,
                expected: 4
            })
        );
        // The marker means nothing to the other encodings, which decode the chunk as it is.
        let lzvn = Encoding::Compressed(Algorithm::Lzvn);
        assert!(decode_chunk(lzvn, &[0xFF, b'e'], &mut out).is_err());
    }

    #[test]
    fn an_lzvn_chunk_opening_with_the_end_of_a_stream_is_its_content_raw() {
        // As macOS's compressor stores a chunk that does not compress: the end-of-stream
        // instruction, which alone produces nothing, then the content.
        let lzvn = Encoding::Compressed(Algorithm::Lzvn);
        let mut out = [0u8; 4];
        assert_eq!(decode_chunk(lzvn, &[0x06, 1, 2, 3, 4], &mut out), Ok(4));
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(decode_chunk(lzvn, &[0x06, 9], &mut out), Ok(1));
        assert_eq!(
            decode_chunk(lzvn, &[0x06; 6], &mut out),
            Err(ChunkError::Overrun {
                held: 5,
                expected: 4
            })
        );
        // The byte is LZVN's alone: to zlib it is the start of a stream that does not decode.
        assert!(decode_chunk(ZLIB, &[0x06, 1, 2, 3, 4], &mut out).is_err());
    }

    #[test]
    fn a_stored_chunk_is_its_content_after_its_marker_and_nothing_else() {
        let mut out = [0u8; 4];
        assert_eq!(decode_chunk(Encoding::Stored, b"\xccabc", &mut out), Ok(3));
        assert_eq!(&out[..3], b"abc");
        // The marker is taken once: a second one is content.
        assert_eq!(
            decode_chunk(Encoding::Stored, b"\xcc\xccab", &mut out),
            Ok(3)
        );
        assert_eq!(&out[..3], b"\xccab");
        assert_eq!(decode_chunk(Encoding::Stored, b"\xcc", &mut out), Ok(0));
        // Every other opening byte, and none, is refused by what it is.
        for other in (0..=u8::MAX).filter(|&b| b != STORED) {
            assert_eq!(
                decode_chunk(Encoding::Stored, &[other, b'a'], &mut out),
                Err(ChunkError::Unmarked(Some(other)))
            );
        }
        let none = decode_chunk(Encoding::Stored, b"", &mut out);
        assert_eq!(none, Err(ChunkError::Unmarked(None)));
        assert!(none.unwrap_err().to_string().contains("opens with nothing"));
        assert_eq!(
            decode_chunk(Encoding::Stored, b"\xccabcde", &mut out),
            Err(ChunkError::Overrun {
                held: 5,
                expected: 4
            })
        );
        // To zlib, 0xCC opens a stream, and is not a marker.
        assert!(decode_chunk(ZLIB, b"\xccabc", &mut out).is_err());
    }

    #[test]
    fn only_the_observed_types_are_read() {
        use Encoding::{Compressed, Stored};
        assert_eq!(
            layout(3),
            Some((Layout::Inline, Compressed(Algorithm::Zlib)))
        );
        assert_eq!(
            layout(4),
            Some((Layout::Resource, Compressed(Algorithm::Zlib)))
        );
        assert_eq!(
            layout(7),
            Some((Layout::Inline, Compressed(Algorithm::Lzvn)))
        );
        assert_eq!(
            layout(8),
            Some((Layout::Offsets, Compressed(Algorithm::Lzvn)))
        );
        assert_eq!(layout(9), Some((Layout::Inline, Stored)));
        assert_eq!(layout(10), Some((Layout::Offsets, Stored)));
        assert_eq!(
            layout(11),
            Some((Layout::Inline, Compressed(Algorithm::Lzfse)))
        );
        assert_eq!(
            layout(12),
            Some((Layout::Offsets, Compressed(Algorithm::Lzfse)))
        );
        assert_eq!(
            layout(13),
            Some((Layout::Inline, Compressed(Algorithm::Lzbitmap)))
        );
        assert_eq!(
            layout(14),
            Some((Layout::Offsets, Compressed(Algorithm::Lzbitmap)))
        );
        for unobserved in [0, 1, 2, 5, 6, 15, 16] {
            assert_eq!(layout(unobserved), None, "type {unobserved}");
        }
        // Types 9 and 10 need no decoder, so every build reads them.
        assert!(Stored.available());
    }
}
