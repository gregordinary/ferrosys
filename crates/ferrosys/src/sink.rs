//! Where a format's bytes go: absolute byte offsets into a seekable destination.
//!
//! A materializer decides what every byte of a filesystem is and then puts it somewhere.
//! The deciding is the family's own — a block group is not a cluster heap — but the putting
//! is not: seek to an offset, write, and remember how far the writing reached. Every family
//! does it identically, which is the test for a shared primitive rather than a shared seam,
//! so it is written once here and each family's layout logic stays its own.
//!
//! Nothing is ever read back from a destination. A format writes only what the filesystem
//! occupies, so a file destination stays sparse and a volume far larger than memory can be
//! created into one.

use std::io::{Result, Seek, SeekFrom, Write};

/// A seekable destination, and how far into it the writing has reached.
///
/// The high-water mark is what [`extend_to`](Self::extend_to) needs: a filesystem whose last
/// blocks hold nothing never writes them, so the destination would otherwise end short of
/// the size the metadata claims.
pub(crate) struct ByteSink<W> {
    sink: W,
    /// One past the highest byte offset written.
    written_end: u64,
}

impl<W: Write + Seek> ByteSink<W> {
    /// A sink over `sink`, with nothing written yet.
    pub(crate) fn new(sink: W) -> Self {
        Self {
            sink,
            written_end: 0,
        }
    }

    /// Take `bytes` at absolute byte offset `offset`.
    pub(crate) fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        self.sink.seek(SeekFrom::Start(offset))?;
        self.sink.write_all(bytes)?;
        self.written_end = self.written_end.max(offset + bytes.len() as u64);
        Ok(())
    }

    /// Make the destination as long as the filesystem, for the case where its final blocks
    /// hold nothing and so were never written.
    pub(crate) fn extend_to(&mut self, size: u64) -> Result<()> {
        if self.written_end < size {
            // The last byte was never written, so it is already zero; writing a zero there
            // only grows the destination.
            self.write_at(size - 1, &[0])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn a_destination_reaches_the_size_its_last_written_byte_did_not() {
        let mut sink = ByteSink::new(Cursor::new(Vec::new()));
        sink.write_at(0, &[1, 2, 3]).expect("write");
        sink.extend_to(16).expect("extend");
        let out = sink.sink.into_inner();
        assert_eq!(
            out.len(),
            16,
            "the destination is as long as the filesystem"
        );
        assert_eq!(&out[..3], &[1, 2, 3]);
        assert!(
            out[3..].iter().all(|&b| b == 0),
            "everything the format did not write reads as zero"
        );
    }

    #[test]
    fn a_destination_already_long_enough_is_left_alone() {
        let mut sink = ByteSink::new(Cursor::new(Vec::new()));
        sink.write_at(0, &[7; 8]).expect("write");
        sink.extend_to(8).expect("extend");
        assert_eq!(sink.sink.into_inner().len(), 8);
    }

    #[test]
    fn the_high_water_mark_is_the_highest_offset_written_not_the_last() {
        // Structures are laid down in ascending order, but a backup copy written earlier
        // than a later structure must not pull the mark back down.
        let mut sink = ByteSink::new(Cursor::new(Vec::new()));
        sink.write_at(32, &[1]).expect("write");
        sink.write_at(0, &[1]).expect("write");
        sink.extend_to(33).expect("extend");
        assert_eq!(sink.sink.into_inner().len(), 33);
    }
}
