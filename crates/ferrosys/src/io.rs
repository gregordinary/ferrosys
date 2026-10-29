//! The crate's byte boundary: where a format's bytes go, where a reader's come from, the
//! arithmetic that names a place in either, and what a failure at that boundary records.
//!
//! A materializer decides what every byte of a filesystem is and then puts it somewhere; a
//! reader finds a structure and then fetches it. The deciding and the finding are the
//! family's own — a block group is not a cluster heap — but the putting and the fetching are
//! not: seek to an offset, move exactly that many bytes. Every family does it identically,
//! which is the test for a shared primitive rather than a shared seam, so both directions are
//! written once here and each family's layout logic stays its own.
//!
//! Nothing is ever read back from a *destination*. A format writes only what the filesystem
//! occupies, so a file destination stays sparse and a volume far larger than memory can be
//! created into one.
//!
//! # Why the addressing is here too
//!
//! Every offset either direction uses has one shape — a base, a count of units, and the size
//! of a unit — and every one of them is computed from a number an untrusted image supplied.
//! A block number, a sector number, an inode table's first block: each reaches its whole
//! range whatever the filesystem around it says, so each product and each sum is one a
//! crafted image can push past the 64-bit range. Wrapping there is not a failed read; it is a
//! *successful* read of the wrong bytes, at a small offset the wrap landed on.
//!
//! So `offset_of` is checked and returns `None` rather than a number, and the caller names
//! the referent in its own vocabulary — a block, a group, a sector — because that is the word
//! the reader of the error needs and this module does not know it. (Named without a link
//! here: it is compiled only where a family is, and this module is not.)
//!
//! # What a failure records
//!
//! [`io_fault`] is the other half of the same boundary: an [`std::io::Error`] belongs to the
//! environment rather than to the image, and every error type in this crate that can carry
//! one records the same two things about it. [`io_error!`] writes that conversion, so the
//! decision lives here rather than once per enum.
//!
//! That pair is what keeps this module out of the family gate the rest of it sits behind:
//! `DetectError` carries an i/o failure in every build, including the one that compiles no
//! family and recognizes nothing. Moving the bytes is a family's concern; failing to move
//! them is not.
//!
//! # What is compiled where
//!
//! The rest of the module is gated by what needs it rather than by "a family": a family that
//! has only a classifier reads one sector at an offset and nothing else, so it reaches
//! `read_exact_at` and neither the write side nor the unit addressing. Each gate is widened
//! by the change that gives that family a materializer or a reader, which is what keeps an
//! unused item here reported rather than quietly allowed.
//!
//! The gates are widened by different events — a family arrives one direction at a time — and
//! each direction's gate is the record of which families have earned it. All five families
//! have both directions, so both gates name all five.
//!
//! Nothing in this paragraph is a doc link, and deliberately: a link naming an item that is
//! absent from some configuration resolves in the deepest build and is a hard error in every
//! other, which is the class `ci/lint-features.sh` exists to catch.

#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
use std::io::{Read, Result, Seek, SeekFrom};
// The write half: `ByteSink` is what a materializer takes.
#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
use std::io::Write;

/// A seekable destination, and how far into it the writing has reached.
///
/// The high-water mark is what [`extend_to`](Self::extend_to) needs: a filesystem whose last
/// blocks hold nothing never writes them, so the destination would otherwise end short of
/// the size the metadata claims.
#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
pub(crate) struct ByteSink<W> {
    sink: W,
    /// One past the highest byte offset written.
    written_end: u64,
}

#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
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
        // Checked, as every offset sum in this module is: the offsets come from planners
        // and cannot wrap today, and this line must not be the one place a planner defect
        // would wrap silently instead of failing.
        let end = offset.checked_add(bytes.len() as u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a write's end overflows the offset space",
            )
        })?;
        self.sink.seek(SeekFrom::Start(offset))?;
        self.sink.write_all(bytes)?;
        self.written_end = self.written_end.max(end);
        Ok(())
    }

    /// Pass everything taken so far on to the destination, through its own `flush`.
    ///
    /// What that makes durable is the destination's to say: a file's `flush` hands nothing to
    /// the medium, and a destination that must survive a power cut between two writes is one
    /// whose `flush` does. The exFAT writer flushes between the stages of a format, which is
    /// what lets such a destination keep their order.
    #[cfg(feature = "exfat")]
    pub(crate) fn flush(&mut self) -> Result<()> {
        self.sink.flush()
    }

    /// Make the destination as long as the filesystem, for the case where its final blocks
    /// hold nothing and so were never written.
    ///
    /// A `size` of zero asks for a destination with no last byte to write, and is answered by
    /// leaving it alone. Every planner refuses a volume anywhere near that small, so nothing
    /// reaches it today — and a guard on bytes that reach an image is unconditional, because
    /// the caller that would reach it is the one written after this line.
    pub(crate) fn extend_to(&mut self, size: u64) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        if self.written_end < size {
            // The last byte was never written, so a zero there overwrites nothing this run
            // wrote and only grows the destination. A fresh destination holds a zero there
            // already.
            self.write_at(size - 1, &[0])?;
        }
        Ok(())
    }
}

/// Exactly `len` bytes at absolute byte `offset` in `src`.
///
/// The read-side counterpart of `ByteSink::write_at`: seek, then move exactly that many
/// bytes or fail. What a short source *means* is the caller's — an ext reader answers a read
/// past the end as an out-of-range reference to whatever named it, a rewrite answers it as
/// the i/o failure it is — so this hands back [`std::io::ErrorKind::UnexpectedEof`] and lets
/// each one say what it is about.
#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
pub(crate) fn read_exact_at<R: Read + Seek>(
    src: &mut R,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    read_exact_into(src, offset, &mut buf)?;
    Ok(buf)
}

/// [`read_exact_at`], into a buffer the caller holds.
///
/// The form for a loop over many runs of one size — a data pass verifying a file sector by
/// sector — where the allocating form would cost one fresh buffer per read.
#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
pub(crate) fn read_exact_into<R: Read + Seek>(
    src: &mut R,
    offset: u64,
    buf: &mut [u8],
) -> Result<()> {
    src.seek(SeekFrom::Start(offset))?;
    src.read_exact(buf)
}

/// A source that ends where the filesystem's region does: the end a caller named, or the
/// source's own, whichever comes first.
///
/// Every family's reader holds its source through one, and detection reads through one, so the
/// region is applied once rather than at each place a reader measures or reads. A read that
/// reaches the region's end comes back short, which [`read_exact_at`] reports as
/// [`std::io::ErrorKind::UnexpectedEof`] as it does for a short source. A seek from the end
/// counts from the region's end, so a reader measuring its source measures the region. A
/// filesystem inside a partition is therefore held to the partition, and the bytes of the
/// partition after it are never read as its own.
///
/// Offsets are the source's own, not the region's: the region begins at the `base` every
/// reader already adds, and only its end is applied here.
#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
pub(crate) struct Bounded<R> {
    inner: R,
    /// One past the region's last byte, as an offset into `inner`, or `None` where the region
    /// runs to the source's end.
    end: Option<u64>,
    /// Where `inner` stands, or `None` until a seek or a query has said.
    at: Option<u64>,
}

#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
impl<R> Bounded<R> {
    /// `inner`, ending `len` bytes past `base`, or at its own end where `len` is `None`.
    ///
    /// A region whose end leaves the 64-bit range ends at the top of it, which no source
    /// reaches: such a region is bounded by the source alone.
    pub(crate) fn new(inner: R, base: u64, len: Option<u64>) -> Self {
        Self {
            inner,
            end: len.map(|len| base.saturating_add(len)),
            at: None,
        }
    }

    /// How many of `wanted` bytes at the current position lie inside the region.
    fn room(&mut self, wanted: usize) -> Result<usize>
    where
        R: Seek,
    {
        let Some(end) = self.end else {
            return Ok(wanted);
        };
        let at = match self.at {
            Some(at) => at,
            None => {
                let at = self.inner.stream_position()?;
                self.at = Some(at);
                at
            }
        };
        let room = end.saturating_sub(at);
        Ok(usize::try_from(room).map_or(wanted, |room| room.min(wanted)))
    }
}

#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
impl<R: Read + Seek> Read for Bounded<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let take = self.room(buf.len())?;
        let n = self.inner.read(&mut buf[..take])?;
        if let Some(at) = self.at.as_mut() {
            *at += n as u64;
        }
        Ok(n)
    }
}

#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
impl<R: Seek> Seek for Bounded<R> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        // Unknown until the seek has answered, so a seek that fails partway leaves nothing
        // stale behind it.
        self.at = None;
        let to = match (pos, self.end) {
            (SeekFrom::End(delta), Some(end)) => {
                let stop = self.inner.seek(SeekFrom::End(0))?.min(end);
                let to = stop.checked_add_signed(delta).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "a seek from the region's end leaves the offset space",
                    )
                })?;
                self.inner.seek(SeekFrom::Start(to))?
            }
            _ => self.inner.seek(pos)?,
        };
        self.at = Some(to);
        Ok(to)
    }
}

/// The write half, for the one verb that writes into an image it did not make: a rewrite of
/// a filesystem inside a partition stops at the partition's end as a read does.
#[cfg(feature = "ext")]
impl<W: Write + Seek> Write for Bounded<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let take = self.room(buf.len())?;
        let n = self.inner.write(&buf[..take])?;
        if let Some(at) = self.at.as_mut() {
            *at += n as u64;
        }
        Ok(n)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

/// The byte offset `index` units of `unit` bytes past `base`, or [`None`] where it leaves the
/// 64-bit range.
///
/// Both the product and the sum are checked, because both are computed from numbers an image
/// supplies and neither is bounded by anything else the image says. A `base` a caller pushed
/// near the top of the range and an `index` a malformed field left enormous each wrap into a
/// small offset, which is a read of the wrong bytes rather than a read that fails.
///
/// `unit` of 1 addresses bytes and `base` of 0 counts from the start of whatever the caller
/// is addressing within — a filesystem's own first byte, say, with the source's base added
/// afterwards by whatever places it.
#[cfg(any(
    feature = "ext",
    feature = "fat",
    feature = "exfat",
    feature = "btrfs",
    feature = "apfs"
))]
pub(crate) const fn offset_of(base: u64, index: u64, unit: u64) -> Option<u64> {
    match index.checked_mul(unit) {
        Some(within) => base.checked_add(within),
        None => None,
    }
}

/// What every error in this crate records about an [`std::io::Error`]: how it classified
/// itself, and what it says.
///
/// Why those two and not the error itself is written out on
/// [`TreeError::Io`](crate::TreeError::Io), which is the shared surface's and so the one a
/// reader of any of them reaches. This is where the decision is *made*: every construction
/// site goes through here, so a change to what is recorded is one edit rather than one per
/// enum.
pub(crate) fn io_fault(err: &std::io::Error) -> (std::io::ErrorKind, String) {
    (err.kind(), err.to_string())
}

/// Write `From<std::io::Error>` for an error type carrying an `Io { kind, message }` variant.
///
/// Every such conversion is the same two lines over [`io_fault`], and hand-writing them is how
/// one enum comes to record something its siblings do not, or to offer a private constructor
/// where they offer the trait a caller reaches through `?`. Generated, every carrying type has
/// the same conversion and the same reach.
macro_rules! io_error {
    ($ty:ty) => {
        impl From<std::io::Error> for $ty {
            fn from(e: std::io::Error) -> Self {
                let (kind, message) = $crate::io::io_fault(&e);
                Self::Io { kind, message }
            }
        }
    };
}

pub(crate) use io_error;

/// Every read a [`Counting`] source was asked for: the offset each began at, and the bytes
/// it wanted. Shared, so a test reads the log while a reader holds the source.
#[cfg(all(test, any(feature = "ext", feature = "fat", feature = "btrfs")))]
pub(crate) type ReadLog = std::rc::Rc<std::cell::RefCell<Vec<(u64, usize)>>>;

/// A source held in memory that keeps every read it is asked for, for the tests that pin
/// what a read costs: how many requests a walk makes, and whether any byte is asked for
/// twice.
#[cfg(all(test, any(feature = "ext", feature = "fat", feature = "btrfs")))]
pub(crate) struct Counting {
    inner: std::io::Cursor<Vec<u8>>,
    reads: ReadLog,
}

#[cfg(all(test, any(feature = "ext", feature = "fat", feature = "btrfs")))]
impl Counting {
    /// A source over `bytes`, and the log its reads are kept in.
    pub(crate) fn new(bytes: Vec<u8>) -> (Self, ReadLog) {
        let reads = ReadLog::default();
        let source = Self {
            inner: std::io::Cursor::new(bytes),
            reads: std::rc::Rc::clone(&reads),
        };
        (source, reads)
    }
}

#[cfg(all(test, any(feature = "ext", feature = "fat", feature = "btrfs")))]
impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let at = self.inner.position();
        self.reads.borrow_mut().push((at, buf.len()));
        self.inner.read(buf)
    }
}

#[cfg(all(test, any(feature = "ext", feature = "fat", feature = "btrfs")))]
impl Seek for Counting {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.inner.seek(pos)
    }
}

#[cfg(all(
    test,
    any(
        feature = "ext",
        feature = "fat",
        feature = "exfat",
        feature = "btrfs",
        feature = "apfs"
    )
))]
mod tests {
    use super::*;
    use std::io::Cursor;

    // `ByteSink` is the write side, so these are compiled where a materializer is rather
    // than wherever this module is -- which is every family that writes one.
    #[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
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

    #[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
    #[test]
    fn a_destination_already_long_enough_is_left_alone() {
        let mut sink = ByteSink::new(Cursor::new(Vec::new()));
        sink.write_at(0, &[7; 8]).expect("write");
        sink.extend_to(8).expect("extend");
        assert_eq!(sink.sink.into_inner().len(), 8);
    }

    #[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
    #[test]
    fn a_destination_of_no_bytes_at_all_has_no_last_byte_to_write() {
        // Every planner refuses a volume this small, so nothing here reaches it — and the
        // subtraction that finds the last byte would run off the bottom of the range if one
        // ever did. A guard on bytes that reach an image is unconditional.
        let mut sink = ByteSink::new(Cursor::new(Vec::new()));
        sink.extend_to(0).expect("extend");
        assert!(sink.sink.into_inner().is_empty());
    }

    #[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
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

    #[test]
    fn a_read_takes_exactly_the_bytes_asked_for_at_the_offset_asked_for() {
        let mut src = Cursor::new((0u8..32).collect::<Vec<_>>());
        assert_eq!(read_exact_at(&mut src, 8, 4).expect("read"), [8, 9, 10, 11]);
        // The cursor's own position before the call means nothing: every read seeks.
        assert_eq!(read_exact_at(&mut src, 0, 2).expect("read"), [0, 1]);
    }

    #[test]
    fn a_bounded_source_ends_at_its_region_and_measures_to_it() {
        // Sixty-four bytes, of which a region of sixteen begins at eight.
        let bytes: Vec<u8> = (0u8..64).collect();
        let mut src = Bounded::new(Cursor::new(bytes.clone()), 8, Some(16));
        // Measured from the end, the source is as long as the region's end.
        assert_eq!(src.seek(SeekFrom::End(0)).expect("seek"), 24);
        assert_eq!(src.seek(SeekFrom::End(-4)).expect("seek"), 20);
        // A read inside the region is the source's own bytes, at the source's own offsets.
        assert_eq!(read_exact_at(&mut src, 8, 16).expect("read"), &bytes[8..24]);
        // One reaching past the region's end is a short source, as one past a file's end is.
        let err = read_exact_at(&mut src, 20, 8).expect_err("past the region");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        // And one beginning past it reads nothing.
        let err = read_exact_at(&mut src, 40, 1).expect_err("past the region");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_bounded_source_is_no_longer_than_the_source_under_it() {
        // A region the source does not wholly hold ends where the source does, so a reader
        // measuring it learns what is there rather than what was named.
        let mut src = Bounded::new(Cursor::new(vec![0u8; 32]), 8, Some(1 << 20));
        assert_eq!(src.seek(SeekFrom::End(0)).expect("seek"), 32);
        // No length is the source's own end, and a length whose end leaves the range is too.
        let mut src = Bounded::new(Cursor::new(vec![0u8; 32]), 8, None);
        assert_eq!(src.seek(SeekFrom::End(0)).expect("seek"), 32);
        assert_eq!(read_exact_at(&mut src, 0, 32).expect("read").len(), 32);
        let mut src = Bounded::new(Cursor::new(vec![0u8; 32]), u64::MAX - 1, Some(8));
        assert_eq!(src.seek(SeekFrom::End(0)).expect("seek"), 32);
    }

    #[test]
    fn a_bounded_source_bounds_a_read_from_wherever_the_source_stood() {
        // Nothing has sought yet, so the position is asked of the source under it.
        let mut inner = Cursor::new((0u8..32).collect::<Vec<_>>());
        inner.set_position(12);
        let mut src = Bounded::new(inner, 0, Some(16));
        let mut buf = [0u8; 8];
        assert_eq!(
            src.read(&mut buf).expect("read"),
            4,
            "four bytes remain in the region"
        );
        assert_eq!(&buf[..4], &[12, 13, 14, 15]);
        assert_eq!(src.read(&mut buf).expect("read"), 0);
    }

    #[cfg(feature = "ext")]
    #[test]
    fn a_bounded_destination_takes_no_byte_past_its_region() {
        let mut dest = Bounded::new(Cursor::new(vec![0u8; 32]), 4, Some(8));
        dest.seek(SeekFrom::Start(10)).expect("seek");
        let err = dest.write_all(&[0xff; 4]).expect_err("past the region");
        assert_eq!(err.kind(), std::io::ErrorKind::WriteZero);
        let bytes = dest.inner.into_inner();
        assert_eq!(
            &bytes[10..12],
            &[0xff, 0xff],
            "the two bytes inside the region"
        );
        assert_eq!(&bytes[12..14], &[0, 0], "nothing past it");
    }

    #[test]
    fn a_read_running_past_the_end_is_the_end_of_the_source_saying_so() {
        // The kind is what each caller relabels: an out-of-range reference to whatever
        // named the bytes, or the plain i/o failure it is. Handing back anything else here
        // would leave the two unable to tell a short source from a broken one.
        let mut src = Cursor::new(vec![0u8; 4]);
        let err = read_exact_at(&mut src, 2, 8).expect_err("a source of four bytes holds none");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    // The unit addressing is reached by a reader rather than by a materializer, whose offsets
    // come from a layout it planned rather than from a number an image supplied. So these two
    // are compiled where a reader is, which today is every family and need not stay so.
    #[cfg(any(
        feature = "ext",
        feature = "fat",
        feature = "exfat",
        feature = "btrfs",
        feature = "apfs"
    ))]
    #[test]
    fn an_offset_is_the_base_plus_as_many_units_as_asked_for() {
        assert_eq!(offset_of(1024, 3, 4096), Some(1024 + 3 * 4096));
        // A unit of one addresses bytes; a base of zero counts from the start of whatever
        // is being addressed within.
        assert_eq!(offset_of(1024, 7, 1), Some(1031));
        assert_eq!(offset_of(0, 5, 512), Some(2560));
    }

    #[cfg(any(
        feature = "ext",
        feature = "fat",
        feature = "exfat",
        feature = "btrfs",
        feature = "apfs"
    ))]
    #[test]
    fn an_offset_that_leaves_the_range_is_no_offset_rather_than_a_small_one() {
        // Both halves are computed from numbers an image supplies, so both are checked. A
        // wrap in either is not a read that fails — it is a successful read of whatever
        // happens to sit at the offset the wrap landed on.
        assert_eq!(offset_of(0, u64::MAX, 2), None, "the product wraps");
        assert_eq!(offset_of(u64::MAX, 1, 1), None, "the sum wraps");
        // And the exact top of the range is reachable, so the check is not off by one.
        assert_eq!(offset_of(u64::MAX - 1, 1, 1), Some(u64::MAX));
    }
}
