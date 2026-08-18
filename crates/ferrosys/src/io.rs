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
//! All four families have both directions, so today every gate names the same four. The
//! gates stay separate all the same, because they are widened by different events — a family
//! arrives one direction at a time, and each direction's gate is the record of which
//! families have earned it.
//!
//! Nothing in this paragraph is a doc link, and deliberately: a link naming an item that is
//! absent from some configuration resolves in the deepest build and is a hard error in every
//! other, which is the class `ci/lint-features.sh` exists to catch.

#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
use std::io::{Read, Result, Seek, SeekFrom};
// The write half alone: `ByteSink` is what a materializer takes, so a family that has a
// reader and no writer yet reaches everything above and none of this.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
use std::io::Write;

/// A seekable destination, and how far into it the writing has reached.
///
/// The high-water mark is what [`extend_to`](Self::extend_to) needs: a filesystem whose last
/// blocks hold nothing never writes them, so the destination would otherwise end short of
/// the size the metadata claims.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) struct ByteSink<W> {
    sink: W,
    /// One past the highest byte offset written.
    written_end: u64,
}

#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
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
            // The last byte was never written, so it is already zero; writing a zero there
            // only grows the destination.
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
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
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
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) fn read_exact_into<R: Read + Seek>(
    src: &mut R,
    offset: u64,
    buf: &mut [u8],
) -> Result<()> {
    src.seek(SeekFrom::Start(offset))?;
    src.read_exact(buf)
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
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
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

#[cfg(all(
    test,
    any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs")
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
    #[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
    #[test]
    fn an_offset_is_the_base_plus_as_many_units_as_asked_for() {
        assert_eq!(offset_of(1024, 3, 4096), Some(1024 + 3 * 4096));
        // A unit of one addresses bytes; a base of zero counts from the start of whatever
        // is being addressed within.
        assert_eq!(offset_of(1024, 7, 1), Some(1031));
        assert_eq!(offset_of(0, 5, 512), Some(2560));
    }

    #[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
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
