//! Several records in one item: the framing rule every variable-length btrfs record shares,
//! and the one place it is checked.
//!
//! Four of the records a filesystem tree holds are a fixed head followed by a tail whose
//! length the head declares — a directory entry and its name, an extended attribute and its
//! value, the names an inode is known by. A key does not always separate them: a `DIR_ITEM` is
//! keyed by the hash of its name, so two names that collide are two records inside one item,
//! and an `INODE_REF` holds one record per name the inode has in that directory.
//!
//! So every one of them is read the same way — take the head, take the tail the head declares,
//! move on — and every one of them can be malformed the same way: a declared tail longer than
//! the item that holds it. That is the bound, it is one bound, and [`for_each_packed`] is
//! where it is applied.
//!
//! This module is pure: it frames bytes and returns slices of them.

use super::ParseError;

/// A record that is a fixed head followed by a tail whose length the head declares.
///
/// Implemented by each of the packed records so that [`for_each_packed`] can frame any of
/// them. The three members are the whole of what framing needs: how long a head is, how to
/// recover one, and how long the record it heads turns out to be.
pub trait Packed: Sized {
    /// The structure's name, for a message naming what failed to frame.
    const STRUCTURE: &'static str;

    /// Bytes the fixed head occupies.
    const HEAD: usize;

    /// Recover the head from the first [`HEAD`](Self::HEAD) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a head.
    fn read_head(buf: &[u8]) -> Result<Self, ParseError>;

    /// Bytes the whole record occupies, the head and everything the head declares.
    ///
    /// Computed in `usize` from fields no wider than 16 bits, so it cannot overflow on any
    /// target this crate builds for.
    fn encoded_len(&self) -> usize;
}

/// Visit every record packed into one item's data, in the order they are stored.
///
/// The closure is handed the head and the tail behind it — a name, a name and a value, or
/// whatever the record declares — and answers whether to keep going, so a caller looking for
/// one name stops at it rather than framing the rest.
///
/// **A record whose declared length escapes the item is a refusal, not a truncation.** The
/// alternative is handing back a name made of whatever follows the item in the leaf, which is
/// the bytes of an unrelated record read as text; and a caller cannot tell the difference,
/// because a short name is what an item legitimately holds.
///
/// # Errors
///
/// [`ParseError::TooShort`] naming the structure, where the data runs out inside a head or
/// inside the tail a head declared.
pub fn for_each_packed<T: Packed, F>(data: &[u8], mut visit: F) -> Result<(), ParseError>
where
    F: FnMut(&T, &[u8]) -> bool,
{
    let mut at = 0usize;
    while at < data.len() {
        let record = T::read_head(&data[at..])?;
        let len = record.encoded_len();
        let end = at + len;
        if end > data.len() {
            return Err(ParseError::TooShort {
                structure: T::STRUCTURE,
                need: len,
                got: data.len() - at,
            });
        }
        if !visit(&record, &data[at + T::HEAD..end]) {
            return Ok(());
        }
        at = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A head of one byte declaring a tail of that many.
    struct Run(u8);

    impl Packed for Run {
        const STRUCTURE: &'static str = "run";
        const HEAD: usize = 1;

        fn read_head(buf: &[u8]) -> Result<Self, ParseError> {
            match buf.first() {
                Some(&n) => Ok(Self(n)),
                None => Err(ParseError::TooShort {
                    structure: Self::STRUCTURE,
                    need: 1,
                    got: 0,
                }),
            }
        }

        fn encoded_len(&self) -> usize {
            Self::HEAD + self.0 as usize
        }
    }

    /// Every tail `for_each_packed` frames out of `data`.
    fn tails(data: &[u8]) -> Result<Vec<Vec<u8>>, ParseError> {
        let mut out = Vec::new();
        for_each_packed::<Run, _>(data, |_, tail| {
            out.push(tail.to_vec());
            true
        })?;
        Ok(out)
    }

    #[test]
    fn every_record_packed_into_one_item_is_framed_in_order() {
        let data = [3u8, b'a', b'b', b'c', 0, 1, b'z'];
        assert_eq!(
            tails(&data).expect("three records"),
            vec![b"abc".to_vec(), Vec::new(), b"z".to_vec()]
        );
        // An item with nothing in it holds no records rather than failing to frame one.
        assert_eq!(tails(&[]).expect("no records"), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn a_record_whose_tail_escapes_the_item_is_refused_rather_than_shortened() {
        // The failure the bound exists for: a declared length past the end of the item would
        // otherwise hand back a name made of whatever follows it in the leaf, and a short
        // name is what an item legitimately holds — so nothing downstream could tell.
        let err = tails(&[3u8, b'a', b'b']).expect_err("a tail one byte past the item");
        assert!(matches!(
            err,
            ParseError::TooShort {
                structure: "run",
                need: 4,
                got: 3,
            }
        ));
    }

    #[test]
    fn a_visitor_that_has_found_what_it_wanted_stops_the_framing_there() {
        let mut seen = Vec::new();
        for_each_packed::<Run, _>(&[1u8, b'a', 1, b'b'], |_, tail| {
            seen.push(tail[0]);
            false
        })
        .expect("one record");
        assert_eq!(seen, vec![b'a']);
    }
}
