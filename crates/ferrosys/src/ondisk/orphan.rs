//! The orphan file's block format.
//!
//! With `orphan_file` set, the inodes awaiting deletion are recorded in a file of
//! their own rather than in a list threaded through the superblock. Each of its blocks
//! is a flat array of little-endian inode numbers closed by an 8-byte tail: the magic
//! word [`ORPHAN_BLOCK_MAGIC`] and the block's crc32c. An entry of zero is an empty
//! slot, so a filesystem with no orphans — every freshly formatted one — carries blocks
//! whose entries are all zero and whose tail is the only meaningful part.
//!
//! As everywhere in this module, the checksum is a value the caller supplies: the
//! construction that produces it is the checksum seam's, not this layer's.

use super::{ParseError, get_u32, put_u32};

/// The magic word closing every orphan-file block (`EXT4_ORPHAN_BLOCK_MAGIC`).
pub const ORPHAN_BLOCK_MAGIC: u32 = 0x0b10_ca04;

/// The bytes the tail occupies at the end of an orphan block: the magic word and the
/// block's checksum, four bytes each.
pub const ORPHAN_TAIL_LEN: usize = 8;

/// The bytes of an orphan block that hold entries: all of it but the tail. This is the
/// region the block's checksum covers.
#[must_use]
pub const fn orphan_entries_len(block_size: usize) -> usize {
    block_size - ORPHAN_TAIL_LEN
}

/// The tail bytes closing an orphan block whose checksum is `checksum`, which is zero
/// when `metadata_csum` is off.
#[must_use]
pub fn orphan_tail_bytes(checksum: u32) -> [u8; ORPHAN_TAIL_LEN] {
    let mut tail = [0u8; ORPHAN_TAIL_LEN];
    put_u32(&mut tail, 0, ORPHAN_BLOCK_MAGIC);
    put_u32(&mut tail, 4, checksum);
    tail
}

/// The checksum stored in `block`'s tail, having confirmed the block ends in the orphan
/// magic word.
///
/// # Errors
///
/// [`ParseError::TooShort`] if `block` is shorter than the tail;
/// [`ParseError::BadMagic`] if it does not end in [`ORPHAN_BLOCK_MAGIC`].
pub fn read_orphan_tail(block: &[u8]) -> Result<u32, ParseError> {
    if block.len() < ORPHAN_TAIL_LEN {
        return Err(ParseError::TooShort {
            structure: "OrphanBlockTail",
            need: ORPHAN_TAIL_LEN,
            got: block.len(),
        });
    }
    let tail = orphan_entries_len(block.len());
    let magic = get_u32(block, tail);
    if magic != ORPHAN_BLOCK_MAGIC {
        return Err(ParseError::BadMagic {
            structure: "OrphanBlockTail",
            found: magic,
            expected: ORPHAN_BLOCK_MAGIC,
        });
    }
    Ok(get_u32(block, tail + 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tail_round_trips_through_a_block() {
        let mut block = vec![0u8; 4096];
        let tail = orphan_tail_bytes(0xdead_beef);
        block[orphan_entries_len(4096)..].copy_from_slice(&tail);
        assert_eq!(read_orphan_tail(&block).expect("valid tail"), 0xdead_beef);
    }

    #[test]
    fn a_block_without_the_magic_is_rejected() {
        // A block of entries with no tail is not an orphan block, however plausible its
        // contents; the magic is what says the format is being followed.
        let block = vec![0u8; 4096];
        assert!(matches!(
            read_orphan_tail(&block),
            Err(ParseError::BadMagic { .. })
        ));
        assert!(matches!(
            read_orphan_tail(&[0u8; 4]),
            Err(ParseError::TooShort { .. })
        ));
    }
}
