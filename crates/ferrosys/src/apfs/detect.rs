//! Whether an image holds an APFS container, decided by block zero.
//!
//! APFS is a tier-1 family: `NXSB` is four bytes at offset 32 of the container's first block,
//! which is a copy of its superblock. Four bytes at a fixed offset are a weaker signature than
//! btrfs's eight, and offset 32 of a FAT boot sector is its 32-bit sector count, so a FAT
//! volume of one particular size spells the magic there. What settles it is a **checksum**:
//! every APFS object carries one over its whole block, and a sector count that happens to spell
//! `NXSB` does not make the rest of the sector sum to zero. Block zero's checksum settles it
//! where it covers the block; where it does not, a whole checkpoint in the descriptor area block
//! zero names does, which is what a lenient open reads such a container through. The question is
//! the reader's own, [`is_container`], so detection claims every container a lenient open reads.
//!
//! Detection is otherwise more forgiving than reading: a container whose features, checkpoint
//! or volumes this crate cannot read is still claimed, because it is one, and the reader is
//! what says why it cannot be read.
//!
//! This module reads block zero, and the descriptor area only where block zero does not
//! verify.

use std::io::{Read, Seek};

use crate::detect::{DetectError, DetectOptions, Filesystem};

use super::container::{ReadError, is_container};

/// Whether the APFS family claims the image.
///
/// `Ok(None)` is "not ours". An I/O failure is the source's rather than the image's and stops
/// detection; a source too short to hold block zero is an answer about the image, so it is
/// "not ours".
pub(crate) fn claim<R: Read + Seek>(
    src: R,
    options: &DetectOptions,
) -> Result<Option<Filesystem>, DetectError> {
    match is_container(src, options.base) {
        Ok(found) => Ok(found.then_some(Filesystem::Apfs)),
        Err(ReadError::Io { kind, message }) => Err(DetectError::Io { kind, message }),
        // Every other refusal is an answer about the image, which `is_container` gives as one.
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs::ondisk::seal;
    use crate::bytes::{put_arr, put_u32};
    use std::io::Cursor;

    /// A block zero carrying the magic and a block size, sealed or not.
    fn block_zero(sealed: bool) -> Vec<u8> {
        let mut block = vec![0u8; 4096];
        put_u32(&mut block, 24, 0x8000_0001);
        put_arr(&mut block, 32, b"NXSB");
        put_u32(&mut block, 36, 4096);
        if sealed {
            seal(&mut block);
        }
        block
    }

    #[test]
    fn a_sealed_block_zero_is_claimed() {
        let found = claim(Cursor::new(block_zero(true)), &DetectOptions::new());
        assert_eq!(found, Ok(Some(Filesystem::Apfs)));
    }

    #[test]
    fn the_magic_without_its_checksum_is_not() {
        // What a FAT boot sector whose sector count spells the magic looks like here.
        let found = claim(Cursor::new(block_zero(false)), &DetectOptions::new());
        assert_eq!(found, Ok(None));
    }

    #[test]
    fn a_source_shorter_than_a_block_is_not_ours() {
        let found = claim(Cursor::new(vec![0u8; 100]), &DetectOptions::new());
        assert_eq!(found, Ok(None));
    }
}
