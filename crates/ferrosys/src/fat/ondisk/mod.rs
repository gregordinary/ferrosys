//! On-disk structures: the pure byte layer where a one-byte offset error is a silent
//! corruption.
//!
//! Every FAT metadata object — the boot sector and its BIOS parameter block, the FAT32
//! information sector, the 32-byte directory entry, and the long-name entry — is defined
//! here as a Rust value with symmetric serialization: a `write_to` that produces its
//! little-endian on-disk form and a `read_from` that recovers it. FAT is little-endian on
//! disk regardless of host byte order, so every field is read and written through an
//! accessor naming its offset, its width, and its byte order rather than through any
//! reinterpret-cast; there is no `unsafe`, no `transmute`, and no `#[repr(C)]` reliance.
//!
//! This module is pure: it moves bytes to and from values. It allocates no clusters and
//! performs no I/O.
//!
//! # What is not here
//!
//! **The type.** FAT12, FAT16, and FAT32 differ in the width of a file allocation table
//! entry and in where the root directory sits, and an image records neither — the type
//! follows from the cluster count, which is computed from the boot sector's fields. So the
//! type lives with the arithmetic that derives it, in
//! [`plan_layout`](crate::fat::plan_layout), and a structure here never asks what type it
//! belongs to except where the byte layout genuinely differs, which is the boot sector's
//! tail and nothing else. The file allocation table is the other place the width shows, and
//! its entries are reached through [`fat::table`](crate::fat::table) rather than here,
//! because an entry is not a structure with fields — it is a value packed at one of three
//! widths into an array.
//!
//! **Validation.** These types recover fields and report a length or a magic that makes
//! recovery impossible. Whether the recovered fields describe a filesystem is a separate
//! question with a separate answer, because a classifier and a reader want it asked with
//! different strictness.

mod boot;
mod dirent;

pub use boot::{
    BOOT_SIGNATURE, BootSector, BootSectorTail, EXTENDED_BOOT_SIGNATURE, FSINFO_LEAD_SIGNATURE,
    FSINFO_STRUCT_SIGNATURE, FSINFO_TRAIL_SIGNATURE, Fat32Params, FsInfo, VolumeInfo,
};
pub use dirent::{
    Attributes, DIR_ENTRY_SIZE, DirEntry, LFN_CHARS_PER_ENTRY, LFN_LAST_ENTRY, LFN_MAX_ENTRIES,
    LFN_PADDING, LfnEntry, NAME_DELETED, NAME_END, NAME_LEADING_E5, lfn_checksum,
};

/// The name a space-padded FAT text field holds: its bytes up to the trailing padding.
///
/// Every fixed-width text field FAT defines — the eleven-byte short name, the eleven-byte
/// volume label, the eight-byte OEM name, the eight-byte type string — is padded on the
/// right with spaces, so the field is not the name: `FAT32   ` is a five-character string in
/// an eight-byte field. Every consumer that reads one of those fields wants the name, and
/// this is where the padding rule is stated.
///
/// Only the right end is trimmed. A leading space is a byte the field actually holds, and a
/// name trimmed at both ends would not be the name on the volume. A NUL is not this format's
/// padding either, so it survives — which is what keeps a field a foreign tool filled with
/// something other than spaces reported as it stands.
///
/// ```
/// # use ferrosys::fat::ondisk::unpadded;
/// assert_eq!(unpadded(b"FAT32   "), b"FAT32");
/// assert_eq!(unpadded(b"        "), b"");
/// // The left end is untouched, and a NUL is not padding here.
/// assert_eq!(unpadded(b" MSDOS5.0"), b" MSDOS5.0");
/// assert_eq!(unpadded(b"ab\0     "), b"ab\0");
/// ```
#[must_use]
pub fn unpadded(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |last| last + 1);
    &field[..end]
}

/// A failure recovering an on-disk structure from bytes.
///
/// The two variants are the whole of what parsing a FAT structure can fail on: there were
/// not enough bytes, or a structure that carries a signature did not carry the right one.
/// Everything else a reader objects to — a sector size that is not a power of two, a
/// cluster chain that leaves the volume — is a judgment about recovered fields rather than
/// a failure to recover them, and is reported as a [`Finding`](crate::Finding) with a
/// severity rather than as a parse error.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The input was shorter than the structure requires.
    #[error("{structure}: need {need} bytes, got {got}")]
    #[non_exhaustive]
    TooShort {
        /// The structure being parsed.
        structure: &'static str,
        /// Bytes the structure requires.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// A signature field did not hold its required value.
    #[error("{structure}: bad signature {found:#010x}, expected {expected:#010x}")]
    #[non_exhaustive]
    BadMagic {
        /// The structure being parsed.
        structure: &'static str,
        /// The value found on disk.
        found: u32,
        /// The value the format requires.
        expected: u32,
    },
}
