//! On-disk structures: the pure byte layer where a one-byte offset error is a silent
//! corruption.
//!
//! Every exFAT metadata object — the Main Boot Sector, the sectors behind it, and the
//! 32-byte directory entry — is defined here as a Rust value with symmetric serialization: a
//! `write_to` that produces its little-endian on-disk form and a `read_from` that recovers
//! it. exFAT is little-endian on disk regardless of host byte order, so every field is read
//! and written through an accessor naming its offset, its width, and its byte order rather
//! than through any reinterpret-cast; there is no `unsafe`, no `transmute`, and no
//! `#[repr(C)]` reliance.
//!
//! The four checksums are here too, because each is a field of one of these structures
//! computed over the bytes of another: the boot region's over its own first eleven sectors,
//! the up-case table's over the table it describes, a directory entry set's over the set it
//! opens, and a name's hash over the name behind it. So is the up-case table the format
//! recommends, which is data a volume carries rather than a structure it lays out — and the
//! only heap resident whose bytes do not follow from the geometry.
//!
//! This module is pure: it moves bytes to and from values, and returns numbers. It allocates
//! no clusters and performs no I/O.
//!
//! # What is not here
//!
//! **The geometry.** Where the allocation table and the cluster heap begin, how long each
//! is, and how many clusters a volume holds are fields the boot sector records and
//! arithmetic derives — so the derivation lives with the planner, in
//! [`plan_layout`](crate::exfat::plan_layout), and this layer moves the numbers without
//! forming an opinion about them.
//!
//! **Validation.** These types recover fields and report a length or a signature that makes
//! recovery impossible. Whether the recovered fields describe a filesystem is a separate
//! question with a separate answer, because a classifier and a reader want it asked with
//! different strictness.
//!
//! **A sector's size.** Only the Main Boot Sector has a fixed width. The eleven sectors
//! behind it are as long as the volume's sectors are, so each is reached through a function
//! over a caller-sized buffer rather than through a structure with a `SIZE` — a signature at
//! "the end of the sector" is at a different offset on every volume, and a constant would
//! have been right on one of them.

mod boot;
mod csum;
mod dirent;
mod table;
mod time;
mod upcase;

pub use boot::{
    BACKUP_BOOT_REGION_SECTOR, BOOT_CODE_LEN, BOOT_REGION_SECTORS, BOOT_SIGNATURE, CHECKSUM_SECTOR,
    EXTENDED_BOOT_FIRST_SECTOR, EXTENDED_BOOT_SECTORS, EXTENDED_BOOT_SIGNATURE,
    FILE_SYSTEM_MAJOR_REVISION, FILE_SYSTEM_MINOR_REVISION, FILE_SYSTEM_NAME, FILE_SYSTEM_REVISION,
    MAIN_BOOT_REGION_SECTOR, MAX_CLUSTER_SHIFT, MUST_BE_ZERO_RANGE, MainBootSector,
    OEM_PARAMETERS_SECTOR, PERCENT_IN_USE_MAX, PERCENT_IN_USE_UNKNOWN, RESERVED_SECTOR,
    VOLUME_FLAG_ACTIVE_FAT, VOLUME_FLAG_CLEAR_TO_ZERO, VOLUME_FLAG_MEDIA_FAILURE,
    VOLUME_FLAG_VOLUME_DIRTY, checksum_sector_value, extended_boot_signature, percent_in_use,
    write_checksum_sector, write_extended_boot_sector,
};
pub use csum::{
    BOOT_CHECKSUM_SKIPS, SET_CHECKSUM_SKIPS, boot_checksum, entry_set_checksum, name_hash,
    upcase_checksum,
};
pub use dirent::{
    AllocationBitmapEntry, DIR_ENTRY_SIZE, DirEntry, EntryType, FileAttributes, FileEntry,
    FileNameEntry, MAX_LABEL_UNITS, MAX_NAME_ENTRIES, MAX_NAME_UNITS, MAX_SECONDARY_COUNT,
    NAME_UNITS_PER_ENTRY, SECONDARY_ALLOCATION_POSSIBLE, SECONDARY_NO_FAT_CHAIN,
    StreamExtensionEntry, UpcaseTableEntry, VolumeLabelEntry,
};
pub use table::{BAD_CLUSTER, END_OF_CHAIN, FAT_ENTRY_MEDIA, FAT_ENTRY_RESERVED};
pub use time::{
    UTC_OFFSET, UTC_OFFSET_VALID, pack_timestamp, unpack_timestamp, utc_offset_minutes,
};
pub use upcase::{
    RECOMMENDED_UPCASE_BYTES, RECOMMENDED_UPCASE_CHECKSUM, RECOMMENDED_UPCASE_TABLE,
    UPCASE_IDENTITY_RUN, UpcaseTable, write_upcase_table,
};

/// A failure recovering an on-disk structure from bytes.
///
/// The two variants are the whole of what parsing an exFAT structure can fail on: there were
/// not enough bytes, or a structure that carries a signature did not carry the right one.
/// Everything else a reader objects to — a sector shift the format does not define, a
/// cluster chain that leaves the volume — is a judgment about recovered fields rather than a
/// failure to recover them, and is reported as a [`Finding`](crate::Finding) with a severity
/// rather than as a parse error.
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
