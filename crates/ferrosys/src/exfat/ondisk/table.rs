//! The allocation table's entry values: the two the format reserves at the head, and the two
//! that end a chain.
//!
//! An exFAT allocation table is an array of 32-bit cluster numbers and nothing else — no
//! structure, no header, no packing at three widths — so there is no type here, only the
//! values that are not cluster numbers. An entry is read and written through
//! [`get_u32`](crate::exfat::ondisk) and `put_u32` at four times its index, like any other
//! little-endian field.
//!
//! # The table is not the authority on what is allocated
//!
//! The allocation bitmap is. The table says what chains where, for the clusters a file
//! occupies; the bitmap says which clusters are in use at all. A volume where the two
//! disagree is a volume this crate does not write, because both are derived from one planned
//! allocation rather than maintained side by side.

/// Entry 0: the media descriptor in the low byte, and ones above it.
///
/// The low byte is `0xF8`, "fixed media", which is the one convention this format keeps from
/// the family it shares a name with. Nothing reads it; the format fixes the whole word.
pub const FAT_ENTRY_MEDIA: u32 = 0xFFFF_FFF8;

/// Entry 1: reserved, and fixed at all ones.
pub const FAT_ENTRY_RESERVED: u32 = 0xFFFF_FFFF;

/// The entry value that ends a cluster chain: this cluster is the last one.
pub const END_OF_CHAIN: u32 = 0xFFFF_FFFF;

/// The entry value marking a cluster the medium could not be relied on for.
///
/// A volume this crate writes has none — a fresh format has nothing to have failed on — and a
/// reader that meets one reports it rather than following it.
pub const BAD_CLUSTER: u32 = 0xFFFF_FFF7;
