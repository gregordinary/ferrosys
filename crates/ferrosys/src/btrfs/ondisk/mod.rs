//! On-disk structures: the pure byte layer where a one-byte offset error is a silent
//! corruption.
//!
//! Every btrfs metadata object this crate reads is defined here as a Rust value with symmetric
//! serialization: a `write_to` that produces its little-endian on-disk form and a `read_from`
//! that recovers it. btrfs is little-endian on disk regardless of host byte order, so every
//! field is read and written through an accessor naming its offset, its width, and its byte
//! order rather than through any reinterpret-cast; there is no `unsafe`, no `transmute`, and
//! no `#[repr(C)]` reliance.
//!
//! The layer has six parts, and they stack:
//!
//! - **[`DiskKey`] and [`ItemType`]** — the 17-byte tuple every tree is sorted by, and the
//!   byte that says what a record is. Nothing else in the format records an item's kind.
//! - **[`Header`], [`Item`], [`KeyPtr`]** — a tree block, and the two things one may hold.
//! - **[`SuperBlock`], [`RootBackup`], [`DevItem`], [`Chunk`], [`Stripe`], [`DevExtent`],
//!   [`DevStats`], [`RootItem`]** — where the filesystem begins, where it began four
//!   transactions ago, how logical space maps onto a device and back, and where each of its
//!   trees starts.
//! - **[`ExtentItem`], [`InlineRef`], [`BlockGroupItem`], [`FreeSpaceInfo`]** — what is
//!   allocated, who holds it, and what is free.
//! - **[`InodeItem`], [`DirItem`], [`FileExtentItem`], [`InodeRef`], [`InodeExtref`],
//!   [`RootRef`]** — what a filesystem tree holds: a file's metadata, the names it is known
//!   by, where its bytes are, and how a subvolume is reachable. Several of these pack into one
//!   item, and [`for_each_packed`] is the one place that framing is bounded.
//! - **[`checksum`] and [`seal`]** — the recipe covering the tree blocks, which the format
//!   arranges to be one recipe by giving a superblock and a tree block the same first field,
//!   and the writing of it that is the last thing done to either.
//!
//! # What is not here
//!
//! **Validation beyond recovery.** These types recover fields, and report the two things that
//! make recovery impossible: there were not enough bytes, or a structure carrying a signature
//! did not carry the right one. Whether the recovered fields describe a filesystem this crate
//! can read — a node size the format forbids, an `nritems` past what a block could hold, a
//! feature bit nothing here understands — is a separate question with a separate answer,
//! asked one layer out where the answer can name what it would take to read it.
//!
//! **The chunk map.** A [`Chunk`] and its [`Stripe`]s are a mapping written down; turning an
//! address into a place on a device means holding every chunk of the filesystem at once,
//! ordered and checked for overlap, which is [`ChunkMap`](crate::btrfs::ChunkMap)'s job.
//!
//! **A block's own length.** Only the superblock has a fixed width. A tree block is as long as
//! the filesystem's node size, which is a field of the superblock — so every bound over a
//! block is computed from a number the caller holds rather than from a constant here, and a
//! constant would have been right on one filesystem.
//!
//! This module is pure: it moves bytes to and from values and returns numbers. It allocates
//! nothing and performs no I/O.

mod chunk;
mod csum;
mod dir;
mod extent;
mod file;
mod inode;
mod key;
mod node;
mod packed;
mod root;
mod superblock;

pub use chunk::{BlockGroupFlags, Chunk, DevExtent, DevItem, DevStats, Stripe};
pub use csum::{
    CHECKSUM_COVERED_FROM, CSUM_FIELD_LEN, ChecksumType, checksum, crc32c_over, padding_is_clear,
    seal, stored_crc32c,
};
pub use dir::{DirEntryType, DirItem, RootRef};
pub use extent::{
    BlockGroupItem, ExtentDataRef, ExtentFlags, ExtentItem, FreeSpaceInfo, InlineRef,
};
pub use file::{Compression, ExtentKind, FileExtentItem};
pub use inode::{InodeExtref, InodeFlags, InodeItem, InodeRef};
pub use key::{DiskKey, ItemType, extref_hash, name_hash, objectid, uuid_key};
pub use node::{
    BACKREF_REV_MIXED, BACKREF_REV_SHIFT, HEADER_FLAG_RELOC, HEADER_FLAG_WRITTEN, Header, Item,
    KeyPtr, LEAF_LEVEL, MAX_LEVEL,
};
pub use packed::{Packed, for_each_packed};
pub use root::{RootFlags, RootItem, TIMESPEC_SIZE, read_timespec, write_timespec};
pub use superblock::{
    BACKUP_ROOTS_OFFSET, CompatFlags, CompatRoFlags, IncompatFlags, LABEL_SIZE, MAGIC,
    MAX_BLOCK_SIZE, MIN_BLOCK_SIZE, MIRRORS, NUM_BACKUP_ROOTS, RootBackup, SUPER_INFO_SIZE,
    SYS_CHUNK_ARRAY_SIZE, SuperBlock, SuperFlags, holds_mirror,
};

/// A failure recovering an on-disk structure from bytes.
///
/// The two variants are the whole of what parsing a btrfs structure can fail on: there were
/// not enough bytes, or the one structure that carries a signature did not carry it.
/// Everything else a reader objects to — a node size the format does not define, an item whose
/// data escapes its leaf, a feature bit nothing here implements — is a judgment about
/// recovered fields rather than a failure to recover them, and is reported by the layer that
/// can say what it means.
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
    ///
    /// Only the superblock has one. A tree block is identified by where it was found and by
    /// the header fields naming its own address and filesystem, not by a signature — which is
    /// why a block read from the wrong place is caught by a different check than this.
    #[error("{structure}: not a btrfs signature: {found:02x?}")]
    #[non_exhaustive]
    BadMagic {
        /// The structure being parsed.
        structure: &'static str,
        /// The eight bytes found where the signature belongs.
        found: [u8; 8],
    },
}
