//! On-disk structures: the pure byte layer where a one-byte offset error is a silent
//! corruption.
//!
//! Every APFS structure this crate reads is defined here as a Rust value recovered through
//! accessors naming each field's offset, width and byte order. APFS is little-endian on disk
//! regardless of host byte order; there is no `unsafe`, no `transmute`, and no `#[repr(C)]`
//! reliance. Offsets and meanings are those of Apple's *Apple File System Reference*
//! (2020-06-22), cited by page, except where an image macOS wrote shows the reference to be
//! wrong, which each such place says. The same layer serializes what the writer emits, and each
//! layout and constant the writer emits is documented and observed: every field it fills is
//! found at that offset, holding what the writer puts there, on the containers macOS writes,
//! and the writer's own constants say what each was observed as.
//!
//! The layer has seven parts, and they stack:
//!
//! - **[`ObjectHeader`], [`checksum`], [`verify`], [`seal`]**: the 32 bytes every object
//!   begins with, and the checksum covering the rest.
//! - **[`ContainerSuperblock`]**: the container's block size, features, checkpoint areas,
//!   object map, and list of volumes.
//! - **[`ObjectMap`], [`MapKey`], [`MapValue`]**: how a virtual identifier at a transaction
//!   becomes a block.
//! - **[`Node`], [`NodeHeader`], [`TreeInfo`]**: one B-tree node, framed and bounds-checked.
//! - **[`VolumeSuperblock`]** and the records of its tree: [`InodeValue`], [`EntryKey`],
//!   [`EntryValue`], [`XattrValue`], [`FileExtent`], [`SiblingLink`], [`DataStream`], and the
//!   [`extended_fields`] an inode and a directory entry carry; and [`PhysicalExtent`], a record
//!   of an extent-reference tree giving a run of blocks its reference count and the record
//!   that wrote it.
//! - **[`SnapshotMeta`]** and **[`SnapshotExtension`]**: a snapshot's record in its volume's
//!   snapshot tree, and the object holding its identifier.
//! - **[`CheckpointMap`]**, **[`SpaceManager`]**, **[`ChunkList`]**, **[`FreeQueueKey`]** and
//!   **[`Reaper`]**: a checkpoint's ephemeral objects, and what the container keeps about which
//!   of its blocks are in use.
//!
//! # What is not here
//!
//! **Validation beyond recovery.** These types recover fields and report what makes recovery
//! impossible: too few bytes, a missing signature, a name without its terminator, a location
//! outside its node. Whether the recovered fields describe a container this crate can read
//! — an unknown feature bit, a block size the format does not define, an object of the wrong
//! type where a tree was expected — is asked one layer out, where the answer can name it.
//!
//! This module is pure: it moves bytes to and from values and performs no I/O.

mod container;
mod node;
mod object;
mod omap;
mod record;
mod snapshot;
mod space;
mod volume;

pub use container::{
    BlockRange, CHECKPOINT_AREA_IS_TREE, CONTAINER_MAGIC, COUNTERS, CheckpointAreas,
    ContainerSuperblock, MAX_BLOCK_SIZE, MAX_VOLUMES, MIN_BLOCK_SIZE,
    incompat as container_incompat,
};
pub use node::{
    CHILD_POINTER_SIZE, EntrySizes, NO_VALUE, NODE_DATA_START, Node, NodeFault, NodeHeader,
    TREE_ALLOW_GHOSTS, TREE_EPHEMERAL, TREE_HASHED, TREE_INFO_SIZE, TREE_KV_NONALIGNED,
    TREE_NO_HEADER, TREE_PHYSICAL, TREE_SEQUENTIAL_INSERT, TreeInfo, Unused, child_oid, node_flags,
};
pub use object::{ObjectHeader, Storage, checksum, kind, seal, verify};
pub use omap::{
    CRYPTO_GENERATION, MAP_CRYPTO_CHANGING, MAP_VALUE_DELETED, MapKey, MapValue, ObjectMap,
};
pub use record::{
    BSD_COMPRESSED, DECMPFS_XATTR, DataStream, ENTRY_TYPE_MASK, EXTENT_LENGTH_MASK, EntryKey,
    EntryValue, ExtendedField, FileExtent, ID_MASK, INTERNAL_BEING_TRUNCATED, INTERNAL_COMPRESSED,
    INTERNAL_EVER_CLONED, INTERNAL_WITH_RESOURCE_FORK, INTERNAL_WITH_SECURITY_ATTRIBUTE,
    INTERNAL_WITHOUT_RESOURCE_FORK, InodeValue, KIND_SHIFT, KeyHeader, PHYSICAL_LENGTH_MASK,
    PhysicalExtent, RESOURCE_FORK_XATTR, SECURITY_XATTR, SIBLING_ID_FIELD, SYMLINK_XATTR,
    SiblingLink, XattrValue, extended_field_blob, extended_fields, field, inode_field,
    inode_number, key_u64, record_kind, sibling_map_record, split_device, xattr_flags, xattr_key,
    xattr_key_size, xattr_name,
};
pub use snapshot::{SNAPSHOT_NAME_ID, SnapshotExtension, SnapshotMeta, snapshot_name_record};
pub use space::{
    CHECKPOINT_MAP_LAST, CI_COUNT_MASK, CheckpointMap, CheckpointMapping, ChunkInfo, ChunkList,
    FreeQueue, FreeQueueKey, REAPER_ALWAYS, REAPER_CONTINUE, ReapList, Reaper, SpaceDevice,
    SpaceManager,
};
pub use volume::{
    MODIFIED_BY_ENTRIES, ModifiedBy, VOLUME_MAGIC, VOLUME_NAME_LEN, VolumeSuperblock,
    incompat as volume_incompat, role_name, volume_flags,
};

/// A failure recovering an on-disk structure from bytes.
///
/// The three variants are the whole of what parsing an APFS structure can fail on: there were
/// not enough bytes, a structure carrying a signature did not carry it, or a name the format
/// stores with a terminator did not end in one. Everything else a reader objects to is a
/// judgment about recovered fields, reported by the layer that can say what it means.
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
    #[error("{structure}: not an APFS signature: {found:02x?}")]
    #[non_exhaustive]
    BadMagic {
        /// The structure being parsed.
        structure: &'static str,
        /// The four bytes found where the signature belongs.
        found: [u8; 4],
    },
    /// A name stored with a terminating NUL did not end in one.
    #[error("{structure}: the stored name does not end in its terminator")]
    #[non_exhaustive]
    Unterminated {
        /// The structure being parsed.
        structure: &'static str,
    },
}

impl ParseError {
    /// [`TooShort`](Self::TooShort) unless `buf` holds at least `need` bytes.
    fn need(structure: &'static str, need: usize, buf: &[u8]) -> Result<(), Self> {
        if buf.len() < need {
            return Err(Self::TooShort {
                structure,
                need,
                got: buf.len(),
            });
        }
        Ok(())
    }
}
