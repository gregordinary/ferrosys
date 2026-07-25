//! The ext2/ext3/ext4 family: the formatter, the reader, and the byte-exact on-disk
//! structures.
//!
//! This module is the crate's filesystem surface. [`format()`] and [`format_to()`] write
//! an image, [`Reader`] reads one back, and [`TreeBuilder`] and [`Source`] describe the
//! tree to write. The layer modules ([`geometry`], [`ondisk`], [`extent`], and the rest)
//! expose the machinery beneath them. The convenience constructors [`ext4`], [`ext3`], and
//! [`ext2`] name a family's baseline directly, as sugar over
//! [`FormatOptions::profile`].
//!
//! The family selector [`Profile`] and the [`FeatureSet`] every layer consults, the
//! findings taxonomy a scan speaks ([`Anomaly`], [`ScanReport`]), and the
//! metadata-checksum seam ([`Checksummer`], [`Crc32c`]) are this family's own vocabulary,
//! re-exported here. The crate root carries the family-agnostic
//! [`crc32c`](crate::crc32c) primitive they build on.
//!
//! # Example
//!
//! ```
//! use ferrosys::ext::ondisk::Timestamp;
//! use ferrosys::ext::{format, FormatOptions, GrowReservation, Metadata, Reader, TreeBuilder};
//!
//! let time = Timestamp::from_secs(1_700_000_000);
//! let source = TreeBuilder::new()
//!     .directory(b"/etc".to_vec(), Metadata::new(0o755, time))
//!     .file(b"/etc/hostname".to_vec(), b"ferrosys\n".to_vec(), Metadata::new(0o644, time));
//!
//! // Format a 64 MiB image reserving descriptor blocks to grow up to 32 GiB.
//! let mut options = FormatOptions::new([0x11; 16], time, [0u8; 16]);
//! options.grow = GrowReservation::UpTo(32 << 30);
//! let image = format(source, 64 << 20, options).expect("format");
//!
//! // Read it back with the crate's own reader, over any Read + Seek source.
//! let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
//! let root = reader.inode(2).expect("root inode");
//! let contents = reader.read_dir(&root).expect("read root");
//! assert!(contents.iter().any(|e| e.name == b"etc"));
//! ```

// The layer modules, presented under `ext`. Each is a facade over the like-named private
// module at the crate root, so `ext::ondisk::SuperBlock` reaches it while the module's own
// cross-references stay `crate::`.
//
// A layer module carries what is *not* lifted flat below: the constants that state its
// contract, the on-disk structures, and the machinery a caller reaches into the layer for.
// Every public item has exactly one path — a type reached flat is not also reached here,
// so rustdoc lists it once and a consumer has one idiom rather than two that both compile.
//
// Every re-export is named. A glob would make anything marked `pub` for one module's
// convenience into public API the moment it was written, and public API can only be
// withdrawn with a major version. Naming them makes each item's publicness a decision,
// and `ci/public-api.sh` holds the whole surface to a committed snapshot so adding one
// shows up as a reviewed line rather than as nothing at all.
/// The permission bits a POSIX ACL entry carries.
pub mod acl {
    pub use crate::acl::{EXEC, READ, WRITE};
}
/// Extent trees: the ext4 file block map, and the machinery that shapes and serializes
/// one.
pub mod extent {
    pub use crate::extent::{
        ExtentNodeBlock, MAX_EXTENT_DEPTH, MAX_EXTENT_LEN, TreeShape, build_leaves, build_tree,
        node_capacity, parse_node, plan_tree, tail_offset, write_node,
    };
}
/// The thresholds the feature model states.
pub mod feature {
    pub use crate::feature::LARGE_FILE_MIN_SIZE;
}
/// The block-count ceilings a layout is planned within.
pub mod geometry {
    pub use crate::geometry::{MAX_32BIT_BLOCKS, MAX_EXTENT_BLOCKS};
}
/// Directory-name hashing, the function a hash-indexed directory orders its entries by.
pub mod hash {
    pub use crate::hash::dir_hash;
}
/// The format-time jbd2 journal: its magic words, its size floor, and the sizing and
/// superblock construction behind [`JournalSize`].
pub mod journal {
    pub use crate::journal::{
        JBD2_MAGIC, JBD2_SUPERBLOCK_V2, MIN_JOURNAL_BLOCKS, build_superblock,
        default_journal_blocks,
    };
}
/// The pure inode model built from a source before any bytes are written: the inodes it
/// holds, the directory entries between them, and the numbers reserved at its head.
pub mod model {
    pub use crate::model::{
        Content, DirChild, FIRST_USER_INO, LOST_FOUND_INO, ModelInode, ROOT_INO,
    };
}
/// The byte-exact on-disk structures: superblock, inodes, directory entries, and more.
pub mod ondisk {
    pub use crate::ondisk::{
        BG_BLOCK_UNINIT, BG_INODE_UNINIT, BG_INODE_ZEROED, DIR_TAIL_LEN, DX_CHECKSUM_OFFSET,
        DX_ENTRY_LEN, DX_HASH_CONTINUED, DX_MAX_INDIRECT_LEVELS, DX_NODE_COUNT_OFFSET,
        DX_ROOT_COUNT_OFFSET, DX_TAIL_LEN, DirEntry, DxEntry, EXTENT_ENTRY_SIZE, EXTENT_MAGIC,
        EXTENT_TAIL_LEN, ExtentHeader, ExtentIdx, ExtentLeaf, FileType, GOOD_OLD_FIRST_INODE,
        GOOD_OLD_INODE_SIZE, GroupDescriptor, Inode, InodeFlags, ORPHAN_BLOCK_MAGIC,
        ORPHAN_TAIL_LEN, ROOT_INODE_MODE, SUPERBLOCK_MAGIC, SuperBlock, Timestamp, dx_limit,
        dx_tail_offset, extra_isize_for, min_rec_len, orphan_entries_len, orphan_tail_bytes,
        read_dx_countlimit, read_dx_entries, read_dx_root_info, read_orphan_tail,
        rec_len_from_disk, rec_len_to_disk, write_dir_tail, write_dx_entries, write_dx_node_header,
        write_dx_root_header, write_dx_tail,
    };
}
/// The bounds a read is held to, and the version of the scan document it emits.
pub mod read {
    pub use crate::read::{MAX_SYMLINK_HOPS, MIN_DIRENT_LEN, SCAN_SCHEMA_VERSION};
}

// The flat entry points and types, the crate's filesystem surface under one namespace.
//
// Constants are not lifted here. Every value naming a bound, a threshold, a magic word, or
// a schema version is reached through the layer module that defines it —
// `ext::read::SCAN_SCHEMA_VERSION`, `ext::read::MIN_DIRENT_LEN`,
// `ext::feature::LARGE_FILE_MIN_SIZE`, `ext::journal::JBD2_MAGIC` — because a constant is a
// detail of the layer whose contract it states, and the layers hold nearly forty of them:
// lifting one is a decision about all of them. Free functions are lifted only where they
// are the pipeline's entry points (`plan_layout`, `build_model`, `format`, `format_to`); a
// layer's own helpers stay in their module.
pub use crate::acl::{Acl, AclEntry, AclError, AclQualifier};
pub use crate::alloc::{AllocError, Allocator};
#[cfg(feature = "tar")]
pub use crate::archive::{ArchiveError, ArchiveSink, ArchiveSource};
pub use crate::csum::{Checksummer, Crc32c, CsumScheme, NullCsum};
pub use crate::dir::{DirBlock, DirBlockKind, DirError, DirLayout, HtreeDir, LinearDir};
pub use crate::extent::{ExtentError, ExtentNode, ExtentTree};
pub use crate::feature::{Compat, FeatureError, FeatureSet, Incompat, Profile, RoCompat};
pub use crate::geometry::{
    BlockRange, GeometryError, GroupLayout, GrowReservation, InodeCount, Layout, PlanRequest,
    ReservedRatio, plan_layout,
};
pub use crate::hash::{DirHash, HashSignedness, HashVersion};
#[cfg(all(feature = "dir", any(target_os = "linux", target_os = "android")))]
pub use crate::host::{DirectorySource, HostError};
pub use crate::journal::{JournalParams, JournalSize, JournalSuperblock};
pub use crate::materialize::{
    ErrorBehavior, FormatError, FormatOptions, FormatPlan, Image, format, format_to,
};
pub use crate::model::{FsModel, ModelConfig, ModelError, build_model};
pub use crate::ondisk::{ParseError, Xattr};
pub use crate::read::{
    Anomaly, Category, Entry, Limits, Location, OpenOptions, ReadError, ReadPolicy, Reader,
    ScanReport, Severity, WalkEntry,
};
pub use crate::source::{
    EntryKind, FileContent, FileRange, Metadata, Source, SourceEntry, TreeBuilder,
};

use crate::ondisk::Timestamp;

/// Format options seeded for an ext4 image: the extent-mapped, checksummed, journalled
/// default. Sugar for [`FormatOptions::new`] followed by
/// [`profile`](FormatOptions::profile) with [`Profile::Ext4`].
#[must_use]
pub fn ext4(uuid: [u8; 16], time: Timestamp, hash_seed: [u8; 16]) -> FormatOptions {
    FormatOptions::new(uuid, time, hash_seed).profile(Profile::Ext4)
}

/// Format options seeded for the ext3 baseline: a block-mapped filesystem with a journal.
/// Sugar for [`FormatOptions::new`] with [`Profile::Ext3`].
#[must_use]
pub fn ext3(uuid: [u8; 16], time: Timestamp, hash_seed: [u8; 16]) -> FormatOptions {
    FormatOptions::new(uuid, time, hash_seed).profile(Profile::Ext3)
}

/// Format options seeded for the ext2 baseline: a block-mapped filesystem with no journal.
/// Sugar for [`FormatOptions::new`] with [`Profile::Ext2`].
#[must_use]
pub fn ext2(uuid: [u8; 16], time: Timestamp, hash_seed: [u8; 16]) -> FormatOptions {
    FormatOptions::new(uuid, time, hash_seed).profile(Profile::Ext2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_family_constructors_seed_the_matching_baseline() {
        let time = Timestamp::from_secs(1_700_000_000);
        assert_eq!(ext4([1; 16], time, [0; 16]).feature, FeatureSet::DEFAULT);
        assert_eq!(ext3([1; 16], time, [0; 16]).feature, FeatureSet::EXT3);
        assert_eq!(ext2([1; 16], time, [0; 16]).feature, FeatureSet::EXT2);
        // The identity inputs are carried straight through.
        let opts = ext4([9; 16], time, [3; 16]);
        assert_eq!(opts.uuid, [9; 16]);
        assert_eq!(opts.hash_seed, [3; 16]);
    }
}
