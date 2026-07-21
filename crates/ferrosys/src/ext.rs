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
/// POSIX ACLs in the on-disk form ext stores them in.
pub mod acl {
    pub use crate::acl::*;
}
/// The multi-range block allocator over a layout's free space.
pub mod alloc {
    pub use crate::alloc::*;
}
/// The tar/PAX archive [`Source`], behind the `tar` feature.
#[cfg(feature = "tar")]
pub mod archive {
    pub use crate::archive::*;
}
/// The metadata-checksum seam and its crc32c implementation.
pub mod csum {
    pub use crate::csum::*;
}
/// Directory block layout: linear and hash-indexed.
pub mod dir {
    pub use crate::dir::*;
}
/// Extent trees: the ext4 file block map.
pub mod extent {
    pub use crate::extent::*;
}
/// The typed feature set and the family selector.
pub mod feature {
    pub use crate::feature::*;
}
/// The pure geometry planner and the layout it produces.
pub mod geometry {
    pub use crate::geometry::*;
}
/// Directory-name hashes for hash-indexed directories.
pub mod hash {
    pub use crate::hash::*;
}
/// The format-time jbd2 journal: sizing and the v2 superblock.
pub mod journal {
    pub use crate::journal::*;
}
/// The materializer that writes the image against a layout.
pub mod materialize {
    pub use crate::materialize::*;
}
/// The pure inode model built from a source before any bytes are written.
pub mod model {
    pub use crate::model::*;
}
/// The byte-exact on-disk structures: superblock, inodes, directory entries, and more.
pub mod ondisk {
    pub use crate::ondisk::*;
}
/// The reader and the scan taxonomy it reports through.
pub mod read {
    pub use crate::read::*;
}
/// The input entries a format consumes: the tree builder and the `Source` trait.
pub mod source {
    pub use crate::source::*;
}

// The flat entry points and types, the crate's filesystem surface under one namespace.
pub use crate::acl::{Acl, AclEntry, AclError, AclQualifier};
pub use crate::alloc::{AllocError, Allocator};
#[cfg(feature = "tar")]
pub use crate::archive::{ArchiveError, ArchiveSource};
pub use crate::csum::{Checksummer, Crc32c, NullCsum};
pub use crate::dir::{DirBlock, DirBlockKind, DirError, DirLayout, HtreeDir, LinearDir};
pub use crate::extent::{ExtentError, ExtentNode, ExtentTree};
pub use crate::feature::{Compat, FeatureError, FeatureSet, Incompat, Profile, RoCompat};
pub use crate::geometry::{
    BlockRange, GeometryError, GroupLayout, GrowReservation, InodeCount, Layout, ReservedRatio,
    plan_layout,
};
pub use crate::hash::{DirHash, HashSignedness, HashVersion};
pub use crate::journal::{JournalSize, JournalSuperblock};
pub use crate::materialize::{ErrorBehavior, FormatError, FormatOptions, Image, format, format_to};
pub use crate::model::{FsModel, ModelConfig, ModelError, build_model};
pub use crate::ondisk::{ParseError, Xattr};
pub use crate::read::{
    Anomaly, Category, Entry, Location, ReadError, ReadPolicy, Reader, ScanReport, Severity,
    WalkEntry,
};
pub use crate::source::{EntryKind, Metadata, Source, SourceEntry, TreeBuilder};

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
