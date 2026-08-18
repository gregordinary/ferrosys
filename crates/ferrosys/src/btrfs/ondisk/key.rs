//! The key every btrfs tree is sorted by, and the two vocabularies it is written in.
//!
//! A btrfs B-tree holds no field that says what kind of record an item is. The key does: a
//! 17-byte tuple of an object's id, a one-byte type, and an offset whose meaning is decided by
//! that type. Every tree is sorted by the tuple in that order, so "the extended attributes of
//! inode 257" is a contiguous range and finding it is one descent.
//!
//! This module is pure: it moves bytes to and from values and answers questions about them.

use crate::bytes::{get_u8, get_u64, put_u8, put_u64};

use super::ParseError;

/// The one-byte middle field of a key: what kind of record an item holds.
///
/// A newtype rather than an enum, because the value comes off an image and the format grows
/// types between releases. An unrecognized type is a value this reader has no opinion about
/// sitting beside values it does — never a reason to refuse the filesystem — so it is kept as
/// it was found and [`name`](Self::name) answers [`None`] for it.
///
/// The ordering is the byte's, which is what the on-disk sort is.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ItemType(u8);

impl ItemType {
    /// A file, directory, or other object's metadata: mode, ownership, size, and times.
    pub const INODE_ITEM: Self = Self(1);
    /// A name an inode is known by in its parent directory.
    pub const INODE_REF: Self = Self(12);
    /// The same, for an inode with more names than one item can hold.
    pub const INODE_EXTREF: Self = Self(13);
    /// One extended attribute, keyed by the hash of its name.
    pub const XATTR_ITEM: Self = Self(24);
    /// The fs-verity descriptor of a file.
    pub const VERITY_DESC_ITEM: Self = Self(36);
    /// A block of a file's fs-verity Merkle tree.
    pub const VERITY_MERKLE_ITEM: Self = Self(37);
    /// An encrypted inode's fscrypt context.
    pub const FSCRYPT_INODE_CTX: Self = Self(41);
    /// An fscrypt context a subvolume carries.
    pub const FSCRYPT_CTX: Self = Self(42);
    /// An inode whose last name was removed while it was still open.
    pub const ORPHAN_ITEM: Self = Self(48);
    /// A directory's log record, written while a log tree is live.
    pub const DIR_LOG_ITEM: Self = Self(60);
    /// The index half of the same.
    pub const DIR_LOG_INDEX: Self = Self(72);
    /// A directory entry keyed by the hash of its name: the form a lookup finds.
    pub const DIR_ITEM: Self = Self(84);
    /// The same entry keyed by its sequence number: the form a readdir walks.
    pub const DIR_INDEX: Self = Self(96);
    /// A run of a file's bytes — held inside the item for a small file, and addressed by an
    /// extent for a large one.
    pub const EXTENT_DATA: Self = Self(108);
    /// The data checksums covering a run of logical bytes.
    pub const EXTENT_CSUM: Self = Self(128);
    /// The root of one tree: every subvolume has one, and so does every tree the filesystem
    /// keeps of its own.
    pub const ROOT_ITEM: Self = Self(132);
    /// A subvolume's link back to the directory it is reachable through.
    pub const ROOT_BACKREF: Self = Self(144);
    /// The forward half of the same link.
    pub const ROOT_REF: Self = Self(156);
    /// One allocated extent, and how many references it has.
    pub const EXTENT_ITEM: Self = Self(168);
    /// The same for a metadata block, in the shorter form `skinny-metadata` writes.
    pub const METADATA_ITEM: Self = Self(169);
    /// Which subvolume owns an extent, under simple quotas.
    pub const EXTENT_OWNER_REF: Self = Self(172);
    /// A reference to a tree block from the tree that owns it.
    pub const TREE_BLOCK_REF: Self = Self(176);
    /// A reference to a data extent from the file that holds it.
    pub const EXTENT_DATA_REF: Self = Self(178);
    /// A reference to a tree block through a snapshot, which shares it.
    pub const SHARED_BLOCK_REF: Self = Self(182);
    /// A reference to a data extent through a snapshot.
    pub const SHARED_DATA_REF: Self = Self(184);
    /// One block group: a contiguous run of logical space of a single kind and profile.
    pub const BLOCK_GROUP_ITEM: Self = Self(192);
    /// How one block group's free space is recorded — as extents, or as a bitmap.
    pub const FREE_SPACE_INFO: Self = Self(198);
    /// One run of free space.
    pub const FREE_SPACE_EXTENT: Self = Self(199);
    /// A bitmap of free space, for a block group too fragmented for extents.
    pub const FREE_SPACE_BITMAP: Self = Self(200);
    /// A run of a device's bytes, and the chunk that occupies it.
    pub const DEV_EXTENT: Self = Self(204);
    /// One device of the filesystem.
    pub const DEV_ITEM: Self = Self(216);
    /// One chunk: a run of logical space, and where on which devices it lives.
    pub const CHUNK_ITEM: Self = Self(228);
    /// A stripe of a chunk, under the RAID stripe tree.
    pub const RAID_STRIPE: Self = Self(230);
    /// Whether quota accounting is on, and whether it is consistent.
    pub const QGROUP_STATUS: Self = Self(240);
    /// One quota group's accounting.
    pub const QGROUP_INFO: Self = Self(242);
    /// One quota group's limits.
    pub const QGROUP_LIMIT: Self = Self(244);
    /// One quota group's membership of another.
    pub const QGROUP_RELATION: Self = Self(246);
    /// A record that lives only while an operation is in progress — a balance, or the
    /// free-space cache the free-space tree replaced.
    pub const TEMPORARY_ITEM: Self = Self(248);
    /// A record kept across mounts, such as a device's error counters.
    pub const PERSISTENT_ITEM: Self = Self(249);
    /// The state of a device replacement.
    pub const DEV_REPLACE: Self = Self(250);
    /// A subvolume's UUID, mapped back to the subvolume it belongs to.
    pub const UUID_SUBVOL: Self = Self(251);
    /// The UUID a received subvolume carried when it was sent.
    pub const UUID_RECEIVED_SUBVOL: Self = Self(252);
    /// A free-form string, which nothing in a filesystem this crate reads uses.
    pub const STRING_ITEM: Self = Self(253);

    /// The on-disk byte.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Wrap an on-disk byte, whatever it holds.
    #[must_use]
    pub const fn from_value(value: u8) -> Self {
        Self(value)
    }

    /// The name this type is known by, or [`None`] where the byte is one the format has not
    /// given a meaning this release knows.
    ///
    /// Two of the bytes name two records each, and the second name is what a filesystem
    /// actually carries: 248 is `BALANCE_ITEM` in the older vocabulary and `TEMPORARY_ITEM`
    /// in the one that replaced it, 249 likewise `DEV_STATS` and `PERSISTENT_ITEM`. The
    /// current name is the one answered, which is what the pinned baseline prints for the
    /// same byte.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::INODE_ITEM => "INODE_ITEM",
            Self::INODE_REF => "INODE_REF",
            Self::INODE_EXTREF => "INODE_EXTREF",
            Self::XATTR_ITEM => "XATTR_ITEM",
            Self::VERITY_DESC_ITEM => "VERITY_DESC_ITEM",
            Self::VERITY_MERKLE_ITEM => "VERITY_MERKLE_ITEM",
            Self::FSCRYPT_INODE_CTX => "FSCRYPT_INODE_CTX",
            Self::FSCRYPT_CTX => "FSCRYPT_CTX",
            Self::ORPHAN_ITEM => "ORPHAN_ITEM",
            Self::DIR_LOG_ITEM => "DIR_LOG_ITEM",
            Self::DIR_LOG_INDEX => "DIR_LOG_INDEX",
            Self::DIR_ITEM => "DIR_ITEM",
            Self::DIR_INDEX => "DIR_INDEX",
            Self::EXTENT_DATA => "EXTENT_DATA",
            Self::EXTENT_CSUM => "EXTENT_CSUM",
            Self::ROOT_ITEM => "ROOT_ITEM",
            Self::ROOT_BACKREF => "ROOT_BACKREF",
            Self::ROOT_REF => "ROOT_REF",
            Self::EXTENT_ITEM => "EXTENT_ITEM",
            Self::METADATA_ITEM => "METADATA_ITEM",
            Self::EXTENT_OWNER_REF => "EXTENT_OWNER_REF",
            Self::TREE_BLOCK_REF => "TREE_BLOCK_REF",
            Self::EXTENT_DATA_REF => "EXTENT_DATA_REF",
            Self::SHARED_BLOCK_REF => "SHARED_BLOCK_REF",
            Self::SHARED_DATA_REF => "SHARED_DATA_REF",
            Self::BLOCK_GROUP_ITEM => "BLOCK_GROUP_ITEM",
            Self::FREE_SPACE_INFO => "FREE_SPACE_INFO",
            Self::FREE_SPACE_EXTENT => "FREE_SPACE_EXTENT",
            Self::FREE_SPACE_BITMAP => "FREE_SPACE_BITMAP",
            Self::DEV_EXTENT => "DEV_EXTENT",
            Self::DEV_ITEM => "DEV_ITEM",
            Self::CHUNK_ITEM => "CHUNK_ITEM",
            Self::RAID_STRIPE => "RAID_STRIPE",
            Self::QGROUP_STATUS => "QGROUP_STATUS",
            Self::QGROUP_INFO => "QGROUP_INFO",
            Self::QGROUP_LIMIT => "QGROUP_LIMIT",
            Self::QGROUP_RELATION => "QGROUP_RELATION",
            Self::TEMPORARY_ITEM => "TEMPORARY_ITEM",
            Self::PERSISTENT_ITEM => "PERSISTENT_ITEM",
            Self::DEV_REPLACE => "DEV_REPLACE",
            Self::UUID_SUBVOL => "UUID_KEY_SUBVOL",
            Self::UUID_RECEIVED_SUBVOL => "UUID_KEY_RECEIVED_SUBVOL",
            Self::STRING_ITEM => "STRING_ITEM",
            _ => return None,
        })
    }
}

/// The object ids the format gives a fixed meaning.
///
/// An id is otherwise an inode number within a subvolume, or a chunk's logical start within
/// the chunk tree, so only the ones below mean the same thing on every filesystem. The
/// negative ones are `u64` values near the top of the range, which is how the format spells a
/// small negative number and why they read as enormous in a key.
pub mod objectid {
    /// The tree of tree roots: every other tree's `ROOT_ITEM` lives here.
    pub const ROOT_TREE: u64 = 1;
    /// The same value inside the chunk tree, where it keys the device items rather than a
    /// tree root.
    pub const DEV_ITEMS: u64 = 1;
    /// Every allocated extent and its references.
    pub const EXTENT_TREE: u64 = 2;
    /// The map from logical addresses to places on devices.
    pub const CHUNK_TREE: u64 = 3;
    /// Which chunk occupies which run of each device — the chunk tree read the other way
    /// round.
    pub const DEV_TREE: u64 = 4;
    /// The filesystem tree of the top-level subvolume.
    pub const FS_TREE: u64 = 5;
    /// The directory in the root tree that names subvolumes.
    pub const ROOT_TREE_DIR: u64 = 6;
    /// The checksums covering every data extent.
    pub const CSUM_TREE: u64 = 7;
    /// Quota accounting.
    pub const QUOTA_TREE: u64 = 8;
    /// Subvolume UUIDs, mapped back to the subvolumes holding them.
    pub const UUID_TREE: u64 = 9;
    /// Free space per block group, under `free-space-tree`.
    pub const FREE_SPACE_TREE: u64 = 10;
    /// Block groups, under `block-group-tree` — where they live instead of in the extent
    /// tree.
    pub const BLOCK_GROUP_TREE: u64 = 11;
    /// Stripe placement, under `raid-stripe-tree`.
    pub const RAID_STRIPE_TREE: u64 = 12;
    /// Logical address remapping, under `remap-tree`.
    pub const REMAP_TREE: u64 = 13;
    /// The checksums covering data extents, which is what every `EXTENT_CSUM` item in the
    /// checksum tree is keyed by. A logical address is the key's *offset* rather than its
    /// objectid, so every checksum item shares this one id.
    pub const EXTENT_CSUM: u64 = u64::MAX - 9;
    /// The free-space cache the free-space tree replaced.
    pub const FREE_SPACE: u64 = u64::MAX - 10;
    /// The tree relocation holds a subvolume in while a balance moves it.
    pub const TREE_RELOC: u64 = u64::MAX - 7;
    /// The subvolume data relocation copies extents through while a balance moves them.
    /// **Every image the baseline writes carries this root**, so a reader that treats an
    /// unnamed id in the root tree as a surprise meets one on the first filesystem it opens.
    pub const DATA_RELOC_TREE: u64 = u64::MAX - 8;
    /// The lowest id a subvolume or an inode may take: everything below is the format's.
    pub const FIRST_FREE: u64 = 256;
    /// The same value in the chunk tree, where it keys every chunk item.
    pub const FIRST_CHUNK_TREE: u64 = 256;
    /// The highest id a subvolume or an inode may take.
    pub const LAST_FREE: u64 = u64::MAX - 255;

    /// The name this id is known by, or [`None`] where it is an inode number, a subvolume, or
    /// a chunk's logical start rather than one of the format's own.
    ///
    /// [`ROOT_TREE`] and [`DEV_ITEMS`] are one value, and so are [`FIRST_FREE`] and
    /// [`FIRST_CHUNK_TREE`]: which of each pair a key means follows from the tree the key was
    /// read out of, which this function is not told. It answers the tree-root name in both
    /// cases, that being the reading a key in the root tree has.
    #[must_use]
    pub const fn name(objectid: u64) -> Option<&'static str> {
        Some(match objectid {
            ROOT_TREE => "ROOT_TREE",
            EXTENT_TREE => "EXTENT_TREE",
            CHUNK_TREE => "CHUNK_TREE",
            DEV_TREE => "DEV_TREE",
            FS_TREE => "FS_TREE",
            ROOT_TREE_DIR => "ROOT_TREE_DIR",
            CSUM_TREE => "CSUM_TREE",
            QUOTA_TREE => "QUOTA_TREE",
            UUID_TREE => "UUID_TREE",
            FREE_SPACE_TREE => "FREE_SPACE_TREE",
            BLOCK_GROUP_TREE => "BLOCK_GROUP_TREE",
            RAID_STRIPE_TREE => "RAID_STRIPE_TREE",
            REMAP_TREE => "REMAP_TREE",
            TREE_RELOC => "TREE_RELOC",
            DATA_RELOC_TREE => "DATA_RELOC_TREE",
            EXTENT_CSUM => "EXTENT_CSUM",
            FREE_SPACE => "FREE_SPACE",
            _ => return None,
        })
    }
}

/// The key offset a name in a directory is stored under: the hash a `DIR_ITEM` and an
/// `XATTR_ITEM` are keyed by.
///
/// A directory holds every entry twice. The `DIR_ITEM` copy is keyed by this, so finding a name
/// is one descent rather than a scan — and two names that hash alike land under one key, which
/// is why an item may hold more than one record.
///
/// **This is crc32c with a seed of its own and no final inversion**, where a checksum in this
/// filesystem seeds with all-ones and inverts. Two constructions over one polynomial, and a
/// lookup built on the wrong one finds nothing on a filesystem nothing is wrong with.
#[must_use]
pub fn name_hash(name: &[u8]) -> u64 {
    u64::from(crate::crc32c(!1, name))
}

/// The key offset an `INODE_EXTREF` is stored under.
///
/// The extended form moves the parent directory out of the key to make room for the name, so
/// the key has to distinguish the same name in two directories — which it does by seeding the
/// hash with the parent's own id, truncated to the width the seed has.
#[must_use]
pub fn extref_hash(parent_objectid: u64, name: &[u8]) -> u64 {
    u64::from(crate::crc32c(parent_objectid as u32, name))
}

/// The `(objectid, offset)` a subvolume's UUID is keyed by in the UUID tree.
///
/// The tree exists to answer "which subvolume is this UUID?", so the UUID has to be the key —
/// and a key holds two eight-byte numbers where a UUID is sixteen bytes, which is exactly
/// enough. It is split in the middle and each half read little-endian, the same way every
/// number in this format is read.
///
/// The item's *data* is the subvolume's id, so the mapping is key to value and the key is the
/// whole question.
#[must_use]
pub fn uuid_key(uuid: [u8; 16]) -> (u64, u64) {
    let (low, high) = uuid.split_at(8);
    (
        u64::from_le_bytes(low.try_into().expect("eight bytes")),
        u64::from_le_bytes(high.try_into().expect("eight bytes")),
    )
}

/// The 17-byte key an item or a child pointer carries, and the tuple every tree is sorted by.
///
/// The three fields are compared in the order they are declared, unsigned, which is the
/// on-disk sort — so the derived [`Ord`] is the format's own and a search may rely on it. What
/// [`offset`](Self::offset) means is decided by [`kind`](Self::kind): a byte offset within a
/// file for an `EXTENT_DATA`, the hash of a name for a `DIR_ITEM`, a length for a
/// `METADATA_ITEM`, and nothing at all for a `ROOT_ITEM`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DiskKey {
    /// The object this record belongs to: an inode number, a tree's own id, or a chunk's
    /// logical start, depending on the tree.
    pub objectid: u64,
    /// What kind of record it is, and therefore what `offset` means.
    pub kind: ItemType,
    /// The third and last sort field, read according to `kind`.
    pub offset: u64,
}

impl DiskKey {
    /// Bytes on disk: `objectid`(8, little-endian), `kind`(1), `offset`(8, little-endian).
    pub const SIZE: usize = 17;

    /// The lowest key in the sort order, which every tree begins at or after.
    pub const MIN: Self = Self::new(0, ItemType::from_value(0), 0);

    /// A key over `objectid`, `kind`, and `offset`.
    #[must_use]
    pub const fn new(objectid: u64, kind: ItemType, offset: u64) -> Self {
        Self {
            objectid,
            kind,
            offset,
        }
    }

    /// The first key any record of `objectid` and `kind` could have: the start of that
    /// contiguous run, which is what a search for "the entries of this directory" asks for.
    #[must_use]
    pub const fn first_of(objectid: u64, kind: ItemType) -> Self {
        Self::new(objectid, kind, 0)
    }

    /// Recover a key from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than a key.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "btrfs_disk_key",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            objectid: get_u64(buf, 0),
            kind: ItemType::from_value(get_u8(buf, 8)),
            offset: get_u64(buf, 9),
        })
    }

    /// Write the key into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than a key. Every caller sizes its buffer from `SIZE`.
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a key needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        put_u64(buf, 0, self.objectid);
        put_u8(buf, 8, self.kind.value());
        put_u64(buf, 9, self.offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_round_trips_through_its_seventeen_bytes() {
        let key = DiskKey::new(
            0x0123_4567_89ab_cdef,
            ItemType::DIR_ITEM,
            0xfedc_ba98_7654_3210,
        );
        let mut buf = [0u8; DiskKey::SIZE];
        key.write_to(&mut buf);
        assert_eq!(DiskKey::read_from(&buf).expect("a full key"), key);
        // The bytes are asserted as well as the round trip: a pair that read and wrote the
        // same wrong order would round-trip perfectly and misplace every key on disk.
        assert_eq!(&buf[..8], &[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]);
        assert_eq!(buf[8], 84);
        assert_eq!(&buf[9..], &[0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe]);
    }

    #[test]
    fn a_buffer_shorter_than_a_key_holds_no_key() {
        let err = DiskKey::read_from(&[0u8; DiskKey::SIZE - 1]).expect_err("sixteen bytes");
        assert!(matches!(
            err,
            ParseError::TooShort {
                need: 17,
                got: 16,
                ..
            }
        ));
    }

    #[test]
    fn keys_sort_by_objectid_then_type_then_offset() {
        // The on-disk sort, which every search here relies on being the derived one. Each
        // pair below differs in exactly one field, so a comparison that read the fields in
        // any other order would get one of them backwards.
        let base = DiskKey::new(5, ItemType::DIR_ITEM, 100);
        assert!(
            base < DiskKey::new(6, ItemType::INODE_ITEM, 0),
            "objectid outranks type"
        );
        assert!(
            base < DiskKey::new(5, ItemType::DIR_INDEX, 0),
            "type outranks offset"
        );
        assert!(base < DiskKey::new(5, ItemType::DIR_ITEM, 101));
        // And the format's own negative ids sort above every ordinary one, being `u64`
        // values near the top of the range. The root tree's last item is one of them.
        assert!(
            DiskKey::new(objectid::FS_TREE, ItemType::ROOT_ITEM, 0)
                < DiskKey::new(objectid::DATA_RELOC_TREE, ItemType::ROOT_ITEM, 0)
        );
    }

    #[test]
    fn the_lowest_key_is_below_every_key_a_tree_can_hold() {
        assert!(DiskKey::MIN <= DiskKey::new(0, ItemType::from_value(0), 0));
        assert!(DiskKey::MIN < DiskKey::new(0, ItemType::from_value(0), 1));
        assert_eq!(DiskKey::first_of(9, ItemType::UUID_SUBVOL).offset, 0);
    }

    #[test]
    fn an_item_type_the_format_has_not_defined_keeps_its_byte_and_has_no_name() {
        // The contract an unknown item rests on: a reader that refused what it could not name
        // would refuse every filesystem that has been used, so the byte survives and the
        // absence of a name is what says it was not recognized.
        let unknown = ItemType::from_value(77);
        assert_eq!(unknown.value(), 77);
        assert_eq!(unknown.name(), None);
        assert_eq!(ItemType::EXTENT_DATA.name(), Some("EXTENT_DATA"));
    }

    #[test]
    fn the_two_bytes_that_name_two_records_answer_with_the_current_name() {
        // 248 and 249 each carry an older name and the one that replaced it. The baseline
        // prints the second of each pair for the same byte, and so does this.
        assert_eq!(ItemType::from_value(248).name(), Some("TEMPORARY_ITEM"));
        assert_eq!(ItemType::from_value(249).name(), Some("PERSISTENT_ITEM"));
    }

    #[test]
    fn the_relocation_roots_are_named_and_sit_at_the_top_of_the_range() {
        // A `u64` near the top of the range is how the format spells a small negative number.
        // `DATA_RELOC_TREE` is in the root tree of every image the baseline writes, so
        // leaving it unnamed would leave a reader without a word for something it always
        // meets.
        assert_eq!(objectid::DATA_RELOC_TREE, 18_446_744_073_709_551_607);
        assert_eq!(
            objectid::name(objectid::DATA_RELOC_TREE),
            Some("DATA_RELOC_TREE")
        );
        assert_eq!(objectid::name(objectid::TREE_RELOC), Some("TREE_RELOC"));
        // An inode number is not one of the format's own.
        assert_eq!(objectid::name(257), None);
    }

    #[test]
    fn a_subvolume_uuid_splits_into_the_key_the_baseline_writes_for_it() {
        // Measured: the pinned baseline gave its filesystem tree the UUID below and keyed the
        // UUID tree's one item at exactly these two numbers. A split that took the halves the
        // other way round, or read either big-endian, would key a lookup at an address the
        // tree does not hold — and answer "no such subvolume" on a filesystem that has one.
        let uuid = [
            0x79, 0xcc, 0x5e, 0x40, 0x2a, 0xab, 0x40, 0xea, 0x93, 0xf9, 0x6f, 0x9b, 0xc0, 0x62,
            0x3d, 0x48,
        ];
        assert_eq!(
            uuid_key(uuid),
            (0xea40_ab2a_405e_cc79, 0x483d_62c0_9b6f_f993)
        );
        assert_eq!(uuid_key([0; 16]), (0, 0));
    }
}
