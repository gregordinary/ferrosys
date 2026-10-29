//! The volume superblock: one volume's identity, features, counts, and the roots of its trees.
//!
//! Every volume in a container has its own superblock, a virtual object found through the
//! container's object map (Apple File System Reference, pp. 51-70). It names the volume's own
//! object map and, through it, the root of the tree holding every file-system record.
//!
//! This module is pure: it moves bytes to and from values and does no I/O.

use crate::bytes::{get_arr, get_u16, get_u32, get_u64, put_arr, put_u16, put_u32, put_u64};

use super::{ObjectHeader, ParseError};

/// The four bytes at offset 32 of every volume superblock: `APSB`.
pub const VOLUME_MAGIC: [u8; 4] = *b"APSB";

/// The bytes a volume's name field takes, terminating NUL included.
pub const VOLUME_NAME_LEN: usize = 256;

/// The modification records a volume superblock keeps.
pub const MODIFIED_BY_ENTRIES: usize = 8;

/// The volume's incompatible feature bits (Apple File System Reference, pp. 68-70).
pub mod incompat {
    /// Names are compared with case folded.
    pub const CASE_INSENSITIVE: u64 = 0x1;
    /// Snapshots may hold files whose data was never stored.
    pub const DATALESS_SNAPSHOTS: u64 = 0x2;
    /// The volume's encryption keys have been changed in place.
    pub const ENCRYPTION_ROLLED: u64 = 0x4;
    /// Names are compared under normalization, case kept.
    pub const NORMALIZATION_INSENSITIVE: u64 = 0x8;
    /// The volume is being restored and is not yet whole.
    pub const INCOMPLETE_RESTORE: u64 = 0x10;
    /// A sealed volume: its tree carries hashes and its file extents are a tree of their own.
    pub const SEALED: u64 = 0x20;
}

/// The volume flags (Apple File System Reference, p. 61).
pub mod volume_flags {
    /// The volume is not encrypted. Every volume this crate reads carries it.
    pub const UNENCRYPTED: u64 = 0x1;
    /// The volume is encrypted with one key for every file.
    pub const ONE_KEY: u64 = 0x8;
    /// Every bit the format names: the two above; spilled over, run spillover cleaner, and
    /// always check extent references; and the four it reserves (Apple File System Reference,
    /// p. 61).
    pub const DEFINED: u64 = 0x1FF;
}

/// The name the reference gives a volume role (Apple File System Reference, pp. 63-66), or
/// [`None`] for a value it does not define. A volume with no role is `none`.
#[must_use]
pub const fn role_name(role: u16) -> Option<&'static str> {
    Some(match role {
        0 => "none",
        0x1 => "system",
        0x2 => "user",
        0x4 => "recovery",
        0x8 => "vm",
        0x10 => "preboot",
        0x20 => "installer",
        0x40 => "data",
        0x80 => "baseband",
        0xC0 => "update",
        0x100 => "xart",
        0x140 => "hardware",
        0x180 => "backup",
        0x1C0 => "sidecar",
        0x240 => "enterprise",
        0x2C0 => "prelogin",
        _ => return None,
    })
}

/// One record of a program that formatted or modified the volume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ModifiedBy {
    /// The program's name and version, NUL-padded.
    pub id: [u8; 32],
    /// When, in nanoseconds since 1970.
    pub timestamp: u64,
    /// The last transaction it wrote.
    pub last_xid: u64,
}

impl ModifiedBy {
    /// Bytes on disk.
    pub const SIZE: usize = 48;

    fn read(buf: &[u8], off: usize) -> Self {
        Self {
            id: get_arr(buf, off),
            timestamp: get_u64(buf, off + 32),
            last_xid: get_u64(buf, off + 40),
        }
    }

    fn write(&self, buf: &mut [u8], off: usize) {
        put_arr(buf, off, &self.id);
        put_u64(buf, off + 32, self.timestamp);
        put_u64(buf, off + 40, self.last_xid);
    }

    /// The program's name up to its first NUL, as the bytes are stored.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        let end = self.id.iter().position(|b| *b == 0).unwrap_or(32);
        &self.id[..end]
    }
}

/// A volume superblock (Apple File System Reference, pp. 51-67).
///
/// Every field the reference lays out is carried, so a value read and written back is the
/// same bytes up to offset [`SIZE`](Self::SIZE). The fields past it are not.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VolumeSuperblock {
    /// Offset 0. The object header.
    pub header: ObjectHeader,
    /// Offset 36. The volume's slot in the container's list.
    pub index: u32,
    /// Offset 40. Compatible features.
    pub features: u64,
    /// Offset 48. Read-only compatible features.
    pub readonly_compatible_features: u64,
    /// Offset 56. Incompatible features: [`incompat`].
    pub incompatible_features: u64,
    /// Offset 64. When the volume was last unmounted, in nanoseconds since 1970.
    pub unmount_time: u64,
    /// Offset 72. Blocks reserved for the volume.
    pub reserve_blocks: u64,
    /// Offset 80. The most blocks the volume may use.
    pub quota_blocks: u64,
    /// Offset 88. Blocks the volume has allocated.
    pub allocated_blocks: u64,
    /// Offset 96. The volume's metadata crypto state, 20 bytes.
    pub meta_crypto: [u8; 20],
    /// Offset 116. The file-system tree root's type word.
    pub root_tree_type: u32,
    /// Offset 120. The extent-reference tree root's type word.
    pub extent_ref_tree_type: u32,
    /// Offset 124. The snapshot tree root's type word.
    pub snapshot_tree_type: u32,
    /// Offset 128. The volume's object map, a physical address.
    pub object_map_oid: u64,
    /// Offset 136. The file-system tree's root, a virtual identifier.
    pub root_tree_oid: u64,
    /// Offset 144. The extent-reference tree's root, a physical address.
    pub extent_ref_tree_oid: u64,
    /// Offset 152. The snapshot tree's root, a physical address.
    pub snapshot_tree_oid: u64,
    /// Offset 160. The transaction a revert in progress returns to.
    pub revert_to_xid: u64,
    /// Offset 168. The superblock a revert in progress returns to.
    pub revert_to_superblock: u64,
    /// Offset 176. The next identifier a file-system object takes.
    pub next_object_id: u64,
    /// Offset 184. Regular files in the volume.
    pub file_count: u64,
    /// Offset 192. Directories.
    pub directory_count: u64,
    /// Offset 200. Symbolic links.
    pub symlink_count: u64,
    /// Offset 208. Every other kind: FIFOs, sockets and device nodes.
    pub other_count: u64,
    /// Offset 216. Snapshots.
    pub snapshot_count: u64,
    /// Offset 224. Blocks ever allocated.
    pub total_blocks_allocated: u64,
    /// Offset 232. Blocks ever freed.
    pub total_blocks_freed: u64,
    /// Offset 240. The volume's identifier.
    pub uuid: [u8; 16],
    /// Offset 256. When the volume was last modified, in nanoseconds since 1970.
    pub last_modified: u64,
    /// Offset 264. [`volume_flags`].
    pub flags: u64,
    /// Offset 272. The program that formatted the volume.
    pub formatted_by: ModifiedBy,
    /// Offset 320. The programs that most recently modified it, newest first.
    pub modified_by: [ModifiedBy; MODIFIED_BY_ENTRIES],
    /// Offset 704. The volume's name, UTF-8, NUL-terminated.
    pub name: [u8; VOLUME_NAME_LEN],
    /// Offset 960. The next document identifier.
    pub next_document_id: u32,
    /// Offset 964. The volume's role: system, data, preboot, and so on.
    pub role: u16,
    /// Offset 966. Reserved.
    pub reserved: u16,
    /// Offset 968. The transaction the root is being moved to.
    pub root_to_xid: u64,
    /// Offset 976. The state of an encryption change in progress.
    pub encryption_rolling_oid: u64,
    /// Offset 984. The largest object identifier the volume had used when an inode's
    /// [`INTERNAL_EVER_CLONED`](super::INTERNAL_EVER_CLONED) became exact: the flag is exact
    /// for an inode whose identifier is larger (Apple File System Reference, p. 58).
    pub clone_info_epoch: u64,
    /// Offset 992. The last transaction written by an implementation that keeps
    /// [`INTERNAL_EVER_CLONED`](super::INTERNAL_EVER_CLONED) exact. Where it is not the newest
    /// [`modified_by`](Self::modified_by) entry's transaction, an implementation that does
    /// not has written since, and where it is zero, one created the volume (Apple File
    /// System Reference, pp. 58-59).
    pub clone_info_xid: u64,
    /// Offset 1000. The virtual object holding each snapshot's identifier, or zero before the
    /// first snapshot.
    pub snapshot_extension_oid: u64,
    /// Offset 1008. The volume group the volume belongs to.
    pub volume_group: [u8; 16],
    /// Offset 1024. A sealed volume's integrity metadata.
    pub integrity_meta_oid: u64,
    /// Offset 1032. A sealed volume's tree of file extents.
    pub file_extent_tree_oid: u64,
    /// Offset 1040. That tree root's type word.
    pub file_extent_tree_type: u32,
    /// Offset 1044. Reserved.
    pub reserved_type: u32,
    /// Offset 1048. Reserved.
    pub reserved_oid: u64,
}

impl VolumeSuperblock {
    /// Bytes the reference lays out.
    pub const SIZE: usize = 1056;

    /// Recover a volume superblock from the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] where `buf` is shorter than [`SIZE`](Self::SIZE), and
    /// [`ParseError::BadMagic`] where offset 32 does not hold [`VOLUME_MAGIC`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        ParseError::need("volume superblock", Self::SIZE, buf)?;
        let magic: [u8; 4] = get_arr(buf, 32);
        if magic != VOLUME_MAGIC {
            return Err(ParseError::BadMagic {
                structure: "volume superblock",
                found: magic,
            });
        }
        let modified_by =
            std::array::from_fn(|i| ModifiedBy::read(buf, 320 + ModifiedBy::SIZE * i));
        Ok(Self {
            header: ObjectHeader::read_from(buf)?,
            index: get_u32(buf, 36),
            features: get_u64(buf, 40),
            readonly_compatible_features: get_u64(buf, 48),
            incompatible_features: get_u64(buf, 56),
            unmount_time: get_u64(buf, 64),
            reserve_blocks: get_u64(buf, 72),
            quota_blocks: get_u64(buf, 80),
            allocated_blocks: get_u64(buf, 88),
            meta_crypto: get_arr(buf, 96),
            root_tree_type: get_u32(buf, 116),
            extent_ref_tree_type: get_u32(buf, 120),
            snapshot_tree_type: get_u32(buf, 124),
            object_map_oid: get_u64(buf, 128),
            root_tree_oid: get_u64(buf, 136),
            extent_ref_tree_oid: get_u64(buf, 144),
            snapshot_tree_oid: get_u64(buf, 152),
            revert_to_xid: get_u64(buf, 160),
            revert_to_superblock: get_u64(buf, 168),
            next_object_id: get_u64(buf, 176),
            file_count: get_u64(buf, 184),
            directory_count: get_u64(buf, 192),
            symlink_count: get_u64(buf, 200),
            other_count: get_u64(buf, 208),
            snapshot_count: get_u64(buf, 216),
            total_blocks_allocated: get_u64(buf, 224),
            total_blocks_freed: get_u64(buf, 232),
            uuid: get_arr(buf, 240),
            last_modified: get_u64(buf, 256),
            flags: get_u64(buf, 264),
            formatted_by: ModifiedBy::read(buf, 272),
            modified_by,
            name: get_arr(buf, 704),
            next_document_id: get_u32(buf, 960),
            role: get_u16(buf, 964),
            reserved: get_u16(buf, 966),
            root_to_xid: get_u64(buf, 968),
            encryption_rolling_oid: get_u64(buf, 976),
            clone_info_epoch: get_u64(buf, 984),
            clone_info_xid: get_u64(buf, 992),
            snapshot_extension_oid: get_u64(buf, 1000),
            volume_group: get_arr(buf, 1008),
            integrity_meta_oid: get_u64(buf, 1024),
            file_extent_tree_oid: get_u64(buf, 1032),
            file_extent_tree_type: get_u32(buf, 1040),
            reserved_type: get_u32(buf, 1044),
            reserved_oid: get_u64(buf, 1048),
        })
    }

    /// Write the superblock into the first [`SIZE`](Self::SIZE) bytes of `buf`, magic
    /// included.
    ///
    /// # Panics
    ///
    /// Where `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= Self::SIZE,
            "a volume superblock needs {} bytes and was given {}",
            Self::SIZE,
            buf.len()
        );
        self.header.write_to(buf);
        put_arr(buf, 32, &VOLUME_MAGIC);
        put_u32(buf, 36, self.index);
        put_u64(buf, 40, self.features);
        put_u64(buf, 48, self.readonly_compatible_features);
        put_u64(buf, 56, self.incompatible_features);
        put_u64(buf, 64, self.unmount_time);
        put_u64(buf, 72, self.reserve_blocks);
        put_u64(buf, 80, self.quota_blocks);
        put_u64(buf, 88, self.allocated_blocks);
        put_arr(buf, 96, &self.meta_crypto);
        put_u32(buf, 116, self.root_tree_type);
        put_u32(buf, 120, self.extent_ref_tree_type);
        put_u32(buf, 124, self.snapshot_tree_type);
        put_u64(buf, 128, self.object_map_oid);
        put_u64(buf, 136, self.root_tree_oid);
        put_u64(buf, 144, self.extent_ref_tree_oid);
        put_u64(buf, 152, self.snapshot_tree_oid);
        put_u64(buf, 160, self.revert_to_xid);
        put_u64(buf, 168, self.revert_to_superblock);
        put_u64(buf, 176, self.next_object_id);
        put_u64(buf, 184, self.file_count);
        put_u64(buf, 192, self.directory_count);
        put_u64(buf, 200, self.symlink_count);
        put_u64(buf, 208, self.other_count);
        put_u64(buf, 216, self.snapshot_count);
        put_u64(buf, 224, self.total_blocks_allocated);
        put_u64(buf, 232, self.total_blocks_freed);
        put_arr(buf, 240, &self.uuid);
        put_u64(buf, 256, self.last_modified);
        put_u64(buf, 264, self.flags);
        self.formatted_by.write(buf, 272);
        for (i, entry) in self.modified_by.iter().enumerate() {
            entry.write(buf, 320 + ModifiedBy::SIZE * i);
        }
        put_arr(buf, 704, &self.name);
        put_u32(buf, 960, self.next_document_id);
        put_u16(buf, 964, self.role);
        put_u16(buf, 966, self.reserved);
        put_u64(buf, 968, self.root_to_xid);
        put_u64(buf, 976, self.encryption_rolling_oid);
        put_u64(buf, 984, self.clone_info_epoch);
        put_u64(buf, 992, self.clone_info_xid);
        put_u64(buf, 1000, self.snapshot_extension_oid);
        put_arr(buf, 1008, &self.volume_group);
        put_u64(buf, 1024, self.integrity_meta_oid);
        put_u64(buf, 1032, self.file_extent_tree_oid);
        put_u32(buf, 1040, self.file_extent_tree_type);
        put_u32(buf, 1044, self.reserved_type);
        put_u64(buf, 1048, self.reserved_oid);
    }

    /// The volume's name up to its first NUL, as the bytes are stored.
    ///
    /// macOS stores the name it was given without normalizing it, cut to 255 bytes.
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(VOLUME_NAME_LEN);
        &self.name[..end]
    }

    /// Whether the volume says its contents are not encrypted.
    #[must_use]
    pub const fn is_unencrypted(&self) -> bool {
        self.flags & volume_flags::UNENCRYPTED != 0
    }

    /// Whether names are compared with case folded.
    #[must_use]
    pub const fn is_case_insensitive(&self) -> bool {
        self.incompatible_features & incompat::CASE_INSENSITIVE != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> VolumeSuperblock {
        let mut name = [0u8; VOLUME_NAME_LEN];
        name[..4].copy_from_slice(b"Data");
        let mut formatted_id = [0u8; 32];
        formatted_id[..10].copy_from_slice(b"newfs_apfs");
        VolumeSuperblock {
            header: ObjectHeader {
                checksum: 0,
                oid: 1026,
                xid: 2,
                type_word: 0x0000_000D,
                subtype: 0,
            },
            index: 0,
            features: 0x2,
            readonly_compatible_features: 0,
            incompatible_features: incompat::CASE_INSENSITIVE,
            unmount_time: 11,
            reserve_blocks: 0,
            quota_blocks: 0,
            allocated_blocks: 300,
            meta_crypto: [0; 20],
            root_tree_type: 0x0000_0002,
            extent_ref_tree_type: 0x4000_0002,
            snapshot_tree_type: 0x4000_0002,
            object_map_oid: 500,
            root_tree_oid: 1028,
            extent_ref_tree_oid: 501,
            snapshot_tree_oid: 502,
            revert_to_xid: 0,
            revert_to_superblock: 0,
            next_object_id: 22,
            file_count: 3,
            directory_count: 2,
            symlink_count: 1,
            other_count: 0,
            snapshot_count: 0,
            total_blocks_allocated: 310,
            total_blocks_freed: 10,
            uuid: [0x33; 16],
            last_modified: 12,
            flags: volume_flags::UNENCRYPTED,
            formatted_by: ModifiedBy {
                id: formatted_id,
                timestamp: 13,
                last_xid: 2,
            },
            modified_by: [ModifiedBy {
                id: [0; 32],
                timestamp: 0,
                last_xid: 0,
            }; MODIFIED_BY_ENTRIES],
            name,
            next_document_id: 3,
            role: 0x40,
            reserved: 0,
            root_to_xid: 0,
            encryption_rolling_oid: 0,
            clone_info_epoch: 0,
            clone_info_xid: 0,
            snapshot_extension_oid: 0,
            volume_group: [0; 16],
            integrity_meta_oid: 0,
            file_extent_tree_oid: 0,
            file_extent_tree_type: 0,
            reserved_type: 0,
            reserved_oid: 0,
        }
    }

    #[test]
    fn a_superblock_round_trips() {
        let sb = sample();
        let mut buf = vec![0u8; 4096];
        sb.write_to(&mut buf);
        assert_eq!(&buf[32..36], b"APSB");
        assert_eq!(VolumeSuperblock::read_from(&buf), Ok(sb.clone()));
        assert_eq!(sb.name_bytes(), b"Data");
        assert_eq!(sb.formatted_by.name(), b"newfs_apfs");
        assert!(sb.is_unencrypted() && sb.is_case_insensitive());
    }

    #[test]
    fn fields_sit_at_the_offsets_the_reference_gives() {
        let mut buf = vec![0u8; 4096];
        sample().write_to(&mut buf);
        assert_eq!(get_u64(&buf, 128), 500, "the object map at 128");
        assert_eq!(get_u64(&buf, 136), 1028, "the root tree at 136");
        assert_eq!(get_u64(&buf, 264), 1, "the flags at 264");
        assert_eq!(&buf[704..708], b"Data", "the name at 704");
        assert_eq!(get_u16(&buf, 964), 0x40, "the role at 964");
    }

    #[test]
    fn another_signature_is_not_a_volume() {
        let mut buf = vec![0u8; 4096];
        sample().write_to(&mut buf);
        buf[35] = b'X';
        assert!(matches!(
            VolumeSuperblock::read_from(&buf),
            Err(ParseError::BadMagic { .. })
        ));
    }

    #[test]
    fn a_name_filling_its_field_has_no_terminator_to_stop_at() {
        let mut sb = sample();
        sb.name = [b'n'; VOLUME_NAME_LEN];
        assert_eq!(sb.name_bytes().len(), VOLUME_NAME_LEN);
    }
}
