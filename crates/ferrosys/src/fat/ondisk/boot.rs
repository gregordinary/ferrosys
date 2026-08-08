//! The boot sector and its BIOS parameter block, the FAT32 information sector, and the
//! volume information record all three FAT types carry.

use crate::bytes::{get_arr, get_u8, get_u16, get_u32, put_arr, put_u8, put_u16, put_u32};

use super::ParseError;

/// The value at offset 510 of sector 0 on a formatted volume.
///
/// It is *not* how a FAT volume is recognized. Every bootable sector ever written ends
/// with it, including the master boot record of a disk whose partitions hold something
/// else entirely, so a classifier that trusted it would claim an ext4 disk as FAT. What
/// identifies a FAT volume is the whole BIOS parameter block agreeing with itself.
pub const BOOT_SIGNATURE: u16 = 0xAA55;

/// The value at [`VolumeInfo::ext_boot_signature`] that says the three fields after it —
/// the volume identifier, the label, and the type string — are present.
pub const EXTENDED_BOOT_SIGNATURE: u8 = 0x29;

/// The first word of an [`FsInfo`] sector, at offset 0.
pub const FSINFO_LEAD_SIGNATURE: u32 = 0x4161_5252;

/// The second word of an [`FsInfo`] sector, at offset 484. The two lead-in signatures sit
/// 484 bytes apart so that a sector holding neither cannot be mistaken for one holding
/// both.
pub const FSINFO_STRUCT_SIGNATURE: u32 = 0x6141_7272;

/// The last word of an [`FsInfo`] sector, at offset 508. Its low half is zero and its high
/// half is [`BOOT_SIGNATURE`], so the sector ends in the same two bytes a boot sector does.
pub const FSINFO_TRAIL_SIGNATURE: u32 = 0xAA55_0000;

/// The sentinel both [`FsInfo`] counts use for "not known".
///
/// The information sector is a hint rather than a record: a driver may update it, ignore
/// it, or leave it stale, and a reader that trusted it over the file allocation table
/// would be trusting a cache nothing is obliged to invalidate.
const FSINFO_UNKNOWN: u32 = 0xFFFF_FFFF;

/// The volume identity record shared by all three FAT types: what `fatlabel` reads and
/// writes, and what a driver reports as a volume serial number.
///
/// It sits at byte 36 of the boot sector on FAT12 and FAT16 and at byte 64 on FAT32, which
/// is the only difference between them — the FAT32 fields of [`Fat32Params`] occupy the
/// 28 bytes in between.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VolumeInfo {
    /// The BIOS drive number a boot loader would be handed: `0x80` for a fixed disk,
    /// `0x00` for removable media. Nothing but boot code reads it.
    pub drive_number: u8,
    /// [`EXTENDED_BOOT_SIGNATURE`] when the three fields below are present. A volume
    /// without it carries no label and no identifier, which is legal and ancient.
    pub ext_boot_signature: u8,
    /// The volume serial number, conventionally derived from the moment of formatting.
    /// This crate takes it as an input so that two formats of one tree produce one image.
    pub volume_id: u32,
    /// The 11-byte volume label, space-padded, in the OEM character set. A volume with no
    /// label carries the literal `NO NAME    `.
    pub label: [u8; 11],
    /// The type string — `FAT12   `, `FAT16   `, or `FAT32   `.
    ///
    /// It is documentation and nothing more. No conformant driver reads it, because the
    /// type follows from the cluster count and from nothing else, so an image whose string
    /// disagrees with its geometry is read by its geometry. Writing it correctly is still
    /// worth doing: it is the formatter stating its own conclusion, which is exactly what
    /// makes it useful to compare against a count-derived answer.
    pub fs_type: [u8; 8],
}

impl VolumeInfo {
    /// Bytes the record occupies, wherever it sits.
    pub const SIZE: usize = 26;

    /// The label a volume with no name carries.
    pub const NO_NAME: [u8; 11] = *b"NO NAME    ";

    /// Read the record from `buf`, whose start is the record's own byte 0.
    fn read_at(buf: &[u8], off: usize) -> Self {
        Self {
            drive_number: get_u8(buf, off),
            // Byte 1 is reserved and reads as zero on a freshly formatted volume; Windows
            // NT used it as a dirty flag, so it is not modelled as one.
            ext_boot_signature: get_u8(buf, off + 2),
            volume_id: get_u32(buf, off + 3),
            label: get_arr::<11>(buf, off + 7),
            fs_type: get_arr::<8>(buf, off + 18),
        }
    }

    /// Write the record at `off`, leaving the reserved byte at `off + 1` alone.
    fn write_at(&self, buf: &mut [u8], off: usize) {
        put_u8(buf, off, self.drive_number);
        put_u8(buf, off + 1, 0);
        put_u8(buf, off + 2, self.ext_boot_signature);
        put_u32(buf, off + 3, self.volume_id);
        put_arr(buf, off + 7, &self.label);
        put_arr(buf, off + 18, &self.fs_type);
    }
}

/// The fields FAT32 inserts at byte 36 of the boot sector, pushing the [`VolumeInfo`] that
/// FAT12 and FAT16 place there out to byte 64.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fat32Params {
    /// Sectors in one file allocation table. FAT32 needs 32 bits for this, which is why it
    /// has a field of its own and why [`BootSector::fat_sectors_16`] is zero on a FAT32
    /// volume — the zero there is how every mainstream driver recognizes the type, ahead of
    /// any cluster arithmetic.
    pub fat_sectors: u32,
    /// Mirroring control. Zero means every file allocation table is kept identical, which
    /// is what this crate writes and what a checker compares them under. Bit 7 set would
    /// mean only the table numbered in the low four bits is live.
    pub ext_flags: u16,
    /// The filesystem version, zero for every FAT32 defined. A driver refuses a volume
    /// whose version it does not know, so nothing else may be written here.
    pub version: u16,
    /// The first cluster of the root directory. FAT32 has no fixed root region: its root is
    /// an ordinary cluster chain, conventionally starting at cluster 2, the first that
    /// exists.
    pub root_cluster: u32,
    /// Which reserved sector holds the [`FsInfo`] hint, conventionally 1.
    pub fs_info_sector: u16,
    /// Which reserved sector holds the backup copy of the boot sector, conventionally 6.
    /// Zero means there is none.
    pub backup_boot_sector: u16,
}

/// The type-dependent tail of the boot sector, from byte 36 on.
///
/// The two shapes are not a version history: a FAT12 or FAT16 volume has never had the
/// FAT32 fields, and a FAT32 volume has never had its volume information at 36.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BootSectorTail {
    /// FAT12 and FAT16: the volume information sits directly at byte 36.
    Fat1216 {
        /// The volume identity record, at byte 36.
        volume: VolumeInfo,
    },
    /// FAT32: its own fields occupy bytes 36 to 64, and the volume information follows.
    Fat32 {
        /// The FAT32 fields, at bytes 36 to 52. Bytes 52 to 64 are reserved and written
        /// zero.
        params: Fat32Params,
        /// The volume identity record, at byte 64.
        volume: VolumeInfo,
    },
}

/// Sector 0 of a FAT volume: a jump instruction, the BIOS parameter block that describes
/// the whole geometry, a type-dependent tail, boot code, and a two-byte signature.
///
/// Every field here is what a driver reads to find everything else. The cluster count — and
/// with it the FAT type — is not a field: it is computed from these, which is why an image
/// cannot lie about its type and why the arithmetic that derives it is the format's real
/// contract.
///
/// Serialization covers the fields and the signature at byte 510. The boot code between the
/// tail and the signature belongs to whoever writes a boot loader, so [`write_to`] leaves it
/// exactly as it found it.
///
/// [`write_to`]: BootSector::write_to
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BootSector {
    /// Bytes 0..3: the jump instruction a boot loader begins with — `EB xx 90` (a short
    /// jump and a no-op) or `E9 xx xx` (a near jump). A driver checks its shape as evidence
    /// the sector is a boot sector at all.
    pub jump: [u8; 3],
    /// Bytes 3..11: the name of the system that formatted the volume, space-padded. No
    /// driver interprets it, and Microsoft's own specification says not to.
    pub oem_name: [u8; 8],
    /// Bytes 11..13: bytes per logical sector. 512, 1024, 2048, or 4096.
    pub bytes_per_sector: u16,
    /// Byte 13: sectors per cluster, a power of two from 1 to 128. The product with
    /// [`bytes_per_sector`](Self::bytes_per_sector) is the allocation unit.
    pub sectors_per_cluster: u8,
    /// Bytes 14..16: sectors before the first file allocation table, including this one.
    /// At least 1 on every type, and at least 2 on FAT32, which needs room for its
    /// information sector.
    pub reserved_sectors: u16,
    /// Byte 16: how many copies of the file allocation table follow the reserved region.
    /// Any value is legal; every implementation writes 2.
    pub fats: u8,
    /// Bytes 17..19: entries in the fixed-capacity root directory region. **Zero on FAT32**,
    /// whose root is a cluster chain instead.
    pub root_entries: u16,
    /// Bytes 19..21: total sectors in the volume, or zero when the count needs the 32-bit
    /// field. Exactly one of this and
    /// [`total_sectors_32`](Self::total_sectors_32) is non-zero on a conformant volume.
    pub total_sectors_16: u16,
    /// Byte 21: the media descriptor — `0xF8` for fixed media, `0xF0` for removable, and a
    /// handful of legacy floppy codes. Whatever it is, the first entry of every file
    /// allocation table repeats it.
    pub media: u8,
    /// Bytes 22..24: sectors in one file allocation table. **Zero on FAT32**, which uses
    /// [`Fat32Params::fat_sectors`] instead — and that zero is how a driver tells the types
    /// apart before it has counted anything.
    pub fat_sectors_16: u16,
    /// Bytes 24..26: sectors per track, from the era when that meant something. Carried
    /// because mtools and DOS-era software read it.
    pub sectors_per_track: u16,
    /// Bytes 26..28: disk heads, as above.
    pub heads: u16,
    /// Bytes 28..32: sectors on the medium before this volume begins — the partition's
    /// start offset, or zero for a volume that is the whole medium.
    pub hidden_sectors: u32,
    /// Bytes 32..36: total sectors when the count exceeds 16 bits, else zero.
    pub total_sectors_32: u32,
    /// Bytes 36 on: the type-dependent tail.
    pub tail: BootSectorTail,
}

impl BootSector {
    /// Bytes the structure serializes into: the first 512 of sector 0, wherever the volume's
    /// own sector size lands. The signature is at byte 510 on every FAT volume, so a larger
    /// logical sector extends past this rather than moving anything within it.
    pub const SIZE: usize = 512;

    /// Byte offset of the two-byte signature.
    pub const SIGNATURE_OFFSET: usize = 510;

    /// The volume's total sector count, taking whichever of the two fields carries it.
    ///
    /// A conformant volume sets exactly one. When both are set this prefers the 16-bit
    /// field, which is what every driver does, so a reader and a writer disagreeing about
    /// which to believe cannot produce two different filesystems from one image.
    #[must_use]
    pub fn total_sectors(&self) -> u32 {
        if self.total_sectors_16 != 0 {
            u32::from(self.total_sectors_16)
        } else {
            self.total_sectors_32
        }
    }

    /// Sectors in one file allocation table, taking whichever of the two fields carries it.
    #[must_use]
    pub fn fat_sectors(&self) -> u32 {
        if self.fat_sectors_16 != 0 {
            u32::from(self.fat_sectors_16)
        } else {
            match self.tail {
                BootSectorTail::Fat1216 { .. } => 0,
                BootSectorTail::Fat32 { params, .. } => params.fat_sectors,
            }
        }
    }

    /// Parse a boot sector from the start of `buf`.
    ///
    /// Which tail is read is decided by [`fat_sectors_16`](Self::fat_sectors_16): zero means
    /// the FAT32 shape. That is the same test every mainstream driver applies before it has
    /// counted a cluster, and no conformant volume of any type contradicts it — a FAT12 or
    /// FAT16 volume always has a non-zero table size in 16 bits, because a table too large
    /// for that field is a volume too large for those types.
    ///
    /// This is a parse and not a validation: it recovers the fields and does not judge
    /// them. In particular it does not require the signature at
    /// [`SIGNATURE_OFFSET`](Self::SIGNATURE_OFFSET), which is present on every bootable
    /// sector ever written and so proves nothing about the sector being a FAT volume's.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "boot sector",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        let fat_sectors_16 = get_u16(buf, 22);
        let tail = if fat_sectors_16 == 0 {
            BootSectorTail::Fat32 {
                params: Fat32Params {
                    fat_sectors: get_u32(buf, 36),
                    ext_flags: get_u16(buf, 40),
                    version: get_u16(buf, 42),
                    root_cluster: get_u32(buf, 44),
                    fs_info_sector: get_u16(buf, 48),
                    backup_boot_sector: get_u16(buf, 50),
                },
                volume: VolumeInfo::read_at(buf, 64),
            }
        } else {
            BootSectorTail::Fat1216 {
                volume: VolumeInfo::read_at(buf, 36),
            }
        };
        Ok(Self {
            jump: get_arr::<3>(buf, 0),
            oem_name: get_arr::<8>(buf, 3),
            bytes_per_sector: get_u16(buf, 11),
            sectors_per_cluster: get_u8(buf, 13),
            reserved_sectors: get_u16(buf, 14),
            fats: get_u8(buf, 16),
            root_entries: get_u16(buf, 17),
            total_sectors_16: get_u16(buf, 19),
            media: get_u8(buf, 21),
            fat_sectors_16,
            sectors_per_track: get_u16(buf, 24),
            heads: get_u16(buf, 26),
            hidden_sectors: get_u32(buf, 28),
            total_sectors_32: get_u32(buf, 32),
            tail,
        })
    }

    /// Serialize into the first [`SIZE`](Self::SIZE) bytes of `buf`, including the signature
    /// at [`SIGNATURE_OFFSET`](Self::SIGNATURE_OFFSET).
    ///
    /// The bytes between the tail and the signature are boot code, and they are left
    /// untouched: a caller that wants a bootable volume writes its loader there first and
    /// then lays the fields over it, and a caller that does not leaves them zero.
    ///
    /// The tail written is the one the value carries, whatever
    /// [`fat_sectors_16`](Self::fat_sectors_16) says. Constructing a value whose two
    /// disagree produces an image no driver reads as the type intended, which is why a
    /// layout is planned rather than assembled.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "boot sector",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        put_arr(buf, 0, &self.jump);
        put_arr(buf, 3, &self.oem_name);
        put_u16(buf, 11, self.bytes_per_sector);
        put_u8(buf, 13, self.sectors_per_cluster);
        put_u16(buf, 14, self.reserved_sectors);
        put_u8(buf, 16, self.fats);
        put_u16(buf, 17, self.root_entries);
        put_u16(buf, 19, self.total_sectors_16);
        put_u8(buf, 21, self.media);
        put_u16(buf, 22, self.fat_sectors_16);
        put_u16(buf, 24, self.sectors_per_track);
        put_u16(buf, 26, self.heads);
        put_u32(buf, 28, self.hidden_sectors);
        put_u32(buf, 32, self.total_sectors_32);
        match self.tail {
            BootSectorTail::Fat1216 { volume } => volume.write_at(buf, 36),
            BootSectorTail::Fat32 { params, volume } => {
                put_u32(buf, 36, params.fat_sectors);
                put_u16(buf, 40, params.ext_flags);
                put_u16(buf, 42, params.version);
                put_u32(buf, 44, params.root_cluster);
                put_u16(buf, 48, params.fs_info_sector);
                put_u16(buf, 50, params.backup_boot_sector);
                // Bytes 52..64 are reserved, and written zero rather than left as found:
                // they sit inside the structure's own span, so leaving them would make the
                // serialization depend on what the buffer held.
                put_arr(buf, 52, &[0u8; 12]);
                volume.write_at(buf, 64);
            }
        }
        put_u16(buf, Self::SIGNATURE_OFFSET, BOOT_SIGNATURE);
        Ok(())
    }
}

/// The FAT32 information sector: a cached free-cluster count and a hint at where to look
/// for the next free one.
///
/// Both are hints. A driver may update them, ignore them, or leave them stale across an
/// unclean shutdown, so the file allocation table remains the only authority on which
/// clusters are free. What this crate writes is accurate at the moment of writing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FsInfo {
    /// Free clusters on the volume, or `None` where the sector records that it does not
    /// know — the sentinel `0xFFFFFFFF`.
    pub free_clusters: Option<u32>,
    /// The cluster a driver should begin searching from, or `None` for "no hint". A value
    /// below 2 is meaningless, since clusters 0 and 1 do not exist.
    pub next_free_cluster: Option<u32>,
}

impl FsInfo {
    /// Bytes the structure occupies. It fills a sector, but only these bytes are defined.
    pub const SIZE: usize = 512;

    /// Where the trailing signature sits: the last four bytes of the sector.
    ///
    /// Its top half is the `55 AA` boot signature and its bottom half is two zero bytes, so
    /// the two halves have different evidential weight and are treated differently — see
    /// [`read_from`](Self::read_from).
    pub const TRAIL_OFFSET: usize = 508;

    /// Parse an information sector from the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE), and
    /// [`ParseError::BadMagic`] when either lead-in signature is wrong.
    ///
    /// Neither half of the trailing signature is required. Its top two bytes duplicate the
    /// boot signature, which is the one value in the sector that a foreign tool is most
    /// likely to have written for its own reasons; its bottom two are zero, which nothing
    /// else accounts for, and a value there is reported by
    /// [`scan`](crate::fat::Reader::scan) rather than refused here — the sector carries no
    /// placement and no chain, so nothing a read does depends on it.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "fsinfo sector",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        for (off, expected) in [
            (0usize, FSINFO_LEAD_SIGNATURE),
            (484, FSINFO_STRUCT_SIGNATURE),
        ] {
            let found = get_u32(buf, off);
            if found != expected {
                return Err(ParseError::BadMagic {
                    structure: "fsinfo sector",
                    found,
                    expected,
                });
            }
        }
        let known = |v: u32| (v != FSINFO_UNKNOWN).then_some(v);
        Ok(Self {
            free_clusters: known(get_u32(buf, 488)),
            next_free_cluster: known(get_u32(buf, 492)),
        })
    }

    /// Serialize into the first [`SIZE`](Self::SIZE) bytes of `buf`, signatures included.
    ///
    /// The two reserved runs the structure spans — bytes 4 to 484 and 496 to 508 — are
    /// written zero, so the sector's bytes are a function of its value alone.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "fsinfo sector",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        buf[..Self::SIZE].fill(0);
        put_u32(buf, 0, FSINFO_LEAD_SIGNATURE);
        put_u32(buf, 484, FSINFO_STRUCT_SIGNATURE);
        put_u32(buf, 488, self.free_clusters.unwrap_or(FSINFO_UNKNOWN));
        put_u32(buf, 492, self.next_free_cluster.unwrap_or(FSINFO_UNKNOWN));
        put_u32(buf, Self::TRAIL_OFFSET, FSINFO_TRAIL_SIGNATURE);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(fs_type: &[u8; 8]) -> VolumeInfo {
        VolumeInfo {
            drive_number: 0x80,
            ext_boot_signature: EXTENDED_BOOT_SIGNATURE,
            volume_id: 0x1234_abcd,
            label: VolumeInfo::NO_NAME,
            fs_type: *fs_type,
        }
    }

    fn fat16() -> BootSector {
        BootSector {
            jump: [0xEB, 0x3C, 0x90],
            oem_name: *b"ferrosys",
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 8,
            fats: 2,
            root_entries: 512,
            total_sectors_16: 4160,
            media: 0xF8,
            fat_sectors_16: 17,
            sectors_per_track: 32,
            heads: 2,
            hidden_sectors: 0,
            total_sectors_32: 0,
            tail: BootSectorTail::Fat1216 {
                volume: volume(b"FAT16   "),
            },
        }
    }

    fn fat32() -> BootSector {
        BootSector {
            jump: [0xEB, 0x58, 0x90],
            oem_name: *b"ferrosys",
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 32,
            fats: 2,
            root_entries: 0,
            total_sectors_16: 0,
            media: 0xF8,
            fat_sectors_16: 0,
            sectors_per_track: 32,
            heads: 16,
            hidden_sectors: 0,
            total_sectors_32: 524_288,
            tail: BootSectorTail::Fat32 {
                params: Fat32Params {
                    fat_sectors: 4033,
                    ext_flags: 0,
                    version: 0,
                    root_cluster: 2,
                    fs_info_sector: 1,
                    backup_boot_sector: 6,
                },
                volume: volume(b"FAT32   "),
            },
        }
    }

    #[test]
    fn a_boot_sector_round_trips_on_both_tails() {
        for original in [fat16(), fat32()] {
            let mut buf = [0u8; BootSector::SIZE];
            original.write_to(&mut buf).expect("write");
            assert_eq!(BootSector::read_from(&buf).expect("read"), original);
        }
    }

    #[test]
    fn the_tail_written_is_the_tail_read_back() {
        // Which tail a sector carries is decided by a zero table size in 16 bits, and the
        // two shapes place the volume information 28 bytes apart. A volume identifier that
        // survives the round trip is what says the offset was chosen the same way on both
        // sides -- reading a FAT32 sector as a FAT12/16 one would find the label in the
        // middle of the FAT32 fields.
        let mut buf = [0u8; BootSector::SIZE];
        fat32().write_to(&mut buf).expect("write");
        assert_eq!(&buf[64 + 7..64 + 18], &VolumeInfo::NO_NAME);
        assert_eq!(
            u32::from_le_bytes([buf[67], buf[68], buf[69], buf[70]]),
            0x1234_abcd
        );

        buf.fill(0);
        fat16().write_to(&mut buf).expect("write");
        assert_eq!(&buf[36 + 7..36 + 18], &VolumeInfo::NO_NAME);
    }

    #[test]
    fn the_field_offsets_are_where_the_format_puts_them() {
        // Spot checks against the layout table rather than against this module's own
        // constants, since a transposed offset would satisfy a round trip perfectly.
        let mut buf = [0u8; BootSector::SIZE];
        fat32().write_to(&mut buf).expect("write");
        assert_eq!(&buf[0..3], &[0xEB, 0x58, 0x90]);
        assert_eq!(&buf[3..11], b"ferrosys");
        assert_eq!(u16::from_le_bytes([buf[11], buf[12]]), 512);
        assert_eq!(buf[13], 1);
        assert_eq!(u16::from_le_bytes([buf[14], buf[15]]), 32);
        assert_eq!(buf[16], 2);
        assert_eq!(u16::from_le_bytes([buf[17], buf[18]]), 0);
        assert_eq!(buf[21], 0xF8);
        assert_eq!(u16::from_le_bytes([buf[22], buf[23]]), 0);
        assert_eq!(
            u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
            524_288
        );
        assert_eq!(
            u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
            4033
        );
        assert_eq!(u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]), 2);
        assert_eq!(u16::from_le_bytes([buf[48], buf[49]]), 1);
        assert_eq!(u16::from_le_bytes([buf[50], buf[51]]), 6);
        // The twelve reserved bytes, and the signature.
        assert_eq!(&buf[52..64], &[0u8; 12]);
        assert_eq!(u16::from_le_bytes([buf[510], buf[511]]), BOOT_SIGNATURE);
    }

    #[test]
    fn writing_leaves_the_boot_code_alone() {
        // A caller that writes a loader and then lays the fields over it must find its
        // loader intact. FAT32's fields end at 90 and FAT12/16's at 62.
        let mut buf = [0x5Au8; BootSector::SIZE];
        fat32().write_to(&mut buf).expect("write");
        assert!(buf[90..510].iter().all(|&b| b == 0x5A));

        let mut buf = [0x5Au8; BootSector::SIZE];
        fat16().write_to(&mut buf).expect("write");
        assert!(buf[62..510].iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn a_short_buffer_is_refused_rather_than_indexed() {
        let mut buf = [0u8; BootSector::SIZE - 1];
        assert!(matches!(
            BootSector::read_from(&buf),
            Err(ParseError::TooShort { .. })
        ));
        assert!(matches!(
            fat16().write_to(&mut buf),
            Err(ParseError::TooShort { .. })
        ));
        assert!(matches!(
            FsInfo::read_from(&buf),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn either_total_sector_field_answers_the_same_question() {
        let mut small = fat32();
        small.total_sectors_16 = 4160;
        small.total_sectors_32 = 0;
        assert_eq!(small.total_sectors(), 4160);
        assert_eq!(fat32().total_sectors(), 524_288);
        assert_eq!(fat32().fat_sectors(), 4033);
        assert_eq!(fat16().fat_sectors(), 17);
    }

    #[test]
    fn an_information_sector_round_trips_including_its_sentinels() {
        for original in [
            FsInfo {
                free_clusters: Some(516_189),
                next_free_cluster: Some(3),
            },
            FsInfo {
                free_clusters: None,
                next_free_cluster: None,
            },
        ] {
            let mut buf = [0xA5u8; FsInfo::SIZE];
            original.write_to(&mut buf).expect("write");
            assert_eq!(FsInfo::read_from(&buf).expect("read"), original);
        }
    }

    #[test]
    fn an_information_sector_writes_its_three_signatures() {
        let mut buf = [0xA5u8; FsInfo::SIZE];
        FsInfo {
            free_clusters: None,
            next_free_cluster: None,
        }
        .write_to(&mut buf)
        .expect("write");
        assert_eq!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            FSINFO_LEAD_SIGNATURE
        );
        assert_eq!(
            u32::from_le_bytes(buf[484..488].try_into().unwrap()),
            FSINFO_STRUCT_SIGNATURE
        );
        assert_eq!(
            u32::from_le_bytes(buf[508..512].try_into().unwrap()),
            FSINFO_TRAIL_SIGNATURE
        );
        // The reserved runs are zeroed rather than carried over from the buffer.
        assert!(buf[4..484].iter().all(|&b| b == 0));
        assert!(buf[496..508].iter().all(|&b| b == 0));
    }

    #[test]
    fn an_information_sector_without_its_signatures_is_refused() {
        let mut buf = [0u8; FsInfo::SIZE];
        FsInfo {
            free_clusters: Some(1),
            next_free_cluster: Some(2),
        }
        .write_to(&mut buf)
        .expect("write");
        // Either lead-in alone is enough to refuse the sector: they sit 484 bytes apart so
        // that a sector holding one by chance is not read as holding both.
        for off in [0usize, 484] {
            let mut damaged = buf;
            damaged[off] ^= 0xFF;
            assert!(matches!(
                FsInfo::read_from(&damaged),
                Err(ParseError::BadMagic { .. })
            ));
        }
    }
}
