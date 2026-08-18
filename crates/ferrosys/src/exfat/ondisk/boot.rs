//! The boot region: the Main Boot Sector, the eleven sectors after it, and where each one
//! sits.
//!
//! A boot region is twelve sectors whatever the sector size, and a volume carries two of
//! them — the main region at sector 0 and its backup at sector 12. Only the first sector of
//! each carries fields; the eleven behind it are boot code, vendor parameters, reserved
//! space, and the checksum over all of them.

use crate::bytes::{
    get_arr, get_u8, get_u16, get_u32, get_u64, put_arr, put_u8, put_u16, put_u32, put_u64,
};

use super::ParseError;

/// The eight bytes at offset 3 of a Main Boot Sector, and the family's strong magic.
///
/// It is not sufficient on its own. The same offset in a FAT boot sector holds
/// `BS_OEMName` — eight bytes of arbitrary text no FAT driver reads and no formatter is
/// constrained in — so a FAT volume whose OEM field happens to spell this would classify as
/// exFAT. The other half of the claim is [`MUST_BE_ZERO_RANGE`].
pub const FILE_SYSTEM_NAME: [u8; 8] = *b"EXFAT   ";

/// The bytes of a Main Boot Sector the format requires to be zero: 53 of them at offset 11.
///
/// They exist to make a collision impossible in one direction. Offsets 11 through 63 are
/// where a FAT boot sector keeps its BIOS parameter block, so a FAT driver reading an exFAT
/// volume finds a bytes-per-sector of zero and refuses the volume rather than acting on it.
/// A classifier uses the same fact the other way: whatever an eight-byte text field may
/// happen to spell, a real FAT parameter block cannot be 53 zero bytes.
pub const MUST_BE_ZERO_RANGE: core::ops::Range<usize> = 11..64;

/// The value at offset 510 of a Main Boot Sector.
///
/// It is at 510 whatever the sector size, so a volume with 4096-byte sectors carries it
/// three and a half kilobytes before the end of its first sector.
pub const BOOT_SIGNATURE: u16 = 0xAA55;

/// The four bytes each extended boot sector ends with, at the sector's last four bytes.
pub const EXTENDED_BOOT_SIGNATURE: u32 = 0xAA55_0000;

/// The revision a volume this crate writes records, and the only one defined: major 1,
/// minor 0, as the minor byte first.
pub const FILE_SYSTEM_REVISION: u16 = 0x0100;

/// The major half of [`FILE_SYSTEM_REVISION`], and the only major revision an implementation
/// may mount.
///
/// A major revision is the format saying "these structures are not the ones you know", so a
/// volume recording another is one whose boot sector is the last thing about it a reader
/// here can claim to understand. A minor revision above
/// [`FILE_SYSTEM_MINOR_REVISION`] is the weaker case — the format asks an implementation to
/// honour it — and is a remark rather than a refusal.
pub const FILE_SYSTEM_MAJOR_REVISION: u8 = (FILE_SYSTEM_REVISION >> 8) as u8;

/// The minor half of [`FILE_SYSTEM_REVISION`], and the only minor revision this crate knows.
pub const FILE_SYSTEM_MINOR_REVISION: u8 = FILE_SYSTEM_REVISION as u8;

/// Sectors in one boot region, main or backup.
pub const BOOT_REGION_SECTORS: u64 = 12;

/// Which sector of a boot region is the first extended boot sector, and how many follow it.
pub const EXTENDED_BOOT_FIRST_SECTOR: u64 = 1;

/// How many extended boot sectors a boot region carries.
pub const EXTENDED_BOOT_SECTORS: u64 = 8;

/// Which sector of a boot region holds the OEM parameters. A volume this crate writes
/// leaves it zero, which is what the format defines as "no parameters recorded".
pub const OEM_PARAMETERS_SECTOR: u64 = 9;

/// Which sector of a boot region is reserved. It is zero on every volume.
pub const RESERVED_SECTOR: u64 = 10;

/// Which sector of a boot region holds its checksum. Sectors 0 through 10 are what the
/// checksum covers, so this is both where it is stored and where the coverage ends.
pub const CHECKSUM_SECTOR: u64 = 11;

/// Which sector of the volume each boot region begins at: the main region at 0, its backup
/// immediately behind it.
pub const MAIN_BOOT_REGION_SECTOR: u64 = 0;

/// The first sector of the backup boot region.
pub const BACKUP_BOOT_REGION_SECTOR: u64 = BOOT_REGION_SECTORS;

/// `VolumeFlags` bit 0: which allocation table is the active one.
///
/// It is meaningful only on the two-table TexFAT variant, which this crate does not write
/// and refuses to read rather than misinterpret.
pub const VOLUME_FLAG_ACTIVE_FAT: u16 = 0x0001;

/// `VolumeFlags` bit 1: a driver has the volume open and has not yet put it down.
///
/// It is the format correctly recording a state rather than a departure from the format, so
/// a volume carrying it is well-formed — and it is the one condition under which what the
/// metadata says and what the volume contains are allowed to differ.
pub const VOLUME_FLAG_VOLUME_DIRTY: u16 = 0x0002;

/// `VolumeFlags` bit 2: the underlying medium reported an error and the driver recorded it.
pub const VOLUME_FLAG_MEDIA_FAILURE: u16 = 0x0004;

/// `VolumeFlags` bit 3: the allocation bitmap's spare bits are known to be clear.
pub const VOLUME_FLAG_CLEAR_TO_ZERO: u16 = 0x0008;

/// The Main Boot Sector: the first sector of each boot region, and every geometry field a
/// volume records.
///
/// The structure is 512 bytes at every sector size. A volume with larger sectors leaves the
/// rest of the sector zero, which the format calls excess space, and the boot signature
/// stays at offset 510 rather than moving to the end.
///
/// Two of its fields are outside the checksum over the region — see
/// [`BOOT_CHECKSUM_SKIPS`](super::BOOT_CHECKSUM_SKIPS) — so a driver may rewrite
/// [`volume_flags`](Self::volume_flags) and [`percent_in_use`](Self::percent_in_use) in
/// place while a volume is mounted without recomputing anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MainBootSector {
    /// Bytes 0..3: a jump instruction, `0xEB 0x76 0x90` on every volume any tool writes —
    /// a short jump past the fields to the boot code at offset 120, and a no-op.
    pub jump_boot: [u8; 3],
    /// Bytes 3..11: [`FILE_SYSTEM_NAME`], and half of how a volume is recognized.
    pub file_system_name: [u8; 8],
    /// Bytes 64..72: where the volume begins on the medium, in sectors, or zero where the
    /// formatter recorded nothing. It is a hint for a boot loader and no driver depends on
    /// it, since a volume is read from wherever it was found.
    pub partition_offset: u64,
    /// Bytes 72..80: sectors the volume spans, the boot regions included. This is the whole
    /// volume rather than the part a filesystem uses.
    pub volume_length: u64,
    /// Bytes 80..84: the first sector of the allocation table, counted from the volume's
    /// start.
    pub fat_offset: u32,
    /// Bytes 84..88: sectors in one allocation table.
    pub fat_length: u32,
    /// Bytes 88..92: the first sector of the cluster heap.
    pub cluster_heap_offset: u32,
    /// Bytes 92..96: clusters in the heap. Cluster numbering starts at 2, so the last
    /// cluster is numbered `cluster_count + 1`.
    pub cluster_count: u32,
    /// Bytes 96..100: the first cluster of the root directory's chain.
    pub first_cluster_of_root: u32,
    /// Bytes 100..104: the volume's serial number. Conventionally drawn from the moment of
    /// formatting; this crate takes it as an input, so two formats of one tree produce one
    /// image.
    pub volume_serial: u32,
    /// Bytes 104..106: [`FILE_SYSTEM_REVISION`]. The low byte is the minor version and the
    /// high byte the major, which is the one place this format orders a pair the other way
    /// round from how it reads.
    pub file_system_revision: u16,
    /// Bytes 106..108: the volume's state flags — [`VOLUME_FLAG_ACTIVE_FAT`],
    /// [`VOLUME_FLAG_VOLUME_DIRTY`], [`VOLUME_FLAG_MEDIA_FAILURE`],
    /// [`VOLUME_FLAG_CLEAR_TO_ZERO`].
    ///
    /// Outside the boot region's checksum, which is what lets a mounted driver keep it
    /// current. That makes it the one field where a wrong value costs nothing to write and
    /// everything to read.
    pub volume_flags: u16,
    /// Byte 108: the base-2 logarithm of the sector size, 9 through 12 — 512 bytes through
    /// 4096.
    pub bytes_per_sector_shift: u8,
    /// Byte 109: the base-2 logarithm of the cluster size in *sectors*, 0 through
    /// `25 - bytes_per_sector_shift`, which caps a cluster at 32 mebibytes.
    pub sectors_per_cluster_shift: u8,
    /// Byte 110: allocation tables on the volume, 1 on every ordinary volume and 2 only on
    /// TexFAT.
    pub number_of_fats: u8,
    /// Byte 111: the BIOS drive number a boot loader would be handed, `0x80` for a fixed
    /// disk. Nothing but boot code reads it.
    pub drive_select: u8,
    /// Byte 112: how full the volume is, 0 through 100, or `0xFF` for "not known".
    ///
    /// Outside the boot region's checksum, beside [`volume_flags`](Self::volume_flags) and
    /// for the same reason.
    pub percent_in_use: u8,
    /// Bytes 120..510: boot code, or zeroes on a volume that does not boot. Modelled whole
    /// because it is inside the region's checksum, so a byte of it is a byte of the answer.
    pub boot_code: [u8; BOOT_CODE_LEN],
}

/// Bytes of boot code a Main Boot Sector holds: from the end of the fields at offset 120 to
/// the signature at 510.
///
/// Unlike the region a FAT boot sector leaves for the same purpose, this one does not vary:
/// the fields ahead of it are the same on every exFAT volume, so the boot code is a
/// fixed-width field rather than a variable region with a capacity.
pub const BOOT_CODE_LEN: usize = 390;

impl MainBootSector {
    /// Bytes the structure occupies, at every sector size.
    pub const SIZE: usize = 512;

    /// The name a volume with nothing else to say records at
    /// [`file_system_name`](Self::file_system_name), and the jump instruction beside it.
    pub const JUMP_BOOT: [u8; 3] = [0xEB, 0x76, 0x90];

    /// Read the structure from the start of `buf`.
    ///
    /// The fields are recovered; whether they describe a filesystem is a separate question
    /// with a separate answer, because a classifier and a reader want it asked with
    /// different strictness. What is checked here is only what makes recovery impossible: a
    /// buffer too short, and the three fixed values that say these bytes are meant to be an
    /// exFAT boot sector at all.
    ///
    /// The third of those is [`MUST_BE_ZERO_RANGE`], and it is checked here rather than left
    /// to a judgment further out because the offset its magic sits at is shared with
    /// another format. `FileSystemName` alone would claim a FAT volume whose eight bytes of
    /// arbitrary OEM text happen to spell it, and claiming that volume means the family that
    /// really owns it is never tried — the one detection failure that silently
    /// misidentifies a healthy filesystem. The 53 zero bytes are what the collision cannot
    /// satisfy, since they are where a FAT parameter block keeps its sector size.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE), and
    /// [`ParseError::BadMagic`] when [`FILE_SYSTEM_NAME`], [`MUST_BE_ZERO_RANGE`], or
    /// [`BOOT_SIGNATURE`] does not hold what the format requires.
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "exFAT main boot sector",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        let name = get_arr::<8>(buf, 3);
        if name != FILE_SYSTEM_NAME {
            // Rendered as a number because that is what the variant carries; the field is
            // eight bytes of text and the first four of them are what tells one apart from
            // the FAT OEM name that shares the offset.
            return Err(ParseError::BadMagic {
                structure: "exFAT main boot sector: FileSystemName",
                found: get_u32(buf, 3),
                expected: u32::from_le_bytes([
                    FILE_SYSTEM_NAME[0],
                    FILE_SYSTEM_NAME[1],
                    FILE_SYSTEM_NAME[2],
                    FILE_SYSTEM_NAME[3],
                ]),
            });
        }
        if let Some(at) = buf[MUST_BE_ZERO_RANGE].iter().position(|b| *b != 0) {
            // The offset of the first byte that is not zero, so a report names where the
            // collision lies rather than only that there was one. A FAT volume's is at 0 or
            // 2 of the run — its sector size — and a truncated or overwritten exFAT volume's
            // is wherever the damage began.
            return Err(ParseError::BadMagic {
                structure: "exFAT main boot sector: MustBeZero",
                found: u32::from(buf[MUST_BE_ZERO_RANGE.start + at]),
                expected: 0,
            });
        }
        let signature = get_u16(buf, 510);
        if signature != BOOT_SIGNATURE {
            return Err(ParseError::BadMagic {
                structure: "exFAT main boot sector: BootSignature",
                found: u32::from(signature),
                expected: u32::from(BOOT_SIGNATURE),
            });
        }
        Ok(Self {
            jump_boot: get_arr::<3>(buf, 0),
            file_system_name: name,
            partition_offset: get_u64(buf, 64),
            volume_length: get_u64(buf, 72),
            fat_offset: get_u32(buf, 80),
            fat_length: get_u32(buf, 84),
            cluster_heap_offset: get_u32(buf, 88),
            cluster_count: get_u32(buf, 92),
            first_cluster_of_root: get_u32(buf, 96),
            volume_serial: get_u32(buf, 100),
            file_system_revision: get_u16(buf, 104),
            volume_flags: get_u16(buf, 106),
            bytes_per_sector_shift: get_u8(buf, 108),
            sectors_per_cluster_shift: get_u8(buf, 109),
            number_of_fats: get_u8(buf, 110),
            drive_select: get_u8(buf, 111),
            percent_in_use: get_u8(buf, 112),
            boot_code: get_arr::<BOOT_CODE_LEN>(buf, 120),
        })
    }

    /// Write the structure into the start of `buf`.
    ///
    /// The 53 bytes of [`MUST_BE_ZERO_RANGE`] and the seven reserved bytes at 113 are
    /// written as the zeroes the format requires rather than left as whatever `buf` held, so
    /// the result does not depend on what the caller handed in.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "exFAT main boot sector",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        put_arr(buf, 0, &self.jump_boot);
        put_arr(buf, 3, &self.file_system_name);
        // The two runs the format requires to be zero, written rather than assumed: they are
        // inside the region's checksum, and half of how a volume is recognized.
        buf[MUST_BE_ZERO_RANGE].fill(0);
        put_u64(buf, 64, self.partition_offset);
        put_u64(buf, 72, self.volume_length);
        put_u32(buf, 80, self.fat_offset);
        put_u32(buf, 84, self.fat_length);
        put_u32(buf, 88, self.cluster_heap_offset);
        put_u32(buf, 92, self.cluster_count);
        put_u32(buf, 96, self.first_cluster_of_root);
        put_u32(buf, 100, self.volume_serial);
        put_u16(buf, 104, self.file_system_revision);
        put_u16(buf, 106, self.volume_flags);
        put_u8(buf, 108, self.bytes_per_sector_shift);
        put_u8(buf, 109, self.sectors_per_cluster_shift);
        put_u8(buf, 110, self.number_of_fats);
        put_u8(buf, 111, self.drive_select);
        put_u8(buf, 112, self.percent_in_use);
        buf[113..120].fill(0);
        put_arr(buf, 120, &self.boot_code);
        put_u16(buf, 510, BOOT_SIGNATURE);
        Ok(())
    }

    /// The major half of [`file_system_revision`](Self::file_system_revision), which is the
    /// half an implementation may not ignore.
    ///
    /// The field orders the pair the other way round from how it reads — the low byte is the
    /// minor version — so the halves are named here rather than shifted at each site that
    /// wants one.
    #[must_use]
    pub const fn major_revision(&self) -> u8 {
        (self.file_system_revision >> 8) as u8
    }

    /// The minor half of [`file_system_revision`](Self::file_system_revision).
    #[must_use]
    pub const fn minor_revision(&self) -> u8 {
        self.file_system_revision as u8
    }

    /// Bytes per sector, from [`bytes_per_sector_shift`](Self::bytes_per_sector_shift).
    ///
    /// `None` where the shift is outside the 9 through 12 the format defines, since a shift
    /// of 40 is not a sector size that happens to be large — it is a field that was not a
    /// sector size.
    #[must_use]
    pub const fn bytes_per_sector(&self) -> Option<u32> {
        match self.bytes_per_sector_shift {
            9..=12 => Some(1 << self.bytes_per_sector_shift),
            _ => None,
        }
    }

    /// Bytes per cluster, from the two shifts together.
    ///
    /// `None` where either shift is outside its defined range. The cluster shift's own
    /// ceiling depends on the sector shift — their sum is capped at 25, which is what caps a
    /// cluster at 32 mebibytes — so the two are answered together rather than separately.
    ///
    /// The sum is checked. Both shifts are bytes an image supplied, and a cluster shift near
    /// the top of the range carries their sum past what a byte holds — where a wrapped sum is
    /// not a comparison that fails but one that *passes*, on a volume whose cluster size is
    /// then a shift of more bits than the number being shifted has.
    #[must_use]
    pub const fn bytes_per_cluster(&self) -> Option<u32> {
        let Some(sector) = self.bytes_per_sector() else {
            return None;
        };
        let Some(shift) = self
            .bytes_per_sector_shift
            .checked_add(self.sectors_per_cluster_shift)
        else {
            return None;
        };
        if shift > MAX_CLUSTER_SHIFT {
            return None;
        }
        Some(sector << self.sectors_per_cluster_shift)
    }
}

/// The largest sum of the two shifts the format defines, which caps a cluster at 32
/// mebibytes.
pub const MAX_CLUSTER_SHIFT: u8 = 25;

/// The value [`percent_in_use`](MainBootSector::percent_in_use) holds where the volume does
/// not record how full it is.
///
/// It is the one value of the byte that is not a percentage, and it is a different answer
/// from both zero and 255 per cent: a report that printed the byte would say a volume nobody
/// measured is more than twice full.
pub const PERCENT_IN_USE_UNKNOWN: u8 = 0xFF;

/// The largest percentage the field holds. Everything between this and
/// [`PERCENT_IN_USE_UNKNOWN`] is a value the field does not define.
pub const PERCENT_IN_USE_MAX: u8 = 100;

/// How full a volume with `used` of `total` clusters allocated is, as
/// [`percent_in_use`](MainBootSector::percent_in_use) records it: the percentage rounded
/// down.
///
/// Rounded down, so a volume with anything at all on it and a great deal of room reports
/// zero — which is what the field says and not a defect in it.
/// [`PERCENT_IN_USE_UNKNOWN`] is not produced here: a writer that has just laid the volume
/// out knows.
///
/// The field is outside the boot region's checksum, so a mounted driver keeps it current
/// while the volume is in use and nothing has to be recomputed when it does.
#[must_use]
pub const fn percent_in_use(used: u32, total: u32) -> u8 {
    if total == 0 {
        return 0;
    }
    let percent = used as u64 * 100 / total as u64;
    if percent > 100 {
        // Unreachable from a layout, where the residents are checked to fit in the heap. It
        // is a clamp rather than an assertion because a field is one byte wide and the
        // alternative to clamping is a truncation that reads as a plausible small number.
        100
    } else {
        percent as u8
    }
}

/// Write one extended boot sector into `sector`, which must be the volume's sector size.
///
/// The sector is boot code with [`EXTENDED_BOOT_SIGNATURE`] in its last four bytes. A volume
/// that does not boot carries eight of these, each zero but for the signature — which is
/// what this writes, since the whole sector is zeroed first.
///
/// # Panics
///
/// When `sector` is shorter than four bytes, which no sector size is.
pub fn write_extended_boot_sector(sector: &mut [u8]) {
    sector.fill(0);
    let at = sector.len() - 4;
    put_u32(sector, at, EXTENDED_BOOT_SIGNATURE);
}

/// The signature an extended boot sector ends with, or `None` where `sector` is too short to
/// hold one.
///
/// It is at the end of the sector rather than at a fixed offset, so where to look for it is
/// a function of the sector size — which is the one thing a reader must already know before
/// it can read a boot region at all.
#[must_use]
pub fn extended_boot_signature(sector: &[u8]) -> Option<u32> {
    let at = sector.len().checked_sub(4)?;
    Some(get_u32(sector, at))
}

/// Fill `sector` with a boot region's checksum, repeated for the whole sector.
///
/// The repetition is the format's, not a convenience: every four bytes of the sector hold
/// the same value, which is what a reader recovering a damaged region relies on.
///
/// # Panics
///
/// When `sector`'s length is not a multiple of four, which no sector size is.
pub fn write_checksum_sector(sector: &mut [u8], checksum: u32) {
    // The byte order is named once, and what follows repeats those four bytes rather than
    // writing a field at each of a sector's worth of offsets.
    let word = checksum.to_le_bytes();
    for at in sector.chunks_exact_mut(4) {
        at.copy_from_slice(&word);
    }
}

/// The checksum a checksum sector records, or `None` where the sector does not hold one
/// value repeated for its whole length.
///
/// Answering `None` rather than the first word is the point: a sector whose words disagree
/// is not a checksum sector with a stale tail, it is a sector this reader cannot say the
/// intended value of.
#[must_use]
pub fn checksum_sector_value(sector: &[u8]) -> Option<u32> {
    let mut words = sector.chunks_exact(4);
    let first = words.next()?;
    if !words.all(|w| w == first) || !sector.chunks_exact(4).remainder().is_empty() {
        return None;
    }
    Some(get_u32(first, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A boot sector with every field set to something distinguishable, so a field written
    /// at the wrong offset lands on a different value rather than on an equal one.
    fn filled() -> MainBootSector {
        MainBootSector {
            jump_boot: MainBootSector::JUMP_BOOT,
            file_system_name: FILE_SYSTEM_NAME,
            partition_offset: 0x0011_2233_4455_6677,
            volume_length: 0x0000_0001_0000_0002,
            fat_offset: 2048,
            fat_length: 62,
            cluster_heap_offset: 4096,
            cluster_count: 7680,
            first_cluster_of_root: 5,
            volume_serial: 0x1234_5678,
            file_system_revision: FILE_SYSTEM_REVISION,
            volume_flags: VOLUME_FLAG_VOLUME_DIRTY,
            bytes_per_sector_shift: 9,
            sectors_per_cluster_shift: 3,
            number_of_fats: 1,
            drive_select: 0x80,
            percent_in_use: 42,
            boot_code: [0x5A; 390],
        }
    }

    #[test]
    fn a_boot_sector_round_trips() {
        let mut buf = [0u8; MainBootSector::SIZE];
        let boot = filled();
        boot.write_to(&mut buf).expect("write");
        assert_eq!(MainBootSector::read_from(&buf).expect("read"), boot);
    }

    #[test]
    fn every_field_lands_at_the_offset_the_format_defines() {
        // The offsets asserted as raw bytes rather than read back through the accessors the
        // writer used: reading a field back through its own accessor is a statement about
        // consistency, and byte-exactness is the one property this crate cannot check
        // against itself.
        let mut buf = [0u8; MainBootSector::SIZE];
        filled().write_to(&mut buf).expect("write");
        assert_eq!(&buf[0..3], &[0xEB, 0x76, 0x90]);
        assert_eq!(&buf[3..11], b"EXFAT   ");
        assert_eq!(&buf[64..72], &0x0011_2233_4455_6677u64.to_le_bytes());
        assert_eq!(&buf[72..80], &0x0000_0001_0000_0002u64.to_le_bytes());
        assert_eq!(&buf[80..84], &2048u32.to_le_bytes());
        assert_eq!(&buf[84..88], &62u32.to_le_bytes());
        assert_eq!(&buf[88..92], &4096u32.to_le_bytes());
        assert_eq!(&buf[92..96], &7680u32.to_le_bytes());
        assert_eq!(&buf[96..100], &5u32.to_le_bytes());
        assert_eq!(&buf[100..104], &0x1234_5678u32.to_le_bytes());
        // Major 1, minor 0, minor byte first — the one pair this format orders the other
        // way round from how it reads.
        assert_eq!(&buf[104..106], &[0x00, 0x01]);
        assert_eq!(&buf[106..108], &2u16.to_le_bytes());
        assert_eq!(buf[108], 9);
        assert_eq!(buf[109], 3);
        assert_eq!(buf[110], 1);
        assert_eq!(buf[111], 0x80);
        assert_eq!(buf[112], 42);
        assert_eq!(&buf[120..510], &[0x5A; 390]);
        assert_eq!(&buf[510..512], &BOOT_SIGNATURE.to_le_bytes());
    }

    #[test]
    fn the_runs_the_format_requires_to_be_zero_are_written_zero() {
        // Written rather than left alone, so what comes out does not depend on what the
        // caller handed in. Both runs are inside the region's checksum, and the 53-byte one
        // is half of how a volume is recognized.
        let mut buf = [0xFFu8; MainBootSector::SIZE];
        filled().write_to(&mut buf).expect("write");
        assert!(buf[MUST_BE_ZERO_RANGE].iter().all(|b| *b == 0));
        assert!(buf[113..120].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_sector_missing_any_of_the_three_fixed_values_is_refused() {
        let mut buf = [0u8; MainBootSector::SIZE];
        filled().write_to(&mut buf).expect("write");

        let mut no_name = buf;
        no_name[3] = b'F';
        assert!(matches!(
            MainBootSector::read_from(&no_name),
            Err(ParseError::BadMagic { .. })
        ));

        let mut no_signature = buf;
        no_signature[510] = 0;
        assert!(matches!(
            MainBootSector::read_from(&no_signature),
            Err(ParseError::BadMagic { .. })
        ));

        assert!(matches!(
            MainBootSector::read_from(&buf[..511]),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn a_sector_whose_must_be_zero_run_is_not_zero_is_refused_at_the_byte_that_is_not() {
        // The half of the claim that the magic cannot make on its own. Every byte of the run
        // is checked, not only its start: a FAT parameter block's sector size is at the
        // front of it, and its cluster count and media byte are further in.
        let mut buf = [0u8; MainBootSector::SIZE];
        filled().write_to(&mut buf).expect("write");
        assert!(MainBootSector::read_from(&buf).is_ok());

        for at in [MUST_BE_ZERO_RANGE.start, 30, MUST_BE_ZERO_RANGE.end - 1] {
            let mut spoiled = buf;
            spoiled[at] = 0x02;
            let err = MainBootSector::read_from(&spoiled)
                .expect_err("a non-zero byte in the run is refused");
            let ParseError::BadMagic {
                found, expected, ..
            } = err
            else {
                panic!("expected a bad-signature refusal at {at}, got {err:?}");
            };
            assert_eq!((found, expected), (2, 0), "at {at}");
        }
    }

    #[test]
    fn a_fat_boot_sector_whose_oem_name_spells_this_format_is_refused() {
        // The collision this run exists to break, built rather than argued: `BS_OEMName` is
        // eight bytes of arbitrary text at the same offset, so a FAT volume can spell the
        // exFAT magic exactly. What it cannot do is leave its own parameter block zero — a
        // FAT driver reading a bytes-per-sector of zero refuses the volume, which is why the
        // format put the run there.
        let mut fat = [0u8; MainBootSector::SIZE];
        fat[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        fat[3..11].copy_from_slice(b"EXFAT   ");
        fat[11..13].copy_from_slice(&512u16.to_le_bytes()); // BPB_BytsPerSec
        fat[13] = 8; // BPB_SecPerClus
        fat[14..16].copy_from_slice(&1u16.to_le_bytes()); // BPB_RsvdSecCnt
        fat[16] = 2; // BPB_NumFATs
        fat[21] = 0xF8; // BPB_Media
        fat[510..512].copy_from_slice(&BOOT_SIGNATURE.to_le_bytes());

        assert!(
            matches!(
                MainBootSector::read_from(&fat),
                Err(ParseError::BadMagic { .. })
            ),
            "a FAT boot sector spelling this magic must not parse as one of these"
        );
    }

    #[test]
    fn the_two_shifts_answer_only_within_the_ranges_the_format_defines() {
        let mut boot = filled();
        for (shift, want) in [(9u8, Some(512u32)), (12, Some(4096)), (8, None), (13, None)] {
            boot.bytes_per_sector_shift = shift;
            assert_eq!(boot.bytes_per_sector(), want, "shift {shift}");
        }

        // The cluster shift's ceiling depends on the sector shift, since it is their sum
        // that the format caps — which is what caps a cluster at 32 mebibytes.
        boot.bytes_per_sector_shift = 9;
        boot.sectors_per_cluster_shift = 16;
        assert_eq!(boot.bytes_per_cluster(), Some(32 << 20));
        boot.sectors_per_cluster_shift = 17;
        assert_eq!(boot.bytes_per_cluster(), None);
        boot.bytes_per_sector_shift = 12;
        boot.sectors_per_cluster_shift = 13;
        assert_eq!(boot.bytes_per_cluster(), Some(32 << 20));
        boot.sectors_per_cluster_shift = 14;
        assert_eq!(boot.bytes_per_cluster(), None);

        // A cluster shift near the top of the byte, where the *sum* of the two leaves the
        // range a byte holds. A wrapped sum is not a comparison that fails but one that
        // passes, after which the shift below it is of more bits than a 32-bit number has —
        // so the answer would be a cluster size no arithmetic produced.
        for shift in [u8::MAX, u8::MAX - 12, 244, 200] {
            boot.sectors_per_cluster_shift = shift;
            assert_eq!(boot.bytes_per_cluster(), None, "cluster shift {shift}");
        }
    }

    #[test]
    fn an_extended_boot_sector_carries_its_signature_at_its_own_end() {
        // At the end of the sector rather than at a fixed offset, so where it lands moves
        // with the sector size — which is the trap a structure with a `SIZE` constant would
        // have walked into.
        for size in [512usize, 4096] {
            let mut sector = vec![0xFFu8; size];
            write_extended_boot_sector(&mut sector);
            assert_eq!(
                extended_boot_signature(&sector),
                Some(EXTENDED_BOOT_SIGNATURE)
            );
            assert_eq!(&sector[size - 4..], &[0x00, 0x00, 0x55, 0xAA]);
            assert!(sector[..size - 4].iter().all(|b| *b == 0));
        }
        assert_eq!(extended_boot_signature(&[0u8; 3]), None);
    }

    #[test]
    fn a_checksum_sector_repeats_its_value_and_is_read_back_only_when_it_does() {
        for size in [512usize, 4096] {
            let mut sector = vec![0u8; size];
            write_checksum_sector(&mut sector, 0xDEAD_BEEF);
            assert!(
                sector
                    .chunks_exact(4)
                    .all(|w| w == 0xDEAD_BEEFu32.to_le_bytes())
            );
            assert_eq!(checksum_sector_value(&sector), Some(0xDEAD_BEEF));

            // A sector whose words disagree has no value to report. Answering the first word
            // would turn a damaged region into a confident wrong answer, which is the one
            // thing the repetition exists to prevent.
            sector[size - 1] ^= 0x01;
            assert_eq!(checksum_sector_value(&sector), None);
        }
        assert_eq!(checksum_sector_value(&[]), None);
    }
}
