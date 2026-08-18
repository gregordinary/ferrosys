//! The 32-byte directory entry, and the long-name entries that precede one.

use crate::bytes::{get_arr, get_u8, get_u16, get_u32, put_arr, put_u8, put_u16, put_u32};

use super::ParseError;

/// Bytes in one directory entry, short or long. A directory is an array of these and
/// nothing else, which is why a directory's capacity is a byte count divided by 32.
pub const DIR_ENTRY_SIZE: usize = 32;

/// The value in [`DirEntry::name`]`[0]` marking an entry as deleted. The rest of the entry
/// is left as it was, which is what makes undelete tools possible and why a writer must
/// never assume a free slot is zeroed.
pub const NAME_DELETED: u8 = 0xE5;

/// The value in [`DirEntry::name`]`[0]` marking an entry as free *and* the end of the
/// directory: no entry after it has ever been used, so a reader stops here.
pub const NAME_END: u8 = 0x00;

/// What [`NAME_DELETED`] is replaced by in a name that genuinely begins with that byte,
/// which some code pages produce. A reader substitutes it back.
pub const NAME_LEADING_E5: u8 = 0x05;

/// Code units of a long name carried by one [`LfnEntry`], across the three disjoint ranges
/// the entry splits them over.
pub const LFN_CHARS_PER_ENTRY: usize = 13;

/// The most long-name entries one name may use, and so the longest name the format holds:
/// the ordinal is six bits wide with 0 reserved, capping a name at 255 code units.
pub const LFN_MAX_ENTRIES: usize = 20;

/// The bit set in an [`LfnEntry::order`] of the entry that comes *last* in the sequence on
/// disk — which, because long-name entries are stored in reverse, is the one carrying the
/// name's final characters and the first a forward reader meets.
pub const LFN_LAST_ENTRY: u8 = 0x40;

/// The unit written into the trailing unused positions of the final long-name entry, after
/// the single `0x0000` that terminates the name.
pub const LFN_PADDING: u16 = 0xFFFF;

/// The attribute byte of a directory entry.
///
/// The four low bits are the DOS attributes; [`VOLUME_ID`](Self::VOLUME_ID) marks the
/// volume label and [`DIRECTORY`](Self::DIRECTORY) marks a subdirectory. Setting all four
/// low bits together is [`LFN`](Self::LFN), the combination that makes a long-name entry
/// invisible to every driver that predates long names — a read-only hidden system volume
/// label is not something any of them will act on.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Attributes(u8);

crate::flags::flag_set!(Attributes: u8);

impl Attributes {
    /// `ATTR_READ_ONLY`. A driver refuses to open the file for writing.
    pub const READ_ONLY: Self = Self(0x01);
    /// `ATTR_HIDDEN`. Omitted from an ordinary listing.
    pub const HIDDEN: Self = Self(0x02);
    /// `ATTR_SYSTEM`. Belongs to the operating system.
    pub const SYSTEM: Self = Self(0x04);
    /// `ATTR_VOLUME_ID`. The entry is the volume label rather than a file. There is at most
    /// one, in the root directory, and its name field is the label.
    pub const VOLUME_ID: Self = Self(0x08);
    /// `ATTR_DIRECTORY`. The entry is a subdirectory, and its size field is zero however
    /// many clusters it occupies.
    pub const DIRECTORY: Self = Self(0x10);
    /// `ATTR_ARCHIVE`. Set on every write; backup software clears it. Every mainstream
    /// driver sets it on a file it creates.
    pub const ARCHIVE: Self = Self(0x20);
    /// `ATTR_LONG_NAME`: the four low bits together, marking a long-name entry.
    pub const LFN: Self = Self(0x0F);

    /// True when the entry is a long-name entry rather than a real one.
    ///
    /// The test is equality over the six low bits and not
    /// [`contains`](Self::contains): an entry that is genuinely a read-only hidden system
    /// volume label would satisfy `contains` while being a real entry, and the
    /// specification's own rule is that the masked value *equals*
    /// [`LFN`](Self::LFN).
    #[must_use]
    pub const fn is_long_name(self) -> bool {
        self.0 & 0x3F == Self::LFN.0
    }
}

/// One 32-byte directory entry: a short name, its attributes, its times, where its data
/// starts, and how long it is.
///
/// The name is the 8.3 form, space-padded and without the separating dot — `README  TXT`,
/// not `README.TXT`. A long name lives in the [`LfnEntry`] values immediately before this
/// one, tied to it by a checksum over these eleven bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DirEntry {
    /// Bytes 0..11: the 8.3 short name, eight name bytes then three extension bytes, each
    /// space-padded, with no dot between them. The first byte doubles as the free-slot
    /// marker — see [`NAME_DELETED`], [`NAME_END`], and [`NAME_LEADING_E5`].
    pub name: [u8; 11],
    /// Byte 11: the attribute byte.
    pub attributes: Attributes,
    /// Byte 12: the case flags Windows NT added — bit 3 lowercases the name, bit 4 the
    /// extension, so `readme.txt` needs no long-name entry. A driver that does not know
    /// them ignores them and sees the uppercase name, which is why they are safe.
    pub case_flags: u8,
    /// Byte 13: hundredths of a second added to the creation time, 0 to 199. The creation
    /// time itself has two-second granularity, so this is what makes it ten-millisecond.
    pub create_time_tenth: u8,
    /// Bytes 14..16: creation time — hours in bits 11..16, minutes in 5..11, and
    /// *two-second* units in 0..5.
    pub create_time: u16,
    /// Bytes 16..18: creation date — years since 1980 in bits 9..16, month in 5..9, day in
    /// 0..5.
    pub create_date: u16,
    /// Bytes 18..20: last access date, in the same form. There is no access *time*: the
    /// format's access granularity is one day.
    pub access_date: u16,
    /// Bytes 20..22: the high half of the first cluster number. Zero on FAT12 and FAT16,
    /// where it is not part of the cluster number at all — it is kept separate from
    /// [`first_cluster_lo`](Self::first_cluster_lo) for exactly that reason, since joining
    /// the two on those types would read whatever an old driver left here as an address.
    pub first_cluster_hi: u16,
    /// Bytes 22..24: last write time, in the same form as
    /// [`create_time`](Self::create_time).
    pub write_time: u16,
    /// Bytes 24..26: last write date.
    pub write_date: u16,
    /// Bytes 26..28: the low half of the first cluster number, and the whole of it on FAT12
    /// and FAT16. Zero for an empty file, which owns no cluster.
    pub first_cluster_lo: u16,
    /// Bytes 28..32: the file's length in bytes. Zero for a directory, whose length is
    /// however many clusters its chain holds.
    pub size: u32,
}

impl DirEntry {
    /// Bytes the structure occupies.
    pub const SIZE: usize = DIR_ENTRY_SIZE;

    /// Parse an entry from the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "directory entry",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            name: get_arr::<11>(buf, 0),
            attributes: Attributes::from_bits(get_u8(buf, 11)),
            case_flags: get_u8(buf, 12),
            create_time_tenth: get_u8(buf, 13),
            create_time: get_u16(buf, 14),
            create_date: get_u16(buf, 16),
            access_date: get_u16(buf, 18),
            first_cluster_hi: get_u16(buf, 20),
            write_time: get_u16(buf, 22),
            write_date: get_u16(buf, 24),
            first_cluster_lo: get_u16(buf, 26),
            size: get_u32(buf, 28),
        })
    }

    /// Serialize into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "directory entry",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        put_arr(buf, 0, &self.name);
        put_u8(buf, 11, self.attributes.bits());
        put_u8(buf, 12, self.case_flags);
        put_u8(buf, 13, self.create_time_tenth);
        put_u16(buf, 14, self.create_time);
        put_u16(buf, 16, self.create_date);
        put_u16(buf, 18, self.access_date);
        put_u16(buf, 20, self.first_cluster_hi);
        put_u16(buf, 22, self.write_time);
        put_u16(buf, 24, self.write_date);
        put_u16(buf, 26, self.first_cluster_lo);
        put_u32(buf, 28, self.size);
        Ok(())
    }

    /// The checksum that ties a set of [`LfnEntry`] values to this entry.
    ///
    /// A long name is only valid while every one of its entries carries this byte, which is
    /// what stops a driver without long-name support from silently orphaning a name: rename
    /// the short entry and the checksum stops matching, so the stale long name is ignored
    /// rather than applied to the wrong file.
    #[must_use]
    pub fn lfn_checksum(&self) -> u8 {
        lfn_checksum(&self.name)
    }
}

/// The rotate-and-add checksum over an 8.3 short name that ties a long name to it.
///
/// Each step rotates the running value right by one bit within a byte and adds the next
/// name byte, wrapping. All eleven bytes are folded in, spaces included, so the checksum
/// is over the padded on-disk form rather than over a trimmed name.
#[must_use]
pub fn lfn_checksum(name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in name {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

/// One long-name entry: thirteen UTF-16 code units of a name, its position in the sequence,
/// and the checksum tying it to the short entry it belongs to.
///
/// Long-name entries sit *immediately before* their short entry and in *reverse* order, so
/// a reader scanning forward meets the last chunk first. The entry carrying the name's
/// final characters has [`LFN_LAST_ENTRY`] set in its [`order`](Self::order).
///
/// The thirteen units are split across three disjoint ranges — bytes 1..11, 14..26, and
/// 28..32 — because the entry has to keep byte 11 an attribute and bytes 26..28 a zero
/// cluster number, so that a driver with no long-name support reads it as a harmless
/// volume label rather than as a file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LfnEntry {
    /// Byte 0: the sequence number, counting from 1, with [`LFN_LAST_ENTRY`] set on the
    /// entry holding the name's final characters. A zero ordinal is not a valid entry;
    /// [`NAME_DELETED`] here marks the slot free, as for a short entry.
    pub order: u8,
    /// Thirteen UTF-16 code units, little-endian, spread over bytes 1..11, 14..26, and
    /// 28..32. A name shorter than the entries holding it is terminated by a single
    /// `0x0000` and padded with [`LFN_PADDING`] after that.
    pub name: [u16; LFN_CHARS_PER_ENTRY],
    /// Byte 13: [`DirEntry::lfn_checksum`] of the short entry this name belongs to. Every
    /// entry of one name carries the same value.
    pub checksum: u8,
}

impl LfnEntry {
    /// Bytes the structure occupies. A long-name entry is a directory entry in every
    /// respect but meaning.
    pub const SIZE: usize = DIR_ENTRY_SIZE;

    /// Byte offsets and lengths, in code units, of the three runs the name is split over.
    const NAME_RUNS: [(usize, usize); 3] = [(1, 5), (14, 6), (28, 2)];

    /// Parse a long-name entry from the start of `buf`.
    ///
    /// This does not check that the entry *is* one — that is
    /// [`Attributes::is_long_name`] over byte 11, which a caller has already applied to
    /// decide which of the two structures to read.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "long name entry",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        let mut name = [0u16; LFN_CHARS_PER_ENTRY];
        let mut at = 0;
        for (off, units) in Self::NAME_RUNS {
            for i in 0..units {
                name[at] = get_u16(buf, off + i * 2);
                at += 1;
            }
        }
        Ok(Self {
            order: get_u8(buf, 0),
            name,
            checksum: get_u8(buf, 13),
        })
    }

    /// Serialize into the first [`SIZE`](Self::SIZE) bytes of `buf`.
    ///
    /// The three fixed bytes that make the entry invisible to a driver without long-name
    /// support are written here and are not fields: the attribute byte at 11 is
    /// [`Attributes::LFN`], the type byte at 12 is zero, and the cluster number at 26..28 is
    /// zero. An entry that lost any of them would be read as a real file.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "long name entry",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        put_u8(buf, 0, self.order);
        let mut at = 0;
        for (off, units) in Self::NAME_RUNS {
            for i in 0..units {
                put_u16(buf, off + i * 2, self.name[at]);
                at += 1;
            }
        }
        put_u8(buf, 11, Attributes::LFN.bits());
        put_u8(buf, 12, 0);
        put_u8(buf, 13, self.checksum);
        put_u16(buf, 26, 0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> DirEntry {
        DirEntry {
            name: *b"README  TXT",
            attributes: Attributes::ARCHIVE,
            case_flags: 0,
            create_time_tenth: 100,
            create_time: 0x4A5B,
            create_date: 0x5123,
            access_date: 0x5124,
            first_cluster_hi: 0x0001,
            write_time: 0x4A5C,
            write_date: 0x5125,
            first_cluster_lo: 0x2345,
            size: 4096,
        }
    }

    #[test]
    fn a_directory_entry_round_trips() {
        let mut buf = [0xA5u8; DirEntry::SIZE];
        entry().write_to(&mut buf).expect("write");
        assert_eq!(DirEntry::read_from(&buf).expect("read"), entry());
    }

    #[test]
    fn the_entry_fields_are_where_the_format_puts_them() {
        let mut buf = [0u8; DirEntry::SIZE];
        entry().write_to(&mut buf).expect("write");
        assert_eq!(&buf[0..11], b"README  TXT");
        assert_eq!(buf[11], 0x20);
        assert_eq!(buf[13], 100);
        assert_eq!(u16::from_le_bytes([buf[20], buf[21]]), 1);
        assert_eq!(u16::from_le_bytes([buf[26], buf[27]]), 0x2345);
        assert_eq!(
            u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
            4096
        );
    }

    #[test]
    fn the_two_halves_of_a_cluster_number_stay_apart() {
        // FAT12 and FAT16 do not have a high half, and a driver on those types leaves
        // whatever it likes at bytes 20..22. Joining them in the on-disk type would make
        // that a file's address, so the halves are separate fields and the reader joins
        // them only where the type says to.
        let mut buf = [0u8; DirEntry::SIZE];
        entry().write_to(&mut buf).expect("write");
        let read = DirEntry::read_from(&buf).expect("read");
        assert_eq!(read.first_cluster_lo, 0x2345);
        assert_eq!(read.first_cluster_hi, 0x0001);
    }

    #[test]
    fn a_long_name_entry_round_trips_across_its_three_runs() {
        let mut name = [LFN_PADDING; LFN_CHARS_PER_ENTRY];
        for (i, unit) in "A Long File N".encode_utf16().enumerate() {
            name[i] = unit;
        }
        let original = LfnEntry {
            order: 1 | LFN_LAST_ENTRY,
            name,
            checksum: 0x5D,
        };
        let mut buf = [0xA5u8; LfnEntry::SIZE];
        original.write_to(&mut buf).expect("write");
        assert_eq!(LfnEntry::read_from(&buf).expect("read"), original);

        // The runs are disjoint and in the order the format states: five units at 1, six at
        // 14, two at 28. A single contiguous run would satisfy the round trip above.
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), u16::from(b'A'));
        assert_eq!(u16::from_le_bytes([buf[14], buf[15]]), u16::from(b'g'));
        assert_eq!(u16::from_le_bytes([buf[28], buf[29]]), u16::from(b' '));
        // And the three bytes that keep the entry invisible to a driver without long-name
        // support are written whatever the buffer held.
        assert_eq!(buf[11], Attributes::LFN.bits());
        assert_eq!(buf[12], 0);
        assert_eq!(u16::from_le_bytes([buf[26], buf[27]]), 0);
    }

    #[test]
    fn the_checksum_is_the_specification_s_rotate_and_add() {
        // mtools writes `A Long File Name.txt` with the short name `ALONGF~1TXT`, which the
        // oracle tier observes. Both derivations of its checksum have to agree: the
        // specification's own loop, spelled out here, and the implementation.
        let name = b"ALONGF~1TXT";
        let mut expected: u8 = 0;
        for &b in name {
            expected = ((expected & 1) << 7)
                .wrapping_add(expected >> 1)
                .wrapping_add(b);
        }
        assert_eq!(lfn_checksum(name), expected);

        // It folds in all eleven bytes including the padding spaces, so two names differing
        // only in where the padding falls do not collide.
        assert_ne!(lfn_checksum(b"AB      TXT"), lfn_checksum(b"ABTXT      "));
    }

    #[test]
    fn a_long_name_belongs_to_the_entry_whose_short_name_it_checksums() {
        let e = entry();
        assert_eq!(e.lfn_checksum(), lfn_checksum(b"README  TXT"));
        // Renaming the short entry breaks the tie, which is the property that stops a
        // driver without long-name support from orphaning a name onto the wrong file.
        let mut renamed = e;
        renamed.name = *b"README2 TXT";
        assert_ne!(renamed.lfn_checksum(), e.lfn_checksum());
    }

    #[test]
    fn an_entry_is_a_long_name_only_on_the_exact_attribute() {
        assert!(Attributes::LFN.is_long_name());
        // A real entry that happens to carry every one of the four bits is still real: the
        // rule is equality over the low six bits, not containment.
        let real = Attributes::READ_ONLY | Attributes::HIDDEN | Attributes::SYSTEM;
        assert!(!real.is_long_name());
        assert!(!Attributes::VOLUME_ID.is_long_name());
        assert!(!(Attributes::LFN | Attributes::DIRECTORY).is_long_name());
        assert!(Attributes::LFN.contains(Attributes::VOLUME_ID));
    }

    #[test]
    fn a_short_buffer_is_refused_rather_than_indexed() {
        let mut buf = [0u8; DIR_ENTRY_SIZE - 1];
        assert!(matches!(
            DirEntry::read_from(&buf),
            Err(ParseError::TooShort { .. })
        ));
        assert!(matches!(
            LfnEntry::read_from(&buf),
            Err(ParseError::TooShort { .. })
        ));
        assert!(matches!(
            entry().write_to(&mut buf),
            Err(ParseError::TooShort { .. })
        ));
    }
}
