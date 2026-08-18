//! The 32-byte directory entry every exFAT directory is made of, and the type byte that
//! says what one is.
//!
//! Every entry is the same width and the same shape: one type byte, and 31 bytes whose
//! meaning that byte decides. What a file needs is more than one entry — a *set* — and the
//! set is the unit a checksum covers, which is what makes a half-written one detectable.
//!
//! [`DirEntry`] is an entry before anything has decided what kind it is. The three typed
//! entries beside it are the ones a format writes into a root directory before anything has
//! been put on the volume: the volume's name, and the two describing the residents of the
//! cluster heap that every driver has to find before it can read anything else.

use crate::bytes::{
    get_arr, get_u8, get_u16, get_u32, get_u64, put_arr, put_u8, put_u16, put_u32, put_u64,
};

use super::ParseError;

/// Bytes one directory entry occupies. Every entry, of every type, is this wide.
pub const DIR_ENTRY_SIZE: usize = 32;

/// A directory entry's type byte: what the entry is, and whether it is in use.
///
/// The byte is four fields. The high bit is [`in_use`](Self::in_use); the next says whether
/// the entry is [`secondary`](Self::is_secondary), meaning it belongs to the set opened by
/// the entry before it; the next says whether it is [`benign`](Self::is_benign), meaning an
/// implementation that does not recognize it may carry on rather than refuse the volume; and
/// the low five bits are the [`code`](Self::code) distinguishing one type from another
/// within those categories.
///
/// # A directory ends at a zero byte and nowhere else
///
/// [`is_end_of_directory`](Self::is_end_of_directory) is the terminator, and it is the only
/// one. An entry whose in-use bit is clear is *skipped* and enumeration continues — which is
/// not an edge case to be handled later: the second slot of the root directory of a freshly
/// formatted volume is exactly that, a volume GUID entry reserved by clearing its in-use
/// bit, and the allocation bitmap and the up-case table are behind it. A reader that stopped
/// at the first entry not in use would find neither, on a conformant volume, silently.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EntryType(pub u8);

impl EntryType {
    /// The end of a directory: a zero type byte, and every slot behind it unused.
    pub const END_OF_DIRECTORY: Self = Self(0x00);

    /// The allocation bitmap's describing entry, one per volume.
    pub const ALLOCATION_BITMAP: Self = Self(0x81);

    /// The up-case table's describing entry, one per volume, carrying the table's checksum.
    pub const UPCASE_TABLE: Self = Self(0x82);

    /// The volume label, up to 11 UTF-16 code units. A volume formatted with no label
    /// carries this entry with a length of zero rather than no entry at all.
    pub const VOLUME_LABEL: Self = Self(0x83);

    /// A file or directory: the primary entry of a set, carrying the count of the secondary
    /// entries behind it and the checksum over all of them.
    pub const FILE: Self = Self(0x85);

    /// The volume GUID, optional. Its slot is reserved on every volume any tool formats,
    /// with the in-use bit cleared where no GUID was supplied.
    pub const VOLUME_GUID: Self = Self(0xA0);

    /// The stream extension: the second entry of a file's set, carrying the name's length
    /// and hash and the file's allocation.
    pub const STREAM_EXTENSION: Self = Self(0xC0);

    /// One 15-code-unit chunk of a file's name. A set carries as many as the name needs.
    pub const FILE_NAME: Self = Self(0xC1);

    /// A vendor's own entry within a file's set, identified by a GUID inside it. Secondary
    /// and benign, so a reader that does not know the vendor carries the entry through
    /// rather than refusing the volume it is in.
    pub const VENDOR_EXTENSION: Self = Self(0xE0);

    /// A vendor's own entry within a file's set, with an allocation attached. Secondary and
    /// benign, like the extension it sits beside.
    pub const VENDOR_ALLOCATION: Self = Self(0xE1);

    /// Bit 7: the entry holds something. Cleared marks the slot free for reuse.
    const IN_USE: u8 = 0x80;

    /// Bit 6: the entry continues the set the entry before it opened.
    const SECONDARY: u8 = 0x40;

    /// Bit 5: an implementation that does not recognize the entry may ignore it.
    const BENIGN: u8 = 0x20;

    /// Whether this byte ends the directory.
    ///
    /// The one terminator. See the type's own documentation for why a cleared in-use bit is
    /// not another.
    #[must_use]
    pub const fn is_end_of_directory(self) -> bool {
        self.0 == Self::END_OF_DIRECTORY.0
    }

    /// Whether the entry holds something, from bit 7.
    ///
    /// An entry that does not is skipped; enumeration continues past it.
    #[must_use]
    pub const fn in_use(self) -> bool {
        self.0 & Self::IN_USE != 0
    }

    /// Whether the entry continues the set the entry before it opened, from bit 6.
    #[must_use]
    pub const fn is_secondary(self) -> bool {
        self.0 & Self::SECONDARY != 0
    }

    /// Whether an implementation that does not recognize the entry may carry on, from bit 5.
    ///
    /// A *critical* entry it does not recognize means it cannot claim to understand the
    /// volume; a benign one it does not recognize means only that there is something there
    /// it has nothing to say about.
    #[must_use]
    pub const fn is_benign(self) -> bool {
        self.0 & Self::BENIGN != 0
    }

    /// The five-bit code distinguishing one type from another within its categories.
    #[must_use]
    pub const fn code(self) -> u8 {
        self.0 & 0x1F
    }

    /// This type with its in-use bit cleared: the entry as a directory records a slot it is
    /// deliberately keeping empty, or one it has deleted.
    ///
    /// [`END_OF_DIRECTORY`](Self::END_OF_DIRECTORY) is left alone, because a zero byte with
    /// nothing cleared is already the terminator and there is no entry there to mark unused.
    #[must_use]
    pub const fn cleared(self) -> Self {
        Self(self.0 & !Self::IN_USE)
    }
}

/// One directory entry, read as the format's generic shape: a type byte and 31 bytes whose
/// meaning it decides.
///
/// This is what an entry is before anything has decided what kind it is, and what a reader
/// holds for a benign entry it does not interpret — a vendor's own, say, which is carried
/// through unchanged rather than synthesized or dropped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DirEntry {
    /// Byte 0: what the entry is.
    pub entry_type: EntryType,
    /// Bytes 1..32: whatever [`entry_type`](Self::entry_type) says they are.
    pub custom: [u8; DIR_ENTRY_SIZE - 1],
}

impl DirEntry {
    /// Bytes the structure occupies.
    pub const SIZE: usize = DIR_ENTRY_SIZE;

    /// Read one entry from the start of `buf`.
    ///
    /// Every 32-byte sequence is an entry of some type, so there is no signature to check
    /// and nothing here can fail but the length.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "exFAT directory entry",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            entry_type: EntryType(get_u8(buf, 0)),
            custom: get_arr::<{ DIR_ENTRY_SIZE - 1 }>(buf, 1),
        })
    }

    /// Write the entry into the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`SIZE`](Self::SIZE).
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        if buf.len() < Self::SIZE {
            return Err(ParseError::TooShort {
                structure: "exFAT directory entry",
                need: Self::SIZE,
                got: buf.len(),
            });
        }
        put_u8(buf, 0, self.entry_type.0);
        put_arr(buf, 1, &self.custom);
        Ok(())
    }

    /// A slot holding nothing, reserved by writing `entry_type` with its in-use bit cleared.
    ///
    /// This is what the second slot of a formatted volume's root directory is: an `0xA0`
    /// volume GUID entry a formatter deliberately left empty, because one entry alone can
    /// never hold a file set and the slot would otherwise have to be the end of the
    /// directory. A reader steps over it and carries on
    /// ([`EntryType::is_end_of_directory`]).
    #[must_use]
    pub const fn reserved(entry_type: EntryType) -> Self {
        Self {
            entry_type: entry_type.cleared(),
            custom: [0; DIR_ENTRY_SIZE - 1],
        }
    }
}

/// The volume label entry: the name a volume answers to, in the root directory's first slot.
///
/// A volume with no name carries this entry all the same, with a character count of zero and
/// a name of zeroes. The entry is written, not omitted — which is what a byte comparison
/// against another implementation's output turns on, and what a driver reads as "this volume
/// has no name".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VolumeLabelEntry {
    /// Byte 1: how many of [`label`](Self::label)'s units are the name. Units past it are
    /// zero.
    pub character_count: u8,
    /// Bytes 2..24: the name, as UTF-16 code units, padded with zeroes.
    pub label: [u16; MAX_LABEL_UNITS],
}

/// The most UTF-16 code units a volume label holds. The field is 22 bytes wide.
pub const MAX_LABEL_UNITS: usize = 11;

impl VolumeLabelEntry {
    /// The entry a volume with no name carries.
    pub const UNNAMED: Self = Self {
        character_count: 0,
        label: [0; MAX_LABEL_UNITS],
    };

    /// Read the entry from the start of `buf`.
    ///
    /// The character count is recovered as it stands. A count past
    /// [`MAX_LABEL_UNITS`] is a judgment about a recovered field rather than a failure to
    /// recover it, so it is reported by whatever read the volume and not here.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`], and
    /// [`ParseError::BadMagic`] when the type byte is not
    /// [`EntryType::VOLUME_LABEL`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        expect_type(buf, EntryType::VOLUME_LABEL, "exFAT volume label entry")?;
        Ok(Self {
            character_count: get_u8(buf, 1),
            label: core::array::from_fn(|i| get_u16(buf, 2 + i * 2)),
        })
    }

    /// Write the entry into the start of `buf`.
    ///
    /// The eight reserved bytes at offset 24 are written as the zeroes the format requires
    /// rather than left as whatever `buf` held.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`].
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        let buf = entry_slot(buf, "exFAT volume label entry")?;
        put_u8(buf, 0, EntryType::VOLUME_LABEL.0);
        put_u8(buf, 1, self.character_count);
        for (i, unit) in self.label.iter().enumerate() {
            put_u16(buf, 2 + i * 2, *unit);
        }
        buf[24..DIR_ENTRY_SIZE].fill(0);
        Ok(())
    }
}

/// The allocation bitmap's describing entry: where the bitmap the volume allocates through
/// lives, and how long it is.
///
/// One per volume, in the root directory. The bitmap is a bit per cluster, so a driver cannot
/// allocate anything until it has read this entry — which is why the reserved slot ahead of
/// it in the root is not a place a reader may stop
/// ([`EntryType::is_end_of_directory`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AllocationBitmapEntry {
    /// Byte 1: which allocation table this bitmap describes. Zero on every volume with one
    /// table, which is every volume outside the transaction-safe variant.
    pub bitmap_flags: u8,
    /// Bytes 20..24: the bitmap's first cluster.
    pub first_cluster: u32,
    /// Bytes 24..32: the bitmap's length in bytes, which is one bit per cluster rounded up.
    pub data_length: u64,
}

impl AllocationBitmapEntry {
    /// Read the entry from the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`], and
    /// [`ParseError::BadMagic`] when the type byte is not
    /// [`EntryType::ALLOCATION_BITMAP`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        expect_type(
            buf,
            EntryType::ALLOCATION_BITMAP,
            "exFAT allocation bitmap entry",
        )?;
        Ok(Self {
            bitmap_flags: get_u8(buf, 1),
            first_cluster: get_u32(buf, 20),
            data_length: get_u64(buf, 24),
        })
    }

    /// Write the entry into the start of `buf`.
    ///
    /// The eighteen reserved bytes at offset 2 are written as the zeroes the format requires.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`].
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        let buf = entry_slot(buf, "exFAT allocation bitmap entry")?;
        put_u8(buf, 0, EntryType::ALLOCATION_BITMAP.0);
        put_u8(buf, 1, self.bitmap_flags);
        buf[2..20].fill(0);
        put_u32(buf, 20, self.first_cluster);
        put_u64(buf, 24, self.data_length);
        Ok(())
    }
}

/// The up-case table's describing entry: where the volume's case folding lives, how long it
/// is, and the checksum that says it is the mapping it claims to be.
///
/// The checksum is what makes this entry more than an address. A volume is free to carry a
/// table that is not the recommended one, so a reader folds names through whatever is here —
/// and the only thing standing between "the table this volume folds through" and "whatever
/// bytes are at that cluster" is [`table_checksum`](Self::table_checksum).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UpcaseTableEntry {
    /// Bytes 4..8: the checksum over every byte of the table.
    pub table_checksum: u32,
    /// Bytes 20..24: the table's first cluster.
    pub first_cluster: u32,
    /// Bytes 24..32: the table's length in bytes.
    pub data_length: u64,
}

impl UpcaseTableEntry {
    /// Read the entry from the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`], and
    /// [`ParseError::BadMagic`] when the type byte is not [`EntryType::UPCASE_TABLE`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        expect_type(buf, EntryType::UPCASE_TABLE, "exFAT up-case table entry")?;
        Ok(Self {
            table_checksum: get_u32(buf, 4),
            first_cluster: get_u32(buf, 20),
            data_length: get_u64(buf, 24),
        })
    }

    /// Write the entry into the start of `buf`.
    ///
    /// The three reserved bytes at offset 1 and the twelve at offset 8 are written as the
    /// zeroes the format requires.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`].
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        let buf = entry_slot(buf, "exFAT up-case table entry")?;
        put_u8(buf, 0, EntryType::UPCASE_TABLE.0);
        buf[1..4].fill(0);
        put_u32(buf, 4, self.table_checksum);
        buf[8..20].fill(0);
        put_u32(buf, 20, self.first_cluster);
        put_u64(buf, 24, self.data_length);
        Ok(())
    }
}

/// The attribute word of a file entry, at offset 4.
///
/// Five of the sixteen bits are defined and they are the DOS attributes exFAT kept.
/// [`DIRECTORY`](Self::DIRECTORY) is the one a reader must act on; the rest describe how a
/// shell presents the entry and what a driver will let a caller do to it.
///
/// The bit FAT uses to mark its volume label is reserved here and is zero on every volume:
/// exFAT gives the label an entry type of its own rather than an attribute, so there is no
/// entry that is a label and a file at once.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FileAttributes(u16);

crate::flags::flag_set!(FileAttributes: u16);

impl FileAttributes {
    /// The file may not be opened for writing.
    pub const READ_ONLY: Self = Self(0x0001);
    /// Omitted from an ordinary listing.
    pub const HIDDEN: Self = Self(0x0002);
    /// Belongs to the operating system.
    pub const SYSTEM: Self = Self(0x0004);
    /// The entry is a directory. Its stream extension addresses the clusters holding the
    /// entries in it.
    pub const DIRECTORY: Self = Self(0x0010);
    /// Set on every write; backup software clears it. Every mainstream driver sets it on a
    /// file it creates.
    pub const ARCHIVE: Self = Self(0x0020);

    /// The bits the format defines. Everything else is reserved and zero on a conformant
    /// volume.
    pub const DEFINED: Self = Self(0x0037);
}

/// Secondary entries a file's set may carry, which the count field's own width allows.
///
/// A set is one file entry and this many behind it. What actually fits is smaller — a stream
/// extension and at most [`MAX_NAME_ENTRIES`] name entries — and the smaller bound is the one
/// a writer is held to; this is the field.
pub const MAX_SECONDARY_COUNT: u8 = 255;

/// UTF-16 code units one name entry carries. A name is spread across as many as it needs,
/// with the last one padded.
pub const NAME_UNITS_PER_ENTRY: usize = 15;

/// The most UTF-16 code units a file name holds, which the stream extension's `NameLength`
/// byte bounds.
pub const MAX_NAME_UNITS: usize = 255;

/// Name entries the longest name needs, which with the stream extension ahead of them is the
/// largest secondary count a file set really has.
pub const MAX_NAME_ENTRIES: usize = MAX_NAME_UNITS.div_ceil(NAME_UNITS_PER_ENTRY);

/// Bit 0 of a secondary entry's flags: the entry may address clusters. A stream extension
/// always sets it, whether or not it currently addresses any.
pub const SECONDARY_ALLOCATION_POSSIBLE: u8 = 0x01;

/// Bit 1 of a secondary entry's flags: the clusters this entry addresses are consecutive, so
/// the allocation table holds no chain for them and a reader must not consult it.
pub const SECONDARY_NO_FAT_CHAIN: u8 = 0x02;

/// The primary entry of a file or directory: what it is, when it was touched, and how many
/// entries behind it belong to it.
///
/// A file is never one entry. This opens a *set* — itself, a [`StreamExtensionEntry`], and a
/// [`FileNameEntry`] for every fifteen code units of the name — and
/// [`set_checksum`](Self::set_checksum) covers all of them, which is what makes a set that was
/// half written detectable rather than merely odd.
///
/// The three times are packed date and time words with a hundredths byte and a zone offset
/// beside them. Two of the three have a hundredths byte; the access time does not, and is
/// therefore granular to two seconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileEntry {
    /// Byte 1: entries behind this one that belong to this set.
    pub secondary_count: u8,
    /// Bytes 2..4: the checksum over the whole set, this field excepted.
    pub set_checksum: u16,
    /// Bytes 4..6: what the entry is and what may be done to it.
    pub attributes: FileAttributes,
    /// Bytes 8..12: the creation date and time, packed.
    pub create: u32,
    /// Bytes 12..16: the modification date and time, packed.
    pub modify: u32,
    /// Bytes 16..20: the access date and time, packed. It has no hundredths field.
    pub access: u32,
    /// Byte 20: hundredths of a second past the creation time, 0 to 199.
    pub create_tenth: u8,
    /// Byte 21: hundredths of a second past the modification time, 0 to 199.
    pub modify_tenth: u8,
    /// Byte 22: the creation time's offset from UTC.
    pub create_utc_offset: u8,
    /// Byte 23: the modification time's offset from UTC.
    pub modify_utc_offset: u8,
    /// Byte 24: the access time's offset from UTC.
    pub access_utc_offset: u8,
}

impl FileEntry {
    /// Read the entry from the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`], and
    /// [`ParseError::BadMagic`] when the type byte is not [`EntryType::FILE`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        expect_type(buf, EntryType::FILE, "exFAT file entry")?;
        Ok(Self {
            secondary_count: get_u8(buf, 1),
            set_checksum: get_u16(buf, 2),
            attributes: FileAttributes::from_bits(get_u16(buf, 4)),
            create: get_u32(buf, 8),
            modify: get_u32(buf, 12),
            access: get_u32(buf, 16),
            create_tenth: get_u8(buf, 20),
            modify_tenth: get_u8(buf, 21),
            create_utc_offset: get_u8(buf, 22),
            modify_utc_offset: get_u8(buf, 23),
            access_utc_offset: get_u8(buf, 24),
        })
    }

    /// Write the entry into the start of `buf`.
    ///
    /// The checksum field is written as it stands. It covers the entries behind this one as
    /// well as this one, so it can only be computed once the whole set has been laid out —
    /// which means a set is serialized, then checksummed, then patched.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`].
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        let buf = entry_slot(buf, "exFAT file entry")?;
        put_u8(buf, 0, EntryType::FILE.0);
        put_u8(buf, 1, self.secondary_count);
        put_u16(buf, 2, self.set_checksum);
        put_u16(buf, 4, self.attributes.bits());
        put_u16(buf, 6, 0);
        put_u32(buf, 8, self.create);
        put_u32(buf, 12, self.modify);
        put_u32(buf, 16, self.access);
        put_u8(buf, 20, self.create_tenth);
        put_u8(buf, 21, self.modify_tenth);
        put_u8(buf, 22, self.create_utc_offset);
        put_u8(buf, 23, self.modify_utc_offset);
        put_u8(buf, 24, self.access_utc_offset);
        buf[25..DIR_ENTRY_SIZE].fill(0);
        Ok(())
    }
}

/// The second entry of a file's set: the name's length and hash, and where the bytes are.
///
/// Two lengths, and the difference between them is the point. [`data_length`](Self::data_length)
/// is how much the entry claims the file is; [`valid_data_length`](Self::valid_data_length) is
/// how much of it has been written. Everything between the two is allocated and *undefined*
/// rather than zero, so a reader that returned it would hand back whatever the medium last
/// held there.
///
/// A stream this crate writes has the two equal: a format writes every byte it allocates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StreamExtensionEntry {
    /// Byte 1: [`SECONDARY_ALLOCATION_POSSIBLE`] and [`SECONDARY_NO_FAT_CHAIN`].
    pub flags: u8,
    /// Byte 3: the name's length in UTF-16 code units, which the name entries behind carry
    /// fifteen at a time.
    pub name_length: u8,
    /// Bytes 4..6: the hash of the up-cased name, which a driver uses to skip a set without
    /// reassembling the name in it.
    pub name_hash: u16,
    /// Bytes 8..16: how many bytes of the allocation have been written.
    pub valid_data_length: u64,
    /// Bytes 20..24: the first cluster, or zero where the stream has no allocation.
    pub first_cluster: u32,
    /// Bytes 24..32: how long the file is.
    pub data_length: u64,
}

impl StreamExtensionEntry {
    /// Whether the clusters this stream holds are consecutive, so the allocation table holds
    /// no chain for them.
    #[must_use]
    pub const fn no_fat_chain(&self) -> bool {
        self.flags & SECONDARY_NO_FAT_CHAIN != 0
    }

    /// Read the entry from the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`], and
    /// [`ParseError::BadMagic`] when the type byte is not [`EntryType::STREAM_EXTENSION`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        expect_type(
            buf,
            EntryType::STREAM_EXTENSION,
            "exFAT stream extension entry",
        )?;
        Ok(Self {
            flags: get_u8(buf, 1),
            name_length: get_u8(buf, 3),
            name_hash: get_u16(buf, 4),
            valid_data_length: get_u64(buf, 8),
            first_cluster: get_u32(buf, 20),
            data_length: get_u64(buf, 24),
        })
    }

    /// Write the entry into the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`].
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        let buf = entry_slot(buf, "exFAT stream extension entry")?;
        put_u8(buf, 0, EntryType::STREAM_EXTENSION.0);
        put_u8(buf, 1, self.flags);
        put_u8(buf, 2, 0);
        put_u8(buf, 3, self.name_length);
        put_u16(buf, 4, self.name_hash);
        put_u16(buf, 6, 0);
        put_u64(buf, 8, self.valid_data_length);
        put_u32(buf, 16, 0);
        put_u32(buf, 20, self.first_cluster);
        put_u64(buf, 24, self.data_length);
        Ok(())
    }
}

/// One fifteen-unit piece of a file's name.
///
/// A name is spread across as many of these as it needs, in order, and the count is not
/// recorded here — the stream extension's `name_length` is what says where the name stops, and
/// the units past it in the last entry are padding a reader ignores.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileNameEntry {
    /// Byte 1: the secondary flags. A name addresses no clusters, so this is zero.
    pub flags: u8,
    /// Bytes 2..32: fifteen UTF-16 code units of the name.
    pub units: [u16; NAME_UNITS_PER_ENTRY],
}

impl FileNameEntry {
    /// The entry carrying `units`, which is at most [`NAME_UNITS_PER_ENTRY`] of them, padded
    /// with zeroes.
    ///
    /// Zero padding rather than the `0xFFFF` its FAT counterpart pads with: exFAT counts a
    /// name's units rather than terminating it, so the padding is never read and the format
    /// asks for nothing in particular there. Zero is what every implementation writes, and a
    /// byte comparison against one of them sees it.
    ///
    /// # Panics
    ///
    /// If `units` is longer than [`NAME_UNITS_PER_ENTRY`].
    #[must_use]
    pub fn new(units: &[u16]) -> Self {
        assert!(
            units.len() <= NAME_UNITS_PER_ENTRY,
            "a name entry holds {NAME_UNITS_PER_ENTRY} units, not {}",
            units.len()
        );
        let mut all = [0u16; NAME_UNITS_PER_ENTRY];
        all[..units.len()].copy_from_slice(units);
        Self {
            flags: 0,
            units: all,
        }
    }

    /// Read the entry from the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`], and
    /// [`ParseError::BadMagic`] when the type byte is not [`EntryType::FILE_NAME`].
    pub fn read_from(buf: &[u8]) -> Result<Self, ParseError> {
        expect_type(buf, EntryType::FILE_NAME, "exFAT file name entry")?;
        Ok(Self {
            flags: get_u8(buf, 1),
            units: core::array::from_fn(|i| get_u16(buf, 2 + i * 2)),
        })
    }

    /// Write the entry into the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`ParseError::TooShort`] when `buf` is shorter than [`DIR_ENTRY_SIZE`].
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ParseError> {
        let buf = entry_slot(buf, "exFAT file name entry")?;
        put_u8(buf, 0, EntryType::FILE_NAME.0);
        put_u8(buf, 1, self.flags);
        for (i, unit) in self.units.iter().enumerate() {
            put_u16(buf, 2 + i * 2, *unit);
        }
        Ok(())
    }
}

/// The one entry's worth of `buf` a typed entry writes into, or [`ParseError::TooShort`].
///
/// Narrowing to exactly [`DIR_ENTRY_SIZE`] is what lets each `write_to` fill its reserved
/// runs by range without the ranges meaning something different on a longer buffer.
fn entry_slot<'a>(buf: &'a mut [u8], structure: &'static str) -> Result<&'a mut [u8], ParseError> {
    if buf.len() < DIR_ENTRY_SIZE {
        return Err(ParseError::TooShort {
            structure,
            need: DIR_ENTRY_SIZE,
            got: buf.len(),
        });
    }
    Ok(&mut buf[..DIR_ENTRY_SIZE])
}

/// Check that `buf` holds an entry of `entry_type`, before any of its fields are recovered.
///
/// A typed entry's fields mean nothing without its type byte: offset 20 is a first cluster on
/// three of the types here and part of a name on a fourth, so recovering the fields of the
/// wrong type produces a plausible structure describing a place on the volume that holds
/// something else.
fn expect_type(
    buf: &[u8],
    entry_type: EntryType,
    structure: &'static str,
) -> Result<(), ParseError> {
    if buf.len() < DIR_ENTRY_SIZE {
        return Err(ParseError::TooShort {
            structure,
            need: DIR_ENTRY_SIZE,
            got: buf.len(),
        });
    }
    let found = get_u8(buf, 0);
    if found != entry_type.0 {
        return Err(ParseError::BadMagic {
            structure,
            found: u32::from(found),
            expected: u32::from(entry_type.0),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_round_trips() {
        let entry = DirEntry {
            entry_type: EntryType::STREAM_EXTENSION,
            custom: core::array::from_fn(|i| i as u8),
        };
        let mut buf = [0u8; DIR_ENTRY_SIZE];
        entry.write_to(&mut buf).expect("write");
        assert_eq!(DirEntry::read_from(&buf).expect("read"), entry);
        assert_eq!(buf[0], 0xC0);
        assert_eq!(&buf[1..], &(0u8..31).collect::<Vec<_>>()[..]);

        assert!(matches!(
            DirEntry::read_from(&buf[..31]),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn the_type_byte_decodes_into_the_four_fields_it_is() {
        // Read off the well-known codes rather than off a synthetic byte, so a bit assigned
        // to the wrong field shows up as a type describing itself wrongly.
        for (entry, secondary, benign, code) in [
            (EntryType::ALLOCATION_BITMAP, false, false, 1),
            (EntryType::UPCASE_TABLE, false, false, 2),
            (EntryType::VOLUME_LABEL, false, false, 3),
            (EntryType::FILE, false, false, 5),
            (EntryType::VOLUME_GUID, false, true, 0),
            (EntryType::STREAM_EXTENSION, true, false, 0),
            (EntryType::FILE_NAME, true, false, 1),
            (EntryType::VENDOR_EXTENSION, true, true, 0),
            (EntryType::VENDOR_ALLOCATION, true, true, 1),
        ] {
            assert!(entry.in_use(), "{entry:?}");
            assert!(!entry.is_end_of_directory(), "{entry:?}");
            assert_eq!(entry.is_secondary(), secondary, "{entry:?}");
            assert_eq!(entry.is_benign(), benign, "{entry:?}");
            assert_eq!(entry.code(), code, "{entry:?}");
        }

        // The volume GUID is the one entry a format writes that an implementation may
        // ignore, and the two vendor entries are the two a file's set may carry that one
        // may. Nothing else a volume this crate writes is benign, so an entry a reader does
        // not recognize is a volume it cannot claim to understand.
        for critical in [
            EntryType::ALLOCATION_BITMAP,
            EntryType::UPCASE_TABLE,
            EntryType::VOLUME_LABEL,
            EntryType::FILE,
            EntryType::STREAM_EXTENSION,
            EntryType::FILE_NAME,
        ] {
            assert!(!critical.is_benign(), "{critical:?}");
        }
    }

    #[test]
    fn a_cleared_in_use_bit_is_not_the_end_of_a_directory() {
        // The rule the very first image any exFAT tool produces depends on: its root's
        // second slot is a volume GUID entry with the in-use bit cleared, and the allocation
        // bitmap and the up-case table are behind it. A reader that read this as a
        // terminator would find neither.
        let reserved = EntryType::VOLUME_GUID.cleared();
        assert_eq!(reserved, EntryType(0x20));
        assert!(!reserved.in_use());
        assert!(
            !reserved.is_end_of_directory(),
            "an entry not in use is skipped, not a terminator"
        );
        // Clearing preserves everything else about the type, so what the slot was is still
        // readable after it is freed.
        assert_eq!(reserved.code(), EntryType::VOLUME_GUID.code());
        assert_eq!(
            reserved.is_secondary(),
            EntryType::VOLUME_GUID.is_secondary()
        );

        // And the terminator is the one byte that is one.
        assert!(EntryType::END_OF_DIRECTORY.is_end_of_directory());
        assert!(!EntryType::END_OF_DIRECTORY.in_use());
        assert_eq!(
            EntryType::END_OF_DIRECTORY.cleared(),
            EntryType::END_OF_DIRECTORY,
            "there is no entry at a terminator to mark unused"
        );
    }

    #[test]
    fn a_reserved_slot_is_a_type_byte_and_nothing_else() {
        // The second slot of every formatted volume's root directory, byte for byte.
        let mut buf = [0xFFu8; DIR_ENTRY_SIZE];
        DirEntry::reserved(EntryType::VOLUME_GUID)
            .write_to(&mut buf)
            .expect("write");
        assert_eq!(buf[0], 0x20);
        assert!(buf[1..].iter().all(|b| *b == 0));
    }

    #[test]
    fn the_three_format_time_entries_round_trip() {
        let label = VolumeLabelEntry {
            character_count: 3,
            label: [0x0045, 0x0053, 0x0050, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let bitmap = AllocationBitmapEntry {
            bitmap_flags: 0,
            first_cluster: 2,
            data_length: 960,
        };
        let upcase = UpcaseTableEntry {
            table_checksum: 0xE619_D30D,
            first_cluster: 3,
            data_length: 5836,
        };

        let mut buf = [0u8; DIR_ENTRY_SIZE];
        label.write_to(&mut buf).expect("write");
        assert_eq!(VolumeLabelEntry::read_from(&buf).expect("read"), label);
        bitmap.write_to(&mut buf).expect("write");
        assert_eq!(
            AllocationBitmapEntry::read_from(&buf).expect("read"),
            bitmap
        );
        upcase.write_to(&mut buf).expect("write");
        assert_eq!(UpcaseTableEntry::read_from(&buf).expect("read"), upcase);
    }

    #[test]
    fn every_field_of_the_format_time_entries_lands_where_the_format_puts_it() {
        // Asserted as raw bytes rather than read back through the accessors the writer used:
        // reading a field back through its own accessor is a statement about consistency, and
        // byte-exactness is the one property this crate cannot check against itself. Each of
        // these is one entry of the root directory a formatted volume carries.
        let mut buf = [0xFFu8; DIR_ENTRY_SIZE];

        VolumeLabelEntry {
            character_count: 3,
            label: [0x0045, 0x0053, 0x0050, 0, 0, 0, 0, 0, 0, 0, 0],
        }
        .write_to(&mut buf)
        .expect("write");
        assert_eq!(buf[0], 0x83);
        assert_eq!(buf[1], 3);
        assert_eq!(&buf[2..8], &[0x45, 0x00, 0x53, 0x00, 0x50, 0x00]);
        assert!(
            buf[8..24].iter().all(|b| *b == 0),
            "the name is zero-padded"
        );
        assert!(buf[24..].iter().all(|b| *b == 0), "the reserved tail");

        let mut buf = [0xFFu8; DIR_ENTRY_SIZE];
        AllocationBitmapEntry {
            bitmap_flags: 0,
            first_cluster: 2,
            data_length: 960,
        }
        .write_to(&mut buf)
        .expect("write");
        assert_eq!(buf[0], 0x81);
        assert_eq!(buf[1], 0);
        assert!(buf[2..20].iter().all(|b| *b == 0), "the reserved run");
        assert_eq!(&buf[20..24], &2u32.to_le_bytes());
        assert_eq!(&buf[24..32], &960u64.to_le_bytes());

        let mut buf = [0xFFu8; DIR_ENTRY_SIZE];
        UpcaseTableEntry {
            table_checksum: 0xE619_D30D,
            first_cluster: 3,
            data_length: 5836,
        }
        .write_to(&mut buf)
        .expect("write");
        assert_eq!(buf[0], 0x82);
        assert!(buf[1..4].iter().all(|b| *b == 0), "the first reserved run");
        assert_eq!(&buf[4..8], &0xE619_D30Du32.to_le_bytes());
        assert!(
            buf[8..20].iter().all(|b| *b == 0),
            "the second reserved run"
        );
        assert_eq!(&buf[20..24], &3u32.to_le_bytes());
        assert_eq!(&buf[24..32], &5836u64.to_le_bytes());
    }

    #[test]
    fn an_entry_of_another_type_is_refused_rather_than_decoded() {
        // Offset 20 is a first cluster on three of these types and part of a name on a
        // fourth, so recovering one type's fields out of another's bytes produces a plausible
        // structure pointing somewhere the volume keeps something else.
        let mut buf = [0u8; DIR_ENTRY_SIZE];
        UpcaseTableEntry {
            table_checksum: 0xE619_D30D,
            first_cluster: 3,
            data_length: 5836,
        }
        .write_to(&mut buf)
        .expect("write");

        assert!(matches!(
            AllocationBitmapEntry::read_from(&buf),
            Err(ParseError::BadMagic {
                found: 0x82,
                expected: 0x81,
                ..
            })
        ));
        assert!(matches!(
            VolumeLabelEntry::read_from(&buf),
            Err(ParseError::BadMagic { .. })
        ));
        assert!(UpcaseTableEntry::read_from(&buf).is_ok());

        // And an entry marked not in use is not the entry with its bit cleared: the type byte
        // is the whole of the check, so a deleted label does not read back as a label.
        buf[0] = EntryType::UPCASE_TABLE.cleared().0;
        assert!(matches!(
            UpcaseTableEntry::read_from(&buf),
            Err(ParseError::BadMagic { .. })
        ));
    }

    #[test]
    fn a_buffer_too_short_for_an_entry_is_refused_in_both_directions() {
        let mut short = [0u8; DIR_ENTRY_SIZE - 1];
        assert!(matches!(
            VolumeLabelEntry::UNNAMED.write_to(&mut short),
            Err(ParseError::TooShort { .. })
        ));
        assert!(matches!(
            AllocationBitmapEntry::read_from(&short),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn a_file_set_round_trips_through_all_three_of_its_entry_kinds() {
        let file = FileEntry {
            secondary_count: 2,
            set_checksum: 0xBEEF,
            attributes: FileAttributes::ARCHIVE,
            create: 0x4A6E_4B5A,
            modify: 0x4A6E_4B5B,
            access: 0x4A6E_4B5C,
            create_tenth: 100,
            modify_tenth: 37,
            create_utc_offset: 0x80,
            modify_utc_offset: 0x80,
            access_utc_offset: 0x80,
        };
        let stream = StreamExtensionEntry {
            flags: SECONDARY_ALLOCATION_POSSIBLE | SECONDARY_NO_FAT_CHAIN,
            name_length: 9,
            name_hash: 0x1234,
            valid_data_length: 5_000,
            first_cluster: 42,
            data_length: 5_000,
        };
        let name = FileNameEntry::new(&"README.TXT".encode_utf16().collect::<Vec<_>>()[..9]);

        let mut buf = [0u8; DIR_ENTRY_SIZE];
        file.write_to(&mut buf).expect("write");
        assert_eq!(FileEntry::read_from(&buf).expect("read"), file);
        stream.write_to(&mut buf).expect("write");
        assert_eq!(StreamExtensionEntry::read_from(&buf).expect("read"), stream);
        name.write_to(&mut buf).expect("write");
        assert_eq!(FileNameEntry::read_from(&buf).expect("read"), name);
    }

    #[test]
    fn every_field_of_a_file_set_lands_where_the_format_puts_it() {
        // Raw bytes at literal offsets, for the reason the format-time entries are asserted
        // that way: reading a field back through the accessor that wrote it says the two
        // agree and says nothing about where on disk the field is.
        let mut buf = [0xFFu8; DIR_ENTRY_SIZE];
        FileEntry {
            secondary_count: 3,
            set_checksum: 0xA1B2,
            attributes: FileAttributes::DIRECTORY,
            create: 0x0102_0304,
            modify: 0x0506_0708,
            access: 0x090A_0B0C,
            create_tenth: 199,
            modify_tenth: 1,
            create_utc_offset: 0x80,
            modify_utc_offset: 0x84,
            access_utc_offset: 0x00,
        }
        .write_to(&mut buf)
        .expect("write");
        assert_eq!(buf[0], 0x85);
        assert_eq!(buf[1], 3);
        assert_eq!(&buf[2..4], &0xA1B2u16.to_le_bytes());
        assert_eq!(&buf[4..6], &0x0010u16.to_le_bytes());
        assert_eq!(&buf[6..8], &[0, 0], "the first reserved run");
        assert_eq!(&buf[8..12], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&buf[12..16], &0x0506_0708u32.to_le_bytes());
        assert_eq!(&buf[16..20], &0x090A_0B0Cu32.to_le_bytes());
        assert_eq!(&buf[20..25], &[199, 1, 0x80, 0x84, 0x00]);
        assert!(buf[25..].iter().all(|b| *b == 0), "the reserved tail");

        let mut buf = [0xFFu8; DIR_ENTRY_SIZE];
        StreamExtensionEntry {
            flags: SECONDARY_ALLOCATION_POSSIBLE,
            name_length: 11,
            name_hash: 0xC3D4,
            valid_data_length: 0x1122_3344_5566_7788,
            first_cluster: 0x0000_BEEF,
            data_length: 0x99AA_BBCC_DDEE_FF00,
        }
        .write_to(&mut buf)
        .expect("write");
        assert_eq!(buf[0], 0xC0);
        assert_eq!(buf[1], 0x01);
        assert_eq!(
            buf[2], 0,
            "the reserved byte between the flags and the length"
        );
        assert_eq!(buf[3], 11);
        assert_eq!(&buf[4..6], &0xC3D4u16.to_le_bytes());
        assert_eq!(&buf[6..8], &[0, 0]);
        assert_eq!(&buf[8..16], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&buf[16..20], &[0, 0, 0, 0], "the third reserved run");
        assert_eq!(&buf[20..24], &0x0000_BEEFu32.to_le_bytes());
        assert_eq!(&buf[24..32], &0x99AA_BBCC_DDEE_FF00u64.to_le_bytes());

        let mut buf = [0xFFu8; DIR_ENTRY_SIZE];
        FileNameEntry::new(&[0x0041, 0x00E9])
            .write_to(&mut buf)
            .expect("write");
        assert_eq!(buf[0], 0xC1);
        assert_eq!(buf[1], 0, "a name addresses no clusters");
        assert_eq!(&buf[2..6], &[0x41, 0x00, 0xE9, 0x00]);
        assert!(
            buf[6..].iter().all(|b| *b == 0),
            "a short name is padded with zeroes, which the length field makes unread"
        );
    }

    #[test]
    fn a_name_is_carried_fifteen_units_at_a_time_and_the_longest_needs_seventeen_entries() {
        // The two constants that decide how many slots a set occupies, and therefore how much
        // room a directory needs. Getting either wrong sizes a directory too small, and what
        // lands on the overflow is whatever was placed after it.
        assert_eq!(NAME_UNITS_PER_ENTRY, 15);
        assert_eq!(MAX_NAME_UNITS, 255);
        assert_eq!(MAX_NAME_ENTRIES, 17);
        assert_eq!(
            MAX_NAME_ENTRIES * NAME_UNITS_PER_ENTRY,
            255,
            "the longest name fills its last entry exactly"
        );
        // A stream extension and the name entries: the largest secondary count a real set has,
        // well inside what the field could record.
        assert!(1 + MAX_NAME_ENTRIES < MAX_SECONDARY_COUNT as usize);
    }

    #[test]
    fn the_attribute_word_is_the_dos_bits_exfat_kept_and_not_fats_label_bit() {
        assert_eq!(FileAttributes::READ_ONLY.bits(), 0x0001);
        assert_eq!(FileAttributes::HIDDEN.bits(), 0x0002);
        assert_eq!(FileAttributes::SYSTEM.bits(), 0x0004);
        assert_eq!(FileAttributes::DIRECTORY.bits(), 0x0010);
        assert_eq!(FileAttributes::ARCHIVE.bits(), 0x0020);

        // Bit 3 is FAT's volume-label attribute and is reserved here: exFAT gives the label an
        // entry type of its own, so no entry is a label and a file at once.
        assert_eq!(FileAttributes::DEFINED.bits() & 0x0008, 0);
        for flag in [
            FileAttributes::READ_ONLY,
            FileAttributes::HIDDEN,
            FileAttributes::SYSTEM,
            FileAttributes::DIRECTORY,
            FileAttributes::ARCHIVE,
        ] {
            assert!(FileAttributes::DEFINED.contains(flag), "{flag:?}");
        }
    }

    #[test]
    fn a_secondary_entrys_flags_say_whether_the_allocation_table_holds_its_chain() {
        let contiguous = StreamExtensionEntry {
            flags: SECONDARY_ALLOCATION_POSSIBLE | SECONDARY_NO_FAT_CHAIN,
            name_length: 1,
            name_hash: 0,
            valid_data_length: 0,
            first_cluster: 2,
            data_length: 0,
        };
        assert!(contiguous.no_fat_chain());
        assert!(
            !StreamExtensionEntry {
                flags: SECONDARY_ALLOCATION_POSSIBLE,
                ..contiguous
            }
            .no_fat_chain()
        );
    }

    #[test]
    fn a_volume_with_no_name_still_carries_a_label_entry() {
        // The entry is written, not omitted. It is the first slot of the root directory on
        // every volume any implementation formats, and a driver reads a count of zero as "no
        // name" rather than reading the absence of an entry.
        let mut buf = [0xFFu8; DIR_ENTRY_SIZE];
        VolumeLabelEntry::UNNAMED.write_to(&mut buf).expect("write");
        assert_eq!(buf[0], 0x83);
        assert!(buf[1..].iter().all(|b| *b == 0));
    }
}
