//! The four checksums an exFAT volume carries, over one primitive at two widths.
//!
//! Every one of them rotates a running value right by one bit and adds the next byte,
//! wrapping. What separates them is the width of the accumulator, what is summed, and which
//! bytes are stepped over — so they are four functions named for what each covers rather
//! than one function taking three parameters, and each is pinned against a foreign
//! implementation on its own.
//!
//! This module is pure: it reads bytes and returns a number.

/// The offsets of the Main Boot Sector that [`boot_checksum`] steps over: the two bytes of
/// `VolumeFlags` at 106, and the one byte of `PercentInUse` at 112.
///
/// Those are the fields a mounted driver rewrites in place — marking the volume dirty,
/// recording how full it is — and the exclusion is what lets it do so without recomputing a
/// checksum over the whole boot region.
///
/// They are stepped over rather than summed as zero, and that distinction is the whole of
/// it: the accumulator rotates once per byte consumed, so a skipped byte and a summed zero
/// byte give different answers on every volume, including the ones where all three bytes
/// are zero — which is every volume a format produces.
pub const BOOT_CHECKSUM_SKIPS: [usize; 3] = [106, 107, 112];

/// The offsets of a directory entry set that [`entry_set_checksum`] steps over: the two
/// bytes of the `SetChecksum` field itself, at offset 2 of the set's first entry.
pub const SET_CHECKSUM_SKIPS: [usize; 2] = [2, 3];

/// The 32-bit checksum over a boot region's first eleven sectors.
///
/// `region` is sectors 0 through 10 of the region in byte order — the Main Boot Sector, the
/// eight extended boot sectors, the OEM parameters sector, and the reserved sector — at
/// whatever the volume's sector size is. Sector 11 then holds the value returned here,
/// repeated for the whole sector.
///
/// The three offsets of [`BOOT_CHECKSUM_SKIPS`] are stepped over. They belong to sector 0,
/// so the skip applies once per region rather than once per sector, which is what makes
/// `region` one slice rather than eleven.
///
/// ```
/// # use ferrosys::exfat::ondisk::boot_checksum;
/// // A region of nothing but zeroes sums to zero, whatever its sector size.
/// assert_eq!(boot_checksum(&[0u8; 11 * 512]), 0);
/// // And one byte of it moves the answer, because every later byte rotates over it.
/// let mut region = [0u8; 11 * 512];
/// region[0] = 1;
/// assert_ne!(boot_checksum(&region), 0);
/// ```
#[must_use]
pub fn boot_checksum(region: &[u8]) -> u32 {
    let mut sum = 0u32;
    for (at, byte) in region.iter().enumerate() {
        if BOOT_CHECKSUM_SKIPS.contains(&at) {
            continue;
        }
        sum = sum.rotate_right(1).wrapping_add(u32::from(*byte));
    }
    sum
}

/// The 32-bit checksum over the bytes of an up-case table, with nothing stepped over.
///
/// It is what the up-case table's own directory entry advertises, and the value that says a
/// volume's case folding is the mapping it claims to be. The recommended table's is
/// [`RECOMMENDED_UPCASE_CHECKSUM`](super::RECOMMENDED_UPCASE_CHECKSUM).
///
/// The primitive is [`boot_checksum`]'s; only the skip list differs, and here it is empty.
///
/// ```
/// # use ferrosys::exfat::ondisk::upcase_checksum;
/// assert_eq!(upcase_checksum(&[]), 0);
/// // The accumulator rotates *before* each byte is added, so one byte is itself and a
/// // trailing zero is what carries it into the top bit.
/// assert_eq!(upcase_checksum(&[0x01]), 1);
/// assert_eq!(upcase_checksum(&[0x01, 0x00]), 0x8000_0000);
/// ```
#[must_use]
pub fn upcase_checksum(table: &[u8]) -> u32 {
    let mut sum = 0u32;
    for byte in table {
        sum = sum.rotate_right(1).wrapping_add(u32::from(*byte));
    }
    sum
}

/// The 16-bit checksum over every byte of a directory entry set.
///
/// `entries` is the whole set laid out end to end — the file entry, its stream extension,
/// and its name entries — which is `32 * (1 + SecondaryCount)` bytes. The two offsets of
/// [`SET_CHECKSUM_SKIPS`] are stepped over, being the field the answer is written into.
///
/// The checksum covering every entry of a set is what makes a partially written one
/// detectable: a set is a file's whole record, and half of one is not a file.
///
/// ```
/// # use ferrosys::exfat::ondisk::entry_set_checksum;
/// // The two bytes the checksum itself occupies are stepped over, so what is already
/// // written there cannot change the answer.
/// let mut set = [0u8; 96];
/// set[0] = 0x85;
/// let clean = entry_set_checksum(&set);
/// set[2] = 0xAB;
/// set[3] = 0xCD;
/// assert_eq!(entry_set_checksum(&set), clean);
/// ```
#[must_use]
pub fn entry_set_checksum(entries: &[u8]) -> u16 {
    let mut sum = 0u16;
    for (at, byte) in entries.iter().enumerate() {
        if SET_CHECKSUM_SKIPS.contains(&at) {
            continue;
        }
        sum = sum.rotate_right(1).wrapping_add(u16::from(*byte));
    }
    sum
}

/// The 16-bit hash of an up-cased file name, over its UTF-16 code units as little-endian
/// bytes.
///
/// `upcased` is the name after folding through the volume's up-case table, not the name as
/// it is stored: the stored name keeps its case and the hash does not, which is what makes
/// a case-insensitive lookup a comparison of two numbers before it is a comparison of two
/// strings.
///
/// The hash is a lookup accelerator, so a wrong one costs no data — it makes a file
/// invisible to a driver that trusts it, which is worse than corruption for being silent.
///
/// ```
/// # use ferrosys::exfat::ondisk::name_hash;
/// // Folding is the caller's, so two cases of one name hash differently here and the same
/// // once each has been through the volume's table.
/// let upper: Vec<u16> = "README".encode_utf16().collect();
/// let lower: Vec<u16> = "readme".encode_utf16().collect();
/// assert_ne!(name_hash(&upper), name_hash(&lower));
/// ```
#[must_use]
pub fn name_hash(upcased: &[u16]) -> u16 {
    let mut hash = 0u16;
    for unit in upcased {
        for byte in unit.to_le_bytes() {
            hash = hash.rotate_right(1).wrapping_add(u16::from(byte));
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::super::RECOMMENDED_UPCASE_BYTES;
    use super::*;

    /// The specification's own arithmetic, written out at each width, as the vector every
    /// function here is held to.
    ///
    /// A rotate and a shift-plus-mask are the same operation, and that is exactly why both
    /// spellings are here: the implementations use the rotate, and asserting them against a
    /// second reading of the same rotate would be asserting that a function equals itself.
    /// These are the form the format states, transcribed once.
    fn spelled_out_32(bytes: &[u8], skip: &[usize]) -> u32 {
        let mut sum = 0u32;
        for (at, byte) in bytes.iter().enumerate() {
            if skip.contains(&at) {
                continue;
            }
            sum = ((sum & 1) << 31)
                .wrapping_add(sum >> 1)
                .wrapping_add(u32::from(*byte));
        }
        sum
    }

    fn spelled_out_16(bytes: &[u8], skip: &[usize]) -> u16 {
        let mut sum = 0u16;
        for (at, byte) in bytes.iter().enumerate() {
            if skip.contains(&at) {
                continue;
            }
            sum = ((sum & 1) << 15)
                .wrapping_add(sum >> 1)
                .wrapping_add(u16::from(*byte));
        }
        sum
    }

    /// Bytes that are not all alike and do not repeat, so a checksum over them depends on
    /// the order they arrive in.
    fn varied(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect()
    }

    #[test]
    fn each_checksum_is_the_arithmetic_the_format_states() {
        let region = varied(11 * 512);
        assert_eq!(
            boot_checksum(&region),
            spelled_out_32(&region, &BOOT_CHECKSUM_SKIPS)
        );

        let table = varied(RECOMMENDED_UPCASE_BYTES as usize);
        assert_eq!(upcase_checksum(&table), spelled_out_32(&table, &[]));

        let set = varied(96);
        assert_eq!(
            entry_set_checksum(&set),
            spelled_out_16(&set, &SET_CHECKSUM_SKIPS)
        );

        let name: Vec<u16> = "FERROSYS.TXT".encode_utf16().collect();
        let bytes: Vec<u8> = name.iter().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(name_hash(&name), spelled_out_16(&bytes, &[]));
    }

    #[test]
    fn the_boot_checksum_steps_over_its_three_offsets_rather_than_summing_them_as_zero() {
        // The one part of this arithmetic that is easy to get wrong and impossible to see:
        // every one of the three excluded bytes is zero on a freshly formatted volume, so
        // an implementation that summed them as the zeroes they are would look right and be
        // wrong on every volume ever written. The accumulator rotates once per byte
        // consumed, which is what makes the two different operations.
        //
        // The region has to hold something for that to show. Over a buffer of nothing but
        // zeroes both readings answer zero, so a case built that way would assert exactly
        // what it set out to disprove — three fewer rotations of an accumulator that is
        // still zero is still zero.
        let mut region = varied(11 * 512);
        for at in BOOT_CHECKSUM_SKIPS {
            region[at] = 0;
        }
        assert_ne!(
            boot_checksum(&region),
            spelled_out_32(&region, &[]),
            "summing the excluded offsets as zeroes gives the same answer as stepping over \
             them, so nothing here would notice an implementation that did neither"
        );
    }

    #[test]
    fn what_a_checksum_covers_is_what_changes_it() {
        // Each function's skip list, asserted from the outside: a byte inside the covered
        // region moves the answer and a byte in the excluded one does not. A skip list that
        // was too wide would pass the arithmetic case above and fail here.
        let mut region = vec![0u8; 11 * 512];
        let clean = boot_checksum(&region);
        for at in BOOT_CHECKSUM_SKIPS {
            region[at] = 0xFF;
            assert_eq!(boot_checksum(&region), clean, "offset {at} is excluded");
            region[at] = 0;
        }
        // The volume serial, four bytes ahead of the first excluded one, is not.
        region[100] = 0xFF;
        assert_ne!(boot_checksum(&region), clean, "the serial is covered");

        let mut set = vec![0u8; 96];
        let clean = entry_set_checksum(&set);
        for at in SET_CHECKSUM_SKIPS {
            set[at] = 0xFF;
            assert_eq!(entry_set_checksum(&set), clean, "offset {at} is excluded");
            set[at] = 0;
        }
        // Every other byte of every entry in the set is covered, including the last.
        for at in [0, 1, 4, 32, 64, 95] {
            set[at] = 0xFF;
            assert_ne!(entry_set_checksum(&set), clean, "offset {at} is covered");
            set[at] = 0;
        }
    }

    #[test]
    fn a_checksum_depends_on_the_order_its_bytes_arrive_in() {
        // The rotation is the whole reason these are not sums, and a transposition is what
        // shows it: two bytes swapped leave every total the same and every answer here
        // different.
        let mut region = varied(11 * 512);
        let first = boot_checksum(&region);
        region.swap(200, 300);
        assert_ne!(boot_checksum(&region), first);

        let name: Vec<u16> = "AB".encode_utf16().collect();
        let swapped: Vec<u16> = "BA".encode_utf16().collect();
        assert_ne!(name_hash(&name), name_hash(&swapped));
    }

    #[test]
    fn a_name_hash_reads_its_units_little_endian() {
        // The name is UTF-16 on disk and the hash is over its bytes, so which byte of a code
        // unit is folded in first is part of the answer. A unit above the ASCII range is
        // what tells the two orders apart.
        let name = [0x00C9u16]; // LATIN CAPITAL LETTER E WITH ACUTE
        let mut expected = 0u16;
        for byte in [0xC9u8, 0x00] {
            expected = expected.rotate_right(1).wrapping_add(u16::from(byte));
        }
        assert_eq!(name_hash(&name), expected);
    }
}
