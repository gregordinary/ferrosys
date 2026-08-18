//! How an exFAT directory entry carries an instant: one packed word, a field of hundredths,
//! and a zone offset.
//!
//! The packing itself is not this format's. exFAT stores the same DOS date and time words FAT
//! stores, so the arithmetic between an instant and those words lives once in
//! [`DosTimestamp`], and what is here is the part exFAT decides:
//! that the two words are one 32-bit field, and that a zone offset sits beside them.
//!
//! # The zone byte is what makes an exFAT time unambiguous
//!
//! FAT records a local time and no way of knowing which locality, so the same entry read on
//! two machines names two instants. exFAT records an offset with each of its three times, and
//! a volume this crate writes records UTC — the times it is given are instants on the Unix
//! timeline, and [`UTC_OFFSET`] is what says so on disk rather than leaving a reader to guess.
//!
//! An offset byte with its high bit clear means no offset was recorded, which is what a
//! reader meets on a volume written by an implementation that did not bother. That is a
//! recovered field like any other and is reported rather than corrected.

use crate::time::DosTimestamp;

/// Bit 7 of an offset byte: the seven bits below it are an offset rather than padding.
pub const UTC_OFFSET_VALID: u8 = 0x80;

/// The offset byte a volume recording UTC carries: an offset is recorded, and it is zero.
///
/// Writing this rather than a zero byte is the difference between "this time is UTC" and
/// "nobody said what this time is", and only the first of the two is true of a volume built
/// from instants.
pub const UTC_OFFSET: u8 = UTC_OFFSET_VALID;

/// Minutes in one unit of the offset field, which counts quarter hours.
const MINUTES_PER_UNIT: i32 = 15;

/// The seven bits of an offset byte below [`UTC_OFFSET_VALID`].
const OFFSET_UNITS: u8 = 0x7F;

/// The 32-bit field an exFAT entry packs a date and time into: the date word above the time
/// word.
#[must_use]
pub const fn pack_timestamp(stamp: DosTimestamp) -> u32 {
    ((stamp.date as u32) << 16) | stamp.time as u32
}

/// The date and time words a 32-bit entry field holds, with `tenth` hundredths beside them.
///
/// The hundredths come from a separate byte of the entry, and an entry that has none — an
/// access time — passes zero, which is the whole of what "this field is granular to two
/// seconds" means.
#[must_use]
pub const fn unpack_timestamp(field: u32, tenth: u8) -> DosTimestamp {
    DosTimestamp {
        date: (field >> 16) as u16,
        time: field as u16,
        tenth,
    }
}

/// The offset from UTC an offset byte records, in minutes, or `None` where the byte records
/// no offset.
///
/// The seven bits below [`UTC_OFFSET_VALID`] are a two's-complement count of quarter hours,
/// so the range is −16:00 to +15:45 and a negative offset is one whose bit 6 is set. Every
/// zone in use falls inside that; the encoding reaches further than the world does.
#[must_use]
pub const fn utc_offset_minutes(byte: u8) -> Option<i32> {
    if byte & UTC_OFFSET_VALID == 0 {
        return None;
    }
    // Sign-extend seven bits into eight, then into the width the arithmetic is done in: bit 6
    // is the sign, so a byte with it set names an offset west of Greenwich.
    let units = ((byte & OFFSET_UNITS) << 1) as i8 >> 1;
    Some(units as i32 * MINUTES_PER_UNIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Timestamp;

    #[test]
    fn the_two_words_pack_into_one_field_with_the_date_above_the_time() {
        // Asserted against the words rather than against a round trip, since which half of
        // the field each word occupies is exactly what a round trip cannot tell apart.
        let stamp = DosTimestamp::encode(Timestamp::from_secs(1_426_325_212)).expect("in range");
        let field = pack_timestamp(stamp);
        assert_eq!((field >> 16) as u16, stamp.date);
        assert_eq!(field as u16, stamp.time);
        assert_ne!(stamp.date, stamp.time, "the halves must be distinguishable");

        // And back, with the hundredths the entry keeps in a byte of its own.
        assert_eq!(unpack_timestamp(field, stamp.tenth), stamp);
        assert_eq!(
            unpack_timestamp(field, 0).tenth,
            0,
            "a field with no hundredths byte is granular to two seconds"
        );
    }

    #[test]
    fn the_offset_byte_says_utc_by_recording_a_zero_offset_rather_than_by_being_zero() {
        // The distinction this constant exists for: one of these says the time is UTC and the
        // other says nobody recorded what it is.
        assert_eq!(utc_offset_minutes(UTC_OFFSET), Some(0));
        assert_eq!(utc_offset_minutes(0), None);
    }

    #[test]
    fn an_offset_is_a_signed_count_of_quarter_hours() {
        // Read off the zones rather than off the encoding, so a sign extension that dropped a
        // bit shows up as a place rather than as a number.
        for (byte, minutes, what) in [
            (UTC_OFFSET_VALID, 0, "UTC"),
            (UTC_OFFSET_VALID | 0x04, 60, "one hour east"),
            (UTC_OFFSET_VALID | 0x7C, -60, "one hour west"),
            (UTC_OFFSET_VALID | 0x16, 330, "India, at half past five"),
            (
                UTC_OFFSET_VALID | 0x2F,
                705,
                "Chatham Island, at a quarter to twelve",
            ),
            (
                UTC_OFFSET_VALID | 0x40,
                -960,
                "the furthest west the field reaches",
            ),
            (
                UTC_OFFSET_VALID | 0x3F,
                945,
                "the furthest east the field reaches",
            ),
        ] {
            assert_eq!(utc_offset_minutes(byte), Some(minutes), "{what}");
        }

        // Bit 7 decides whether the rest is read at all, so a byte that would be a large
        // offset is not one where the bit is clear.
        assert_eq!(utc_offset_minutes(0x7F), None);
    }
}
