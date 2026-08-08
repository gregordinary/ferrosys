//! The DOS date and time a directory entry records, and the conversion between one and the
//! crate's own [`Timestamp`].
//!
//! A FAT directory entry stores an instant in two sixteen-bit words and one byte, counting
//! years from 1980 and seconds in units of two. The conversion is therefore lossy in three
//! separate ways, and each one is a property of the format rather than a choice:
//!
//! - **Range.** Nothing before [`TIME_SECS_MIN`] or after [`TIME_SECS_MAX`] fits, because the
//!   date word holds seven bits of year.
//! - **Granularity.** The time word's seconds field counts *two-second* units.
//!   [`DosTimestamp::tenth`] recovers the rest to a hundredth of a second, and only the
//!   creation time has such a field — a write time is granular to two seconds and an access
//!   *date* has no time word at all.
//! - **Zone.** The words carry no zone and no offset. Every conversion here is UTC, so an
//!   image's bytes do not depend on where the machine that wrote it thinks it is.
//!
//! An instant outside the range is reported rather than wrapped: a year that overflowed
//! seven bits would land in the 1980s and look entirely plausible.

use crate::time::Timestamp;

/// The first instant a FAT directory entry represents: 1980-01-01T00:00:00Z, in seconds
/// since the Unix epoch. The date word counts years from 1980, so there is nothing earlier
/// to encode.
pub const TIME_SECS_MIN: i64 = 315_532_800;

/// The last instant a FAT directory entry represents: 2107-12-31T23:59:58Z, in seconds
/// since the Unix epoch. The year field is seven bits wide, reaching 1980 + 127, and the
/// seconds field counts two-second units, so the final odd second is not representable
/// either.
pub const TIME_SECS_MAX: i64 = 4_354_819_198;

/// Seconds in one unit of the time word's seconds field.
const SECONDS_PER_UNIT: i64 = 2;

/// Days in the 400-year Gregorian cycle, which is the period over which the leap rule
/// repeats.
const DAYS_PER_ERA: i64 = 146_097;

/// Days from 1970-01-01 to 0000-03-01, the shifted epoch the civil-date conversion works
/// against. Starting the year in March puts the leap day at the end of it, which is what
/// removes every special case from the arithmetic below.
const DAYS_EPOCH_TO_SHIFTED: i64 = 719_468;

/// An instant in the form a directory entry carries it.
///
/// The three fields are exactly the three a [`DirEntry`](super::DirEntry) stores, so
/// converting once and copying the parts out is what keeps a creation time, a write time,
/// and an access date consistent with each other.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DosTimestamp {
    /// The date word: years since 1980 in bits 9..16, month 1 to 12 in bits 5..9, and day
    /// 1 to 31 in bits 0..5.
    pub date: u16,
    /// The time word: hours in bits 11..16, minutes in bits 5..11, and *two-second* units
    /// in bits 0..5.
    pub time: u16,
    /// Hundredths of a second past what [`time`](Self::time) holds, 0 to 199 — the odd
    /// second the two-second unit dropped, plus the fraction within it. Only a creation
    /// time has a field for this.
    pub tenth: u8,
}

/// A calendar date and time of day, UTC.
struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

/// The civil date and time of day at `secs` seconds past the Unix epoch, UTC.
///
/// The days-to-civil half shifts the year to begin in March so that the leap day falls at
/// the end of it, which makes the month-length sequence repeat without a table and the
/// 400-year cycle divide exactly. It is exact for every `i64` a caller can reach here,
/// because the range is checked before it is called.
fn civil_from_secs(secs: i64) -> Civil {
    // Days and seconds-within-day, with the remainder taken toward negative infinity so a
    // time before the epoch lands on the previous day rather than on a negative hour.
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);

    let shifted = days + DAYS_EPOCH_TO_SHIFTED;
    let era = shifted.div_euclid(DAYS_PER_ERA);
    let day_of_era = shifted.rem_euclid(DAYS_PER_ERA);
    // The year within the era, undoing the three leap-day exceptions the Gregorian rule
    // makes across 400 years.
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // The month in the shifted year, where 0 is March. The constants are the closed form of
    // the 31/30/31/30/31 month-length sequence that repeats once the leap day is at the end.
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = (if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    }) as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    Civil {
        year,
        month,
        day,
        hour: (rem / 3600) as u32,
        minute: (rem / 60 % 60) as u32,
        second: (rem % 60) as u32,
    }
}

/// Days from the Unix epoch to `year`-`month`-`day`, the inverse of the shift
/// [`civil_from_secs`] applies.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * i64::from(shifted_month) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = 365 * year_of_era + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * DAYS_PER_ERA + day_of_era - DAYS_EPOCH_TO_SHIFTED
}

/// The date, time, and hundredths a directory entry records `time` as, or `None` where the
/// instant is outside the range the fields reach.
///
/// The seconds field counts two-second units and rounds **down**, so the dropped odd second
/// reappears in [`DosTimestamp::tenth`] rather than moving the instant. An entry that has no
/// hundredths field therefore records a time up to two seconds early, which is the format's
/// granularity and not a rounding choice.
#[must_use]
pub fn encode_time(time: Timestamp) -> Option<DosTimestamp> {
    if time.secs < TIME_SECS_MIN || time.secs > TIME_SECS_MAX {
        return None;
    }
    let c = civil_from_secs(time.secs);
    // The range check above bounds the year to 1980..=2107, so every field below fits the
    // bits the format gives it.
    let year = (c.year - 1980) as u16;
    let date = (year << 9) | ((c.month as u16) << 5) | c.day as u16;
    let time_word = ((c.hour as u16) << 11) | ((c.minute as u16) << 5) | (c.second / 2) as u16;
    // What the two-second unit dropped, to a hundredth: the odd second, plus the fraction
    // within it. A decoded timestamp may carry a fraction of a second or more, which is
    // clamped rather than allowed to overflow the field's 0..200 range.
    let hundredths = (c.second % 2) * 100 + (time.nanos / 10_000_000).min(99);
    Some(DosTimestamp {
        date,
        time: time_word,
        tenth: hundredths.min(199) as u8,
    })
}

/// The instant a directory entry's date, time, and hundredths describe, UTC.
///
/// Every field is taken as it is found. An image may hold a date no calendar has — day 31 of
/// February, month 0, day 0 — and this reports the instant that arithmetic reaches rather
/// than refusing, because a reader's job is to say what the image holds and a scan is what
/// judges it. An entry with no time word passes zero, which is midnight.
#[must_use]
pub fn decode_time(stamp: DosTimestamp) -> Timestamp {
    let year = 1980 + i64::from(stamp.date >> 9);
    let month = u32::from((stamp.date >> 5) & 0xF);
    let day = u32::from(stamp.date & 0x1F);
    let hour = i64::from(stamp.time >> 11);
    let minute = i64::from((stamp.time >> 5) & 0x3F);
    let second = i64::from(stamp.time & 0x1F) * SECONDS_PER_UNIT;

    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second + i64::from(stamp.tenth) / 100;
    Timestamp {
        secs,
        nanos: (u32::from(stamp.tenth) % 100) * 10_000_000,
    }
}

/// Whether `time` is an instant a FAT directory entry represents.
///
/// The final odd second of 2107 is excluded along with everything past it: the seconds field
/// counts two-second units, so there is no encoding for it.
#[must_use]
pub const fn time_is_representable(time: Timestamp) -> bool {
    time.secs >= TIME_SECS_MIN && time.secs <= TIME_SECS_MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One instant, in both forms: the seconds it is, and the calendar it reads as.
    ///
    /// The calendar side is written as the fields a person reads off a clock rather than as
    /// the packed words, and [`packed`] does the packing. A table of bit-shifted literals
    /// would be this module's own arithmetic restated, which checks nothing.
    struct Known {
        what: &'static str,
        secs: i64,
        nanos: u32,
        /// Year, month, day, hour, minute, second — UTC.
        calendar: (u16, u16, u16, u16, u16, u16),
        tenth: u8,
    }

    /// The date and time words a calendar reading packs into, by the field positions the
    /// format states rather than by [`encode_time`]'s arithmetic.
    fn packed(calendar: (u16, u16, u16, u16, u16, u16)) -> (u16, u16) {
        let (year, month, day, hour, minute, second) = calendar;
        let date = ((year - 1980) << 9) | (month << 5) | day;
        let time = (hour << 11) | (minute << 5) | (second / 2);
        (date, time)
    }

    const KNOWN: &[Known] = &[
        Known {
            what: "the first instant the format represents",
            secs: TIME_SECS_MIN,
            nanos: 0,
            calendar: (1980, 1, 1, 0, 0, 0),
            tenth: 0,
        },
        Known {
            what: "the last instant the format represents",
            secs: TIME_SECS_MAX,
            nanos: 0,
            calendar: (2107, 12, 31, 23, 59, 58),
            tenth: 0,
        },
        Known {
            what: "the baseline formatter's invariant instant",
            // The constant `mkfs.fat --invariant` stamps with. Its odd second is what the
            // hundredths field carries, and the seconds field rounds down.
            secs: 1_426_325_213,
            nanos: 0,
            calendar: (2015, 3, 14, 9, 26, 53),
            tenth: 100,
        },
        Known {
            what: "a leap day",
            // The century rule makes 2000 a leap year where 1900 and 2100 are not, so this is
            // the date the arithmetic is most likely to miss.
            secs: 951_827_696,
            nanos: 0,
            calendar: (2000, 2, 29, 12, 34, 56),
            tenth: 0,
        },
        Known {
            what: "a fraction inside an even second",
            secs: 1_426_325_212,
            nanos: 370_000_000,
            calendar: (2015, 3, 14, 9, 26, 52),
            tenth: 37,
        },
    ];

    #[test]
    fn every_known_instant_encodes_to_the_words_a_calendar_gives() {
        for k in KNOWN {
            let (date, time) = packed(k.calendar);
            let encoded = encode_time(Timestamp {
                secs: k.secs,
                nanos: k.nanos,
            })
            .unwrap_or_else(|| panic!("{}: refused an instant in range", k.what));
            assert_eq!(encoded.date, date, "{}: date word", k.what);
            assert_eq!(encoded.time, time, "{}: time word", k.what);
            assert_eq!(encoded.tenth, k.tenth, "{}: hundredths", k.what);
        }
    }

    #[test]
    fn decoding_recovers_the_instant_the_fields_can_hold() {
        for k in KNOWN {
            let (date, time) = packed(k.calendar);
            let decoded = decode_time(DosTimestamp {
                date,
                time,
                tenth: k.tenth,
            });
            // The hundredths field recovers the instant to a hundredth of a second, so what
            // comes back is the original truncated to that granularity and nothing coarser.
            let expected_nanos = (k.nanos / 10_000_000) * 10_000_000;
            assert_eq!(decoded.secs, k.secs, "{}: seconds", k.what);
            assert_eq!(decoded.nanos, expected_nanos, "{}: fraction", k.what);
        }
    }

    #[test]
    fn an_instant_outside_the_range_is_refused_rather_than_wrapped() {
        // A year that overflowed seven bits would land back in the 1980s and look entirely
        // plausible, which is exactly why this is not allowed to wrap.
        assert!(encode_time(Timestamp::from_secs(TIME_SECS_MIN - 1)).is_none());
        assert!(encode_time(Timestamp::from_secs(TIME_SECS_MAX + 1)).is_none());
        assert!(encode_time(Timestamp::from_secs(0)).is_none());
        assert!(encode_time(Timestamp::from_secs(-1)).is_none());
        assert!(encode_time(Timestamp::from_secs(TIME_SECS_MIN)).is_some());
        assert!(encode_time(Timestamp::from_secs(TIME_SECS_MAX)).is_some());
        assert!(time_is_representable(Timestamp::from_secs(TIME_SECS_MIN)));
        assert!(!time_is_representable(Timestamp::from_secs(
            TIME_SECS_MIN - 1
        )));
    }

    #[test]
    fn the_round_trip_holds_across_the_whole_representable_range() {
        // Every two-second unit of every day would be 2 billion cases; a stride that is
        // coprime with a day, a year, and the 400-year cycle walks every hour of the day and
        // every day of the year instead, at a few hundred thousand.
        const STRIDE: i64 = 100_003;
        let mut secs = TIME_SECS_MIN;
        let mut checked = 0u32;
        while secs <= TIME_SECS_MAX {
            let encoded = encode_time(Timestamp::from_secs(secs)).expect("in range");
            let decoded = decode_time(encoded);
            assert_eq!(
                decoded.secs, secs,
                "the instant did not survive the round trip"
            );
            checked += 1;
            secs += STRIDE;
        }
        assert!(
            checked > 40_000,
            "the sweep only checked {checked} instants"
        );
    }

    #[test]
    fn the_civil_conversion_agrees_with_itself_in_both_directions() {
        // The two halves are separate transcriptions of the same shift, so a defect in one
        // that the round trip above cannot see — a month boundary the encoder and the decoder
        // both move — is caught by walking days directly.
        for day in -25_000..25_000i64 {
            let c = civil_from_secs(day * 86_400);
            assert_eq!(
                days_from_civil(c.year, c.month, c.day),
                day,
                "day {day} converts to {}-{}-{} and back to something else",
                c.year,
                c.month,
                c.day
            );
            assert!((1..=12).contains(&c.month), "day {day}: month {}", c.month);
            assert!((1..=31).contains(&c.day), "day {day}: day {}", c.day);
        }
    }

    #[test]
    fn the_conversion_is_utc_and_carries_no_zone() {
        // The epoch itself is outside the range, so the anchor is the first instant that is
        // in it: 1980-01-01T00:00:00Z is midnight, and midnight in no other zone.
        let midnight = encode_time(Timestamp::from_secs(TIME_SECS_MIN)).expect("in range");
        assert_eq!(midnight.time, 0);
        assert_eq!(midnight.date & 0x1F, 1, "the day must be the first");
        assert_eq!((midnight.date >> 5) & 0xF, 1, "the month must be January");
    }

    #[test]
    fn a_date_no_calendar_has_is_reported_rather_than_refused() {
        // A reader says what the image holds; a scan is what judges it. Day 31 of February
        // decodes to the instant the arithmetic reaches, which is in March.
        let odd = decode_time(DosTimestamp {
            date: (35 << 9) | (2 << 5) | 31,
            time: 0,
            tenth: 0,
        });
        assert_eq!(
            odd.secs,
            decode_time(DosTimestamp {
                date: (35 << 9) | (3 << 5) | 3,
                time: 0,
                tenth: 0,
            })
            .secs
        );
    }
}
