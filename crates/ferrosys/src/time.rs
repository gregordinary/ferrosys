//! Wall-clock time: the instant a filesystem records against a file, and the calendar that
//! reads it.
//!
//! [`Timestamp`] is a point on the Unix timeline — whole seconds and a nanosecond fraction
//! — and nothing more. It is the form a source states a time in and the form a read hands
//! one back, whichever family is underneath.
//!
//! How that instant reaches the disk is usually the family's business, and the conversion
//! lives in that family's on-disk layer: the range of instants a format represents, the width
//! of the fields it splits them across, and the granularity it rounds to are all properties of
//! the format rather than of the instant. A time this type can hold is therefore not always a
//! time a given filesystem can store, and the family that cannot store it is the one that
//! says so.
//!
// The exception is compiled only where a family that stores it is, so the paragraph naming it
// is too — a link to an item a build does not have is a hard error in exactly that build.
#![cfg_attr(
    any(feature = "fat", feature = "exfat"),
    doc = "\n # The encoding two families inherited\n\n [`DosTimestamp`] is the exception, \
and it is here for the reason a conversion normally is not: FAT and exFAT do not each define \
a date format, they carry the same one. The same two packed words, the same 1980 epoch, the \
same two-second granularity, the same companion field of hundredths. What differs is where \
each format puts those words in a directory entry and what it stores beside them, and that \
part stays in each family's own on-disk layer.\n"
)]
//! # The calendar
//!
//! What the families share is the calendar underneath those conversions: a format that
//! stores a year and a month needs the civil date an instant reads as, and anything printing
//! a time needs the same. [`Civil`] is that reading, computed arithmetically in the
//! proleptic Gregorian calendar and always UTC — so a timestamp means the same thing on
//! every machine, and no table is consulted to find out.

use core::fmt;

/// Seconds in a day.
const SECS_PER_DAY: i64 = 86_400;

/// Days in the 400-year Gregorian cycle, which is the period over which the leap rule
/// repeats exactly.
const DAYS_PER_ERA: i64 = 146_097;

/// Days from 1970-01-01 to 0000-03-01, the shifted epoch the conversions work against.
/// Starting the year in March puts the leap day at the end of it, which is what removes
/// every special case from the arithmetic.
const DAYS_EPOCH_TO_SHIFTED: i64 = 719_468;

/// An instant: seconds since the Unix epoch, plus a nanosecond fraction.
///
/// The seconds are signed, so a time before 1970 is an ordinary value rather than a special
/// case. The fraction is nanoseconds within the second and is normally below
/// [`NANOS_PER_SEC`](Self::NANOS_PER_SEC) — a timestamp *decoded* from an image need not be,
/// because the field it came out of may be wider than the second it divides, and what is
/// reported is what the image holds.
///
/// The type is exhaustive: an instant is a second and a fraction, and there is no field it
/// could grow.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Timestamp {
    /// Seconds since the Unix epoch, negative before it.
    pub secs: i64,
    /// Nanoseconds within the second, normally `0..1_000_000_000`.
    pub nanos: u32,
}

impl Timestamp {
    /// One past the largest fraction that divides a second.
    pub const NANOS_PER_SEC: u32 = 1_000_000_000;

    /// An instant at `secs` seconds past the epoch, with no sub-second part.
    #[must_use]
    pub const fn from_secs(secs: i64) -> Self {
        Self { secs, nanos: 0 }
    }

    /// The civil date and time of day this instant reads as, UTC.
    ///
    /// The fraction is not carried across: a civil reading is a calendar position, and what
    /// divides its final second is still [`nanos`](Self::nanos).
    ///
    /// ```
    /// # use ferrosys::Timestamp;
    /// let civil = Timestamp::from_secs(1_700_000_000).civil();
    /// assert_eq!((civil.year, civil.month, civil.day), (2023, 11, 14));
    /// assert_eq!((civil.hour, civil.minute, civil.second), (22, 13, 20));
    /// ```
    #[must_use]
    pub const fn civil(self) -> Civil {
        Civil::at_secs(self.secs)
    }
}

/// A civil date and time of day, UTC: what an instant reads as on a calendar.
///
/// The calendar is the proleptic Gregorian one, extended backwards without limit, so a date
/// before its adoption is the date the rule gives rather than the one any country used.
///
/// The fields are public and are taken as they are found in both directions. A [`Civil`]
/// that came from an instant is always a real date; one a caller assembled — from the fields
/// an image holds, say — need not be, and [`to_secs`](Self::to_secs) reports the instant the
/// arithmetic reaches rather than refusing. A reader's job is to say what the image holds,
/// and judging it is a scan's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Civil {
    /// The year. Negative before year 1, which the proleptic calendar numbers 0 and below.
    pub year: i64,
    /// The month, 1 to 12, for a date this crate computed.
    pub month: u32,
    /// The day of the month, 1 to 31, for a date this crate computed.
    pub day: u32,
    /// The hour, 0 to 23.
    pub hour: u32,
    /// The minute, 0 to 59.
    pub minute: u32,
    /// The second, 0 to 59.
    pub second: u32,
}

impl Civil {
    /// The civil date and time of day at `secs` seconds past the Unix epoch, UTC.
    ///
    /// The days-to-civil half shifts the year to begin in March so that the leap day falls at
    /// the end of it, which makes the month-length sequence repeat without a table and the
    /// 400-year cycle divide exactly. It is exact for every `i64`.
    ///
    /// The remainder is taken toward negative infinity, so a time before the epoch lands on
    /// the previous day rather than on a negative hour: one second before 1970 is the last
    /// second of 1969.
    #[must_use]
    pub const fn at_secs(secs: i64) -> Self {
        let days = secs.div_euclid(SECS_PER_DAY);
        let rem = secs.rem_euclid(SECS_PER_DAY);

        let shifted = days + DAYS_EPOCH_TO_SHIFTED;
        let era = shifted.div_euclid(DAYS_PER_ERA);
        let day_of_era = shifted.rem_euclid(DAYS_PER_ERA);
        // The year within the era, undoing the three leap-day exceptions the Gregorian rule
        // makes across 400 years.
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        // The month in the shifted year, where 0 is March. The constants are the closed form
        // of the 31/30/31/30/31 month-length sequence that repeats once the leap day is at
        // the end.
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
        let month = (if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        }) as u32;
        let year = year_of_era + era * 400 + (month <= 2) as i64;

        Self {
            year,
            month,
            day,
            hour: (rem / 3600) as u32,
            minute: (rem / 60 % 60) as u32,
            second: (rem % 60) as u32,
        }
    }

    /// The instant this date and time of day is, in seconds past the Unix epoch, UTC.
    ///
    /// The inverse of [`at_secs`](Self::at_secs), undoing the same shift. Every field is
    /// taken as it is found, so a date no calendar has — day 31 of February, month 0 — yields
    /// the instant the arithmetic reaches rather than an error.
    #[must_use]
    pub const fn to_secs(self) -> i64 {
        let year = self.year - (self.month <= 2) as i64;
        let era = year.div_euclid(400);
        let year_of_era = year.rem_euclid(400);
        let shifted_month = if self.month > 2 {
            self.month - 3
        } else {
            self.month + 9
        };
        let day_of_year = (153 * shifted_month as i64 + 2) / 5 + self.day as i64 - 1;
        let day_of_era = 365 * year_of_era + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * DAYS_PER_ERA + day_of_era - DAYS_EPOCH_TO_SHIFTED;
        days * SECS_PER_DAY + self.hour as i64 * 3600 + self.minute as i64 * 60 + self.second as i64
    }
}

impl fmt::Display for Civil {
    /// `YYYY-MM-DDTHH:MM:SSZ`: the ISO 8601 extended form, always UTC and always with the
    /// zone designator, so a rendering carries the zone it was computed in.
    ///
    /// The year is written to at least four digits. A year outside four digits — which no
    /// filesystem this crate reads can record — widens the field rather than being truncated
    /// into one that would name a different year.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        } = *self;
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        )
    }
}

/// Seconds in one unit of the time word's seconds field.
#[cfg(any(feature = "fat", feature = "exfat"))]
const SECONDS_PER_UNIT: u32 = 2;

/// An instant in the DOS date and time encoding: two sixteen-bit words counting years from
/// 1980 and seconds in units of two, and a companion field of hundredths.
///
/// FAT and exFAT both store this, bit for bit, because both inherited it from the same
/// ancestor rather than each choosing it. Where a directory entry puts the two words and what
/// it keeps beside them differ — a FAT entry holds them as separate fields and gives only its
/// creation time a hundredths byte, an exFAT entry packs them into one 32-bit field and adds a
/// zone offset — so each family's on-disk layer owns that part and this owns the arithmetic
/// underneath it.
///
/// The conversion is lossy in three separate ways, and each one is a property of the encoding
/// rather than a choice:
///
/// - **Range.** Nothing before [`SECS_MIN`](Self::SECS_MIN) or after
///   [`SECS_MAX`](Self::SECS_MAX) fits, because the date word holds seven bits of year.
/// - **Granularity.** The time word's seconds field counts *two-second* units.
///   [`tenth`](Self::tenth) recovers the rest to a hundredth of a second, and a field the
///   format gives no hundredths to is granular to two seconds.
/// - **Zone.** The words carry no zone. Every conversion here is UTC, so an image's bytes do
///   not depend on where the machine that wrote it thinks it is. A format that records an
///   offset beside the words records it beside them, not in them.
///
/// An instant outside the range is reported rather than wrapped: a year that overflowed seven
/// bits would land in the 1980s and look entirely plausible.
///
/// ```
/// use ferrosys::{DosTimestamp, Timestamp};
///
/// // 2015-03-14T09:26:53Z. The odd second is what the hundredths field carries, because
/// // the seconds field counts twos and rounds down.
/// let stamp = DosTimestamp::encode(Timestamp::from_secs(1_426_325_213)).expect("in range");
/// assert_eq!(stamp.tenth, 100);
/// assert_eq!(DosTimestamp::decode(stamp).secs, 1_426_325_213);
///
/// // The Unix epoch is thirty-five years too early for the date word.
/// assert!(DosTimestamp::encode(Timestamp::from_secs(0)).is_none());
/// ```
#[cfg(any(feature = "fat", feature = "exfat"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DosTimestamp {
    /// The date word: years since 1980 in bits 9..16, month 1 to 12 in bits 5..9, and day
    /// 1 to 31 in bits 0..5.
    pub date: u16,
    /// The time word: hours in bits 11..16, minutes in bits 5..11, and *two-second* units
    /// in bits 0..5.
    pub time: u16,
    /// Hundredths of a second past what [`time`](Self::time) holds, 0 to 199 — the odd
    /// second the two-second unit dropped, plus the fraction within it. A field the format
    /// gives no hundredths to leaves this zero.
    pub tenth: u8,
}

#[cfg(any(feature = "fat", feature = "exfat"))]
impl DosTimestamp {
    /// The first instant the encoding represents: 1980-01-01T00:00:00Z, in seconds since the
    /// Unix epoch. The date word counts years from 1980, so there is nothing earlier to
    /// encode.
    pub const SECS_MIN: i64 = 315_532_800;

    /// The last instant the encoding represents: 2107-12-31T23:59:58Z, in seconds since the
    /// Unix epoch. The year field is seven bits wide, reaching 1980 + 127, and the seconds
    /// field counts two-second units, so the final odd second is not representable either.
    pub const SECS_MAX: i64 = 4_354_819_198;

    /// The largest value [`tenth`](Self::tenth) holds: 199 hundredths, which is the odd
    /// second the two-second unit dropped plus the ninety-nine hundredths within it.
    ///
    /// A byte reaches 255, so the top fifty-six values are ones the field cannot mean —
    /// [`is_well_formed`](Self::is_well_formed) is where an image carrying one is judged.
    pub const MAX_TENTH: u8 = 199;

    /// The date, time, and hundredths this encoding records `time` as, or `None` where the
    /// instant is outside the range the fields reach.
    ///
    /// The seconds field counts two-second units and rounds **down**, so the dropped odd
    /// second reappears in [`tenth`](Self::tenth) rather than moving the instant. A field
    /// that has no hundredths therefore records a time up to two seconds early, which is the
    /// encoding's granularity and not a rounding choice.
    #[must_use]
    pub fn encode(time: Timestamp) -> Option<Self> {
        if !Self::represents(time) {
            return None;
        }
        let c = Timestamp::from_secs(time.secs).civil();
        // The range check above bounds the year to 1980..=2107, so every field below fits the
        // bits the encoding gives it.
        let year = (c.year - 1980) as u16;
        let date = (year << 9) | ((c.month as u16) << 5) | c.day as u16;
        let time_word = ((c.hour as u16) << 11) | ((c.minute as u16) << 5) | (c.second / 2) as u16;
        // What the two-second unit dropped, to a hundredth: the odd second, plus the fraction
        // within it. A decoded timestamp may carry a fraction of a second or more, which is
        // clamped to what the field holds rather than allowed to run past it.
        let hundredths = (c.second % 2) * 100 + (time.nanos / 10_000_000).min(99);
        Some(Self {
            date,
            time: time_word,
            tenth: hundredths.min(Self::MAX_TENTH as u32) as u8,
        })
    }

    /// The calendar position the two words spell, field for field.
    ///
    /// Every field is taken as it is found, so this is a [`Civil`] a caller assembled rather
    /// than one an instant produced: it may name day 31 of February or a twenty-fifth hour.
    /// It is the one derivation of the six fields, so [`decode`](Self::decode) and
    /// [`is_well_formed`](Self::is_well_formed) read the same bits the same way.
    const fn civil(self) -> Civil {
        Civil {
            year: 1980 + (self.date >> 9) as i64,
            month: ((self.date >> 5) & 0xF) as u32,
            day: (self.date & 0x1F) as u32,
            hour: (self.time >> 11) as u32,
            minute: ((self.time >> 5) & 0x3F) as u32,
            // The seconds field counts two-second units, so it is scaled back to seconds
            // before the calendar sees it — the odd second the encoding dropped rides in the
            // hundredths.
            second: (self.time & 0x1F) as u32 * SECONDS_PER_UNIT,
        }
    }

    /// The instant this date, time, and hundredths describe, UTC.
    ///
    /// Every field is taken as it is found. An image may hold a date no calendar has — day 31
    /// of February, month 0, day 0 — and this reports the instant that arithmetic reaches
    /// rather than refusing, because a reader's job is to say what the image holds and
    /// [`is_well_formed`](Self::is_well_formed) is what judges it. A field with no time word
    /// passes zero, which is midnight.
    #[must_use]
    pub const fn decode(self) -> Timestamp {
        Timestamp {
            secs: self.civil().to_secs() + self.tenth as i64 / 100,
            nanos: (self.tenth as u32 % 100) * 10_000_000,
        }
    }

    /// Whether every field holds a value the encoding defines for it.
    ///
    /// This is what [`decode`](Self::decode) defers: a month of 0, a day of 31 in February, a
    /// twenty-fifth hour, a seconds field counting past 58, and a hundredths byte past
    /// [`MAX_TENTH`](Self::MAX_TENTH) are each a field an image may carry and no encoder
    /// produces. A reader hands back the instant the arithmetic reaches; a scan asks this and
    /// reports the ones that answer `false`.
    ///
    /// The month lengths are not tabulated. A date the calendar has is one a round trip
    /// through the calendar returns unchanged, and one it does not have is one the arithmetic
    /// moves — February 31 comes back as March 3, hour 24 as midnight the next day — so the
    /// round trip is the whole test.
    ///
    /// ```
    /// use ferrosys::DosTimestamp;
    ///
    /// // 2015-03-14T09:26:52Z, which the calendar has.
    /// assert!(DosTimestamp { date: 0x4A6E, time: 0x4B5A, tenth: 0 }.is_well_formed());
    /// // Month 0 and day 0, which is what an entry of zero bytes spells.
    /// assert!(!DosTimestamp::default().is_well_formed());
    /// ```
    #[must_use]
    pub const fn is_well_formed(self) -> bool {
        if self.tenth > Self::MAX_TENTH {
            return false;
        }
        let stated = self.civil();
        let reached = Civil::at_secs(stated.to_secs());
        stated.year == reached.year
            && stated.month == reached.month
            && stated.day == reached.day
            && stated.hour == reached.hour
            && stated.minute == reached.minute
            && stated.second == reached.second
    }

    /// Whether `time` is an instant this encoding represents.
    ///
    /// The final odd second of 2107 is excluded along with everything past it: the seconds
    /// field counts two-second units, so there is no encoding for it.
    #[must_use]
    pub const fn represents(time: Timestamp) -> bool {
        time.secs >= Self::SECS_MIN && time.secs <= Self::SECS_MAX
    }
}

#[cfg(test)]
mod tests {
    use super::{Civil, Timestamp};

    #[test]
    fn an_instant_is_its_seconds_and_fraction() {
        assert_eq!(
            Timestamp::from_secs(1_700_000_000),
            Timestamp {
                secs: 1_700_000_000,
                nanos: 0
            }
        );
        // The seconds are signed, so a time before the epoch is an ordinary value.
        assert_eq!(Timestamp::from_secs(-1).secs, -1);
        assert_eq!(Timestamp::default(), Timestamp::from_secs(0));
    }

    #[test]
    fn a_civil_reading_renders_as_utc_without_a_calendar_to_consult() {
        let at = |secs| Timestamp::from_secs(secs).civil().to_string();
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap day in a year divisible by 400, which the 100-year rule would otherwise
        // have skipped.
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        // Before the epoch the arithmetic floors: one second before 1970 is the last second
        // of 1969, not the first of 1970.
        assert_eq!(at(-1), "1969-12-31T23:59:59Z");
        // The ends of the range an ext4 timestamp reaches, and of a FAT one.
        assert_eq!(at(-2_147_483_648), "1901-12-13T20:45:52Z");
        assert_eq!(at(15_032_385_535), "2446-05-10T22:38:55Z");
        assert_eq!(at(315_532_800), "1980-01-01T00:00:00Z");
        assert_eq!(at(4_354_819_198), "2107-12-31T23:59:58Z");
    }

    #[test]
    fn the_conversion_agrees_with_itself_in_both_directions() {
        // The two halves are separate transcriptions of the same shift, so a defect in one
        // that a round trip through seconds alone cannot see — a month boundary both move —
        // is caught by walking days directly, across every leap rule the calendar has.
        for day in -200_000..200_000i64 {
            let c = Civil::at_secs(day * 86_400);
            assert_eq!(
                c.to_secs() / 86_400,
                day,
                "day {day} converts to {c} and back to something else"
            );
            assert!((1..=12).contains(&c.month), "day {day}: month {}", c.month);
            assert!((1..=31).contains(&c.day), "day {day}: day {}", c.day);
        }
    }

    #[test]
    fn a_date_no_calendar_has_yields_the_instant_the_arithmetic_reaches() {
        // A caller assembling a `Civil` from an image's fields may hand over a date that
        // does not exist. Day 31 of February is the first three days of March, reported
        // rather than refused — judging what an image holds is a scan's job.
        let odd = Civil {
            year: 2015,
            month: 2,
            day: 31,
            hour: 0,
            minute: 0,
            second: 0,
        };
        let march = Civil {
            year: 2015,
            month: 3,
            day: 3,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert_eq!(odd.to_secs(), march.to_secs());
    }
}

#[cfg(all(test, any(feature = "fat", feature = "exfat")))]
mod dos_tests {
    use super::*;

    /// One instant, in both forms: the seconds it is, and the calendar it reads as.
    ///
    /// The calendar side is written as the fields a person reads off a clock rather than as
    /// the packed words, and [`packed`] does the packing. A table of bit-shifted literals
    /// would be this encoding's own arithmetic restated, which checks nothing.
    struct Known {
        what: &'static str,
        secs: i64,
        nanos: u32,
        /// Year, month, day, hour, minute, second — UTC.
        calendar: (u16, u16, u16, u16, u16, u16),
        tenth: u8,
    }

    /// The date and time words a calendar reading packs into, by the field positions the
    /// encoding states rather than by [`DosTimestamp::encode`]'s arithmetic.
    fn packed(calendar: (u16, u16, u16, u16, u16, u16)) -> (u16, u16) {
        let (year, month, day, hour, minute, second) = calendar;
        let date = ((year - 1980) << 9) | (month << 5) | day;
        let time = (hour << 11) | (minute << 5) | (second / 2);
        (date, time)
    }

    const KNOWN: &[Known] = &[
        Known {
            what: "the first instant the encoding represents",
            secs: DosTimestamp::SECS_MIN,
            nanos: 0,
            calendar: (1980, 1, 1, 0, 0, 0),
            tenth: 0,
        },
        Known {
            what: "the last instant the encoding represents",
            secs: DosTimestamp::SECS_MAX,
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
            let encoded = DosTimestamp::encode(Timestamp {
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
            let decoded = DosTimestamp {
                date,
                time,
                tenth: k.tenth,
            }
            .decode();
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
        let encode = |secs| DosTimestamp::encode(Timestamp::from_secs(secs));
        assert!(encode(DosTimestamp::SECS_MIN - 1).is_none());
        assert!(encode(DosTimestamp::SECS_MAX + 1).is_none());
        assert!(encode(0).is_none());
        assert!(encode(-1).is_none());
        assert!(encode(DosTimestamp::SECS_MIN).is_some());
        assert!(encode(DosTimestamp::SECS_MAX).is_some());
        assert!(DosTimestamp::represents(Timestamp::from_secs(
            DosTimestamp::SECS_MIN
        )));
        assert!(!DosTimestamp::represents(Timestamp::from_secs(
            DosTimestamp::SECS_MIN - 1
        )));
    }

    #[test]
    fn the_round_trip_holds_across_the_whole_representable_range() {
        // Every two-second unit of every day would be 2 billion cases; a stride that is
        // coprime with a day, a year, and the 400-year cycle walks every hour of the day and
        // every day of the year instead, at a few hundred thousand.
        const STRIDE: i64 = 100_003;
        let mut secs = DosTimestamp::SECS_MIN;
        let mut checked = 0u32;
        while secs <= DosTimestamp::SECS_MAX {
            let encoded = DosTimestamp::encode(Timestamp::from_secs(secs)).expect("in range");
            assert_eq!(
                encoded.decode().secs,
                secs,
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
    fn the_conversion_is_utc_and_carries_no_zone() {
        // The epoch itself is outside the range, so the anchor is the first instant that is
        // in it: 1980-01-01T00:00:00Z is midnight, and midnight in no other zone.
        let midnight =
            DosTimestamp::encode(Timestamp::from_secs(DosTimestamp::SECS_MIN)).expect("in range");
        assert_eq!(midnight.time, 0);
        assert_eq!(midnight.date & 0x1F, 1, "the day must be the first");
        assert_eq!((midnight.date >> 5) & 0xF, 1, "the month must be January");
    }

    #[test]
    fn a_date_no_calendar_has_is_reported_rather_than_refused() {
        // A reader says what the image holds; a scan is what judges it. Day 31 of February
        // decodes to the instant the arithmetic reaches, which is in March.
        let odd = DosTimestamp {
            date: (35 << 9) | (2 << 5) | 31,
            time: 0,
            tenth: 0,
        }
        .decode();
        assert_eq!(
            odd.secs,
            DosTimestamp {
                date: (35 << 9) | (3 << 5) | 3,
                time: 0,
                tenth: 0,
            }
            .decode()
            .secs
        );
    }

    #[test]
    fn a_field_outside_the_range_the_encoding_defines_is_what_the_judge_answers_for() {
        // The other half of the pair above: `decode` defers and this is the site it defers
        // to. Each row is one field carrying a value the encoding has no meaning for, and
        // each is a value an image may hold — the whole point is that no encoder produces
        // one, so nothing but a judgment on the recovered field catches it.
        let date = |month: u16, day: u16| (35 << 9) | (month << 5) | day;
        for (stamp, what) in [
            (
                DosTimestamp {
                    date: date(0, 0),
                    time: 0,
                    tenth: 0,
                },
                "month 0 and day 0, which is what a field of zero bytes spells",
            ),
            (
                DosTimestamp {
                    date: date(2, 31),
                    time: 0,
                    tenth: 0,
                },
                "day 31 of February",
            ),
            (
                DosTimestamp {
                    date: date(13, 1),
                    time: 0,
                    tenth: 0,
                },
                "a thirteenth month",
            ),
            (
                DosTimestamp {
                    date: date(3, 14),
                    time: 24 << 11,
                    tenth: 0,
                },
                "a twenty-fifth hour",
            ),
            (
                DosTimestamp {
                    date: date(3, 14),
                    time: 60 << 5,
                    tenth: 0,
                },
                "a sixtieth minute",
            ),
            (
                DosTimestamp {
                    date: date(3, 14),
                    time: 30,
                    tenth: 0,
                },
                "a seconds field counting past fifty-eight",
            ),
            (
                DosTimestamp {
                    date: date(3, 14),
                    time: 0,
                    tenth: 200,
                },
                "a hundredths byte past what the field means",
            ),
        ] {
            assert!(!stamp.is_well_formed(), "{what} is a field out of range");
        }

        // And the dates a calendar does have are not swept up with them: a judge that
        // answered `false` too readily would report every volume. The leap day is the case
        // worth naming, because it is a real date in one year and not in the next — and the
        // year is the date word's own, so the judge has to read it rather than assume one.
        let leap_day = |year: u16| DosTimestamp {
            date: ((year - 1980) << 9) | (2 << 5) | 29,
            time: 0,
            tenth: 0,
        };
        assert!(leap_day(2000).is_well_formed(), "2000 is a leap year");
        assert!(!leap_day(2015).is_well_formed(), "2015 is not");
        assert!(!leap_day(2100).is_well_formed(), "nor is 2100");

        for secs in [
            DosTimestamp::SECS_MIN,
            DosTimestamp::SECS_MAX,
            951_827_696,
            1_426_325_213,
        ] {
            let stamp = DosTimestamp::encode(Timestamp::from_secs(secs)).expect("in range");
            assert!(
                stamp.is_well_formed(),
                "{secs} encodes to a field it judges"
            );
        }
        assert_eq!(DosTimestamp::MAX_TENTH, 199);
        assert!(
            DosTimestamp {
                date: date(3, 14),
                time: 0,
                tenth: DosTimestamp::MAX_TENTH,
            }
            .is_well_formed()
        );
    }
}
