//! Wall-clock time: the instant a filesystem records against a file.
//!
//! [`Timestamp`] is a point on the Unix timeline — whole seconds and a nanosecond fraction
//! — and nothing more. It is the form a source states a time in and the form a read hands
//! one back, whichever family is underneath.
//!
//! How that instant reaches the disk is the family's business, and the conversion lives in
//! that family's on-disk layer: the range of instants a format represents, the width of the
//! fields it splits them across, and the granularity it rounds to are all properties of the
//! format rather than of the instant. A time this type can hold is therefore not always a
//! time a given filesystem can store, and the family that cannot store it is the one that
//! says so.

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
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
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
}

#[cfg(test)]
mod tests {
    use super::Timestamp;

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
}
