//! Sizing a filesystem to what goes in it: what every family's fit search shares.
//!
//! A family is normally told how large its filesystem is. Told instead to hold a particular
//! tree, it has the hardest thing to compute directly: how much room a filesystem has left
//! depends on how it is laid out, and how it is laid out follows from its size. The answer
//! is a fixed point, not a formula.
//!
//! So it is searched for, and the search is what this module holds. Everything that differs
//! between families stays with the family — what a candidate is measured in, where its
//! bounds are, what a probe does, and what it means when one fails — because each of those
//! is implemented differently rather than merely named the same. What is shared is the
//! bracket itself, and the one input a caller states.

/// Room to leave beyond what the source needs, when a filesystem is sized to fit one.
///
/// A fit search with no slack finds the smallest filesystem the source fits in, which is a
/// filesystem with nothing left in it — correct for an image that will only ever be read,
/// and useless for one that will be written to. This states how much must remain.
///
/// The measure is what the finished filesystem reports free, in whatever unit it accounts
/// for space in: blocks for a family that has them, clusters for one whose free counter
/// counts those. It is the same number the filesystem's own free count carries and the same
/// one `df` reports as *used* against *size*. Where a family lays a second reservation over
/// those same units rather than making a second claim on them — as ext's super-user
/// reservation does — the two add up, so a filesystem left a fifth free under a 5%
/// reservation leaves an unprivileged writer 15% of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum Slack {
    /// Nothing beyond the source: the smallest filesystem that holds it.
    #[default]
    None,
    /// At least this many bytes free, rounded up to whole allocation units.
    Bytes(u64),
    /// At least this share of the filesystem free, in hundredths of one percent — `2000`
    /// for a fifth, `150` for 1.5%.
    ///
    /// The share is of the whole filesystem rather than of the source, so it says what the
    /// finished image looks like rather than how far it was grown: at `2500` a quarter of
    /// the space is free whatever the source turned out to occupy. A share past
    /// [`MAX_SHARE`](Self::MAX_SHARE) is refused before any searching happens, by the
    /// family's own error.
    Share(u16),
}

impl Slack {
    /// The largest share a fit search will look for: 90%, in hundredths of one percent.
    ///
    /// At this share the filesystem is ten times the source it holds, and each further step
    /// toward a wholly empty filesystem multiplies the size again while the search works
    /// harder to find it. A size that far from what the contents need is a size to name
    /// rather than to search for.
    pub const MAX_SHARE: u16 = 9000;

    /// Hundredths of one percent of a whole, exactly: the product is carried in 128 bits so
    /// it exists for every count, and narrowing back is lossless because the share is
    /// bounded well below one.
    pub(crate) fn share_of(total: u64, hundredths: u16) -> u64 {
        (u128::from(total) * u128::from(hundredths) / 10_000) as u64
    }

    /// The allocation units a filesystem of `total_units` must have free to satisfy this.
    ///
    /// The unit is the family's, and so is its size in bytes: a family whose free counter
    /// counts clusters passes its cluster size here, and a family that counts blocks passes
    /// its block size.
    pub(crate) fn required_free(self, total_units: u64, unit_bytes: u64) -> u64 {
        match self {
            Self::None => 0,
            Self::Bytes(bytes) => bytes.div_ceil(unit_bytes),
            Self::Share(hundredths) => Self::share_of(total_units, hundredths),
        }
    }

    /// The share this asks for, if it is past what a search will look for.
    ///
    /// Returned rather than refused, because the refusal is a family's own error and this
    /// module names none of them.
    pub(crate) fn share_over_limit(self) -> Option<u16> {
        match self {
            Self::Share(hundredths) if hundredths > Self::MAX_SHARE => Some(hundredths),
            _ => None,
        }
    }
}

/// What one candidate size turned out to be.
///
/// The four failing arms exist because a search that climbs has to know which direction a
/// refusal points in. Reading an upward-closed refusal as "too small" is what makes a climb
/// step over the sizes that work, so a family states the direction rather than leaving the
/// bracket to infer one.
///
/// The arms are the verdicts a search can reach, not the ones a particular build happens to
/// emit, so a build carrying no family at all constructs none of them. The allowance is
/// scoped to exactly that build: with a family compiled in, an arm no search reaches is a
/// dead arm and is reported as one.
#[cfg_attr(not(any(feature = "ext", feature = "fat")), allow(dead_code))]
pub(crate) enum Probe<T, E> {
    /// The tree was placed and the slack was met. Carries whatever the family wants to keep
    /// from the attempt, so the winning candidate needs no second search to rebuild it.
    ///
    /// What it carries is the *probe's own* result. State a family keeps outside this — a
    /// tree every probe allocates into, say — belongs to whichever candidate ran last, which
    /// the bracket does not promise is this one.
    Fits(T),
    /// Placed, but with less room left than the slack asked for.
    Tight,
    /// Refused, and no smaller size would do better.
    TooSmall(E),
    /// Refused, and no *larger* size would do better either — the candidate is past the top
    /// of what this family accepts. Ends the climb rather than continuing it.
    Exhausted(E),
    /// Refused for a reason no size changes. Ends the search outright.
    Impossible(E),
}

/// The smallest count in `floor ..= ceiling` that probes as [`Probe::Fits`], with the count
/// one below it proven not to.
///
/// Brackets by doubling and then bisects. It brackets rather than solving because fit is not
/// monotone in size for any family that has been measured: a filesystem one unit larger can
/// need one more unit of metadata and so have less room than the one below it. Both ends of
/// the bracket are established by probing, which is what makes the guarantee above true
/// whether or not the function is monotone.
///
/// **Every non-fitting verdict moves the floor, including in the bisection.** Moving the
/// ceiling on one would leave the ceiling naming a size that does not fit while the carried
/// value describes a larger one — and a caller that sizes a destination from the first and
/// writes the second has been handed two answers to one question.
///
/// The error is `None` when the range was searched to its end without a fit and no probe had
/// anything to say about why; the caller renders that as its own "does not fit".
pub(crate) fn bracket<T, E, F>(
    floor: u64,
    ceiling: u64,
    mut probe: F,
) -> Result<(u64, T), Option<E>>
where
    F: FnMut(u64) -> Probe<T, E>,
{
    if floor > ceiling {
        return Err(None);
    }
    // `lo` is a count proven not to fit, and stays one below the floor until something is:
    // the floor itself is a candidate, not a value already ruled out.
    let mut lo = floor.saturating_sub(1);
    let mut candidate = floor;
    let (mut hi, mut fitted) = 'climb: loop {
        match probe(candidate) {
            Probe::Fits(value) => break (candidate, value),
            Probe::Impossible(e) => return Err(Some(e)),
            Probe::Exhausted(e) => {
                // Upward-closed: everything at or above `candidate` refuses this way, so
                // a fit — if there is one — lies strictly between the last count proven
                // too small and this candidate. The doubling can overshoot a window
                // narrower than one doubling, so the window is bisected rather than
                // surrendered: too-small raises the floor, another upward-closed refusal
                // lowers the ceiling, and only a window that closes empty returns the
                // refusal.
                let mut above = candidate;
                let mut refusal = e;
                loop {
                    if above - lo <= 1 {
                        return Err(Some(refusal));
                    }
                    let mid = lo + (above - lo) / 2;
                    match probe(mid) {
                        Probe::Fits(value) => break 'climb (mid, value),
                        Probe::Impossible(e) => return Err(Some(e)),
                        Probe::Exhausted(e) => {
                            above = mid;
                            refusal = e;
                        }
                        Probe::Tight | Probe::TooSmall(_) => lo = mid,
                    }
                }
            }
            Probe::Tight | Probe::TooSmall(_) if candidate == ceiling => {
                return Err(match probe(ceiling) {
                    Probe::TooSmall(e) => Some(e),
                    _ => None,
                });
            }
            Probe::Tight | Probe::TooSmall(_) => {
                lo = candidate;
                candidate = candidate.saturating_mul(2).min(ceiling);
            }
        }
    };

    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        match probe(mid) {
            Probe::Fits(value) => {
                hi = mid;
                fitted = value;
            }
            // Every other verdict moves the floor. See the note above: the alternative is a
            // returned size and a returned plan that describe different filesystems.
            _ => lo = mid,
        }
    }
    Ok((hi, fitted))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe that fits at or above `least`, within a domain of `..=top`.
    fn threshold(least: u64, top: u64) -> impl FnMut(u64) -> Probe<u64, &'static str> {
        move |n| {
            if n > top {
                Probe::Exhausted("past the top")
            } else if n >= least {
                Probe::Fits(n)
            } else {
                Probe::TooSmall("below the threshold")
            }
        }
    }

    #[test]
    fn a_fit_window_narrower_than_one_doubling_is_found_not_stepped_over() {
        // The climb doubles, so a window that opens and closes between two of its
        // candidates is one the climb itself never lands in: from 4 it steps to 8, and a
        // domain that fits only 5 and 6 answers 8 with the upward-closed refusal. That
        // refusal bounds the window rather than ending the search — the fit is between
        // the last too-small count and the refused one.
        for (least, top) in [(5u64, 6u64), (5, 5), (3, 3), (9, 11)] {
            let (n, carried) =
                bracket(1, 1 << 30, threshold(least, top)).expect("a size in the window fits");
            assert_eq!(n, least, "the smallest that fits, window {least}..={top}");
            assert_eq!(carried, least);
        }
        // And a window that is genuinely empty is the refusal, not a loop.
        let err = bracket(8, 1 << 30, threshold(5, 6)).expect_err("nothing at or above 8 fits");
        assert_eq!(err, Some("past the top"));
    }

    #[test]
    fn the_answer_is_the_smallest_that_fits_and_carries_that_probes_value() {
        for least in [1u64, 2, 7, 64, 1000, 65_537] {
            let (n, carried) = bracket(1, 1 << 30, threshold(least, u64::MAX)).expect("fits");
            assert_eq!(n, least, "the smallest that fits");
            assert_eq!(carried, least, "the value carried is the winning probe's");
        }
    }

    #[test]
    fn a_floor_above_the_answer_is_the_answer() {
        // The floor is a candidate, not a value already ruled out: a tree whose contents
        // already exceed what it needs must not have the floor itself skipped.
        let (n, _) = bracket(100, 1 << 20, threshold(7, u64::MAX)).expect("fits");
        assert_eq!(n, 100);
    }

    #[test]
    fn a_ceiling_below_the_answer_reports_rather_than_returning_one_that_does_not_fit() {
        assert!(matches!(
            bracket(1, 50, threshold(51, u64::MAX)),
            Err(Some("below the threshold"))
        ));
        assert!(matches!(bracket(10, 5, threshold(1, u64::MAX)), Err(None)));
    }

    #[test]
    fn a_verdict_that_points_upward_ends_the_search_rather_than_climbing_past_it() {
        // Nothing in `..=40` fits and everything above 40 is out of the domain, so the climb
        // has to stop rather than run to the ceiling.
        assert!(matches!(
            bracket(1, 1 << 40, threshold(1000, 40)),
            Err(Some("past the top"))
        ));
    }

    #[test]
    fn a_refusal_no_size_changes_ends_the_search_at_once() {
        let mut probes = 0;
        let r: Result<(u64, u64), _> = bracket(1, 1 << 40, |_| {
            probes += 1;
            Probe::Impossible("nothing to do with the size")
        });
        assert!(matches!(r, Err(Some("nothing to do with the size"))));
        assert_eq!(
            probes, 1,
            "it does not climb through a refusal it cannot fix"
        );
    }

    #[test]
    fn the_size_one_below_the_answer_is_one_the_search_actually_probed() {
        // The guarantee is not just that the answer fits: it is that the answer is tight.
        // Recording every candidate is what shows the bisection closed rather than stopped.
        let mut seen: Vec<u64> = Vec::new();
        let (n, _) = bracket(1, 1 << 20, |c| {
            seen.push(c);
            if c >= 12_345 {
                Probe::Fits(c)
            } else {
                Probe::TooSmall("small")
            }
        })
        .expect("fits");
        assert_eq!(n, 12_345);
        assert!(seen.contains(&12_344), "one below the answer was probed");
    }

    #[test]
    fn a_share_is_exact_at_every_size() {
        // The product is carried in 128 bits, so a count near the top of the range is a
        // quarter of itself rather than an overflow.
        assert_eq!(Slack::share_of(u64::MAX, 2500), u64::MAX / 4);
        assert_eq!(Slack::share_of(1_000_000, 150), 15_000);
        assert_eq!(Slack::share_of(0, 9000), 0);
    }

    #[test]
    fn bytes_round_up_to_whole_units_of_whatever_size() {
        // The same request in bytes is a different count of units per family, which is the
        // whole reason the unit is an argument.
        assert_eq!(Slack::Bytes(4097).required_free(0, 4096), 2);
        assert_eq!(Slack::Bytes(4097).required_free(0, 512), 9);
        assert_eq!(Slack::None.required_free(1_000, 4096), 0);
    }

    #[test]
    fn only_a_share_can_be_over_the_limit() {
        assert_eq!(Slack::Share(Slack::MAX_SHARE).share_over_limit(), None);
        assert_eq!(Slack::Share(9001).share_over_limit(), Some(9001));
        assert_eq!(Slack::Bytes(u64::MAX).share_over_limit(), None);
        assert_eq!(Slack::None.share_over_limit(), None);
    }
}
