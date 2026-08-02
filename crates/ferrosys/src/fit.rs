//! Sizing a filesystem to what goes in it: the search behind [`FormatPlan::fit`].
//!
//! Every other way into a format is told how large the filesystem is. This one is not, and
//! the size is the hardest thing to compute directly: how much room a filesystem has left
//! depends on how many block groups it has, how large its inode tables are, how many
//! descriptor blocks it reserves to grow into, and how large a journal its size earns —
//! and every one of those follows from the size. The answer is a fixed point, not a
//! formula.
//!
//! So it is searched for. A candidate size is planned and the source is *placed* into it —
//! the format's own placement pass, over a sink that keeps nothing — and what the placement
//! leaves free is what judges the candidate. Nothing here estimates what a format would do;
//! it runs the part of the format that decides, which is why a size the search returns is a
//! size that formats.
//!
//! The search brackets rather than solves, because fit is not monotone in size: a
//! filesystem one block larger can need one more block group, and so have less room than
//! the one below it. Both ends of the bracket are established by placing, so the search
//! closes on a size that was placed successfully with the size one block below it proven
//! not to be — which is the guarantee worth stating whether or not the function is
//! monotone.

use crate::geometry::{GrowReservation, Layout, MAX_32BIT_BLOCKS, MAX_EXTENT_BLOCKS};
use crate::materialize::{FormatError, FormatOptions, free_after_placing, plan_geometry};
use crate::model::{Content, FsModel};

/// Room to leave beyond what the source needs, when a filesystem is sized to fit one.
///
/// A fit search with no slack finds the smallest filesystem the source fits in, which is a
/// filesystem with nothing left in it — correct for an image that will only ever be read,
/// and useless for one that will be written to. This states how much must remain.
///
/// The measure is free blocks once the source is written: the same count the filesystem's
/// own `s_free_blocks_count` carries, and the same one `df` reports as *used* against
/// *size*. The super-user reservation
/// ([`ReservedRatio`](crate::geometry::ReservedRatio)) is separate accounting laid over
/// those same blocks rather than a second claim on them, so a filesystem left a fifth free
/// under the default 5% reservation leaves an unprivileged writer 15% of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub enum Slack {
    /// Nothing beyond the source: the smallest filesystem that holds it.
    #[default]
    None,
    /// At least this many bytes free, rounded up to whole blocks.
    Bytes(u64),
    /// At least this share of the filesystem free, in hundredths of one percent — `2000`
    /// for a fifth, `150` for 1.5%.
    ///
    /// The share is of the whole filesystem rather than of the source, so it says what the
    /// finished image looks like rather than how far it was grown: at `2500` a quarter of
    /// the blocks are free whatever the source turned out to occupy. A share past
    /// [`MAX_SHARE`](Self::MAX_SHARE) is refused with
    /// [`FormatError::SlackShareTooLarge`].
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
    /// it exists for every block count, and narrowing back is lossless because the share is
    /// bounded well below one.
    fn share_of(total: u64, hundredths: u16) -> u64 {
        (u128::from(total) * u128::from(hundredths) / 10_000) as u64
    }

    /// The blocks a filesystem of `total_blocks` must have free to satisfy this.
    fn required_free(self, total_blocks: u64, block_size: u64) -> u64 {
        match self {
            Self::None => 0,
            Self::Bytes(bytes) => bytes.div_ceil(block_size),
            Self::Share(hundredths) => Self::share_of(total_blocks, hundredths),
        }
    }

    /// Refuse a share past the limit before any searching happens.
    fn validate(self) -> Result<(), FormatError> {
        match self {
            Self::Share(hundredths) if hundredths > Self::MAX_SHARE => {
                Err(FormatError::SlackShareTooLarge {
                    hundredths,
                    limit: Self::MAX_SHARE,
                })
            }
            _ => Ok(()),
        }
    }
}

/// A candidate size that held the source: the geometry it planned, ready to become a plan.
pub(crate) struct Fitted {
    pub(crate) layout: Layout,
    pub(crate) journal_blocks: Option<u32>,
}

/// Why a candidate size was rejected.
enum Miss {
    /// It could not be planned or placed. The failure is carried so the search can report
    /// it if no size works at all — "out of space by 40 blocks" says far more than "no size
    /// fits".
    Failed(FormatError),
    /// It was planned and placed, and had less room left than the slack asks for. Nothing
    /// failed; the filesystem is simply too tight.
    TooTight,
}

/// The largest block count the search will consider.
///
/// Two bounds, and the smaller wins. The format's own is the largest block count the
/// feature set addresses. A [`GrowReservation::UpTo`] target is the other: the planner
/// refuses a filesystem larger than the target it is meant to grow *into*, so a search that
/// went past it would be trying sizes that cannot be planned by definition.
fn ceiling_blocks(options: &FormatOptions) -> u64 {
    let format = if options.feature.is_64bit() {
        MAX_EXTENT_BLOCKS
    } else {
        MAX_32BIT_BLOCKS
    };
    match options.grow {
        GrowReservation::UpTo(bytes) => format.min(bytes / u64::from(options.feature.block_size)),
        GrowReservation::None | GrowReservation::Max => format,
    }
}

/// A block count to begin the bracket at: the blocks the contents alone occupy, before any
/// of the filesystem's own structures.
///
/// This is a starting point and nothing more. Neither end of the bracket is taken on trust
/// — both are established by actually placing — so a hint that is too high only makes the
/// search bisect downward from it, and one that is too low only costs a doubling or two.
/// It exists because a search that started at one block would spend twenty probes climbing
/// to where the answer obviously is.
fn content_floor(model: &FsModel, block_size: u64) -> u64 {
    model
        .inodes
        .values()
        .map(|inode| match &inode.content {
            // Every directory holds at least `.` and `..`, so at least one block.
            Content::Directory(_) => 1,
            Content::File(content) => content.len().div_ceil(block_size),
            Content::SlowSymlink(target) => (target.len() as u64).div_ceil(block_size),
            // Stored in the inode itself: a fast symlink's target, a device number, and
            // the nothing a FIFO or socket holds.
            Content::FastSymlink(_) | Content::Device { .. } | Content::Special => 0,
        })
        .sum()
}

/// Plan a filesystem of `blocks` blocks and place the model into it.
fn probe(
    model: &FsModel,
    options: &FormatOptions,
    slack: Slack,
    blocks: u64,
) -> Result<Fitted, Miss> {
    let block_size = u64::from(options.feature.block_size);
    let size_bytes = blocks.saturating_mul(block_size);
    let (layout, journal_blocks) =
        plan_geometry(model, options, size_bytes).map_err(Miss::Failed)?;
    let free = free_after_placing(&layout, options, journal_blocks, model).map_err(Miss::Failed)?;
    if free < slack.required_free(layout.total_blocks, block_size) {
        return Err(Miss::TooTight);
    }
    Ok(Fitted {
        layout,
        journal_blocks,
    })
}

/// Find the smallest filesystem that holds `model` with `slack` free, and return the
/// geometry it planned.
///
/// # Errors
///
/// [`FormatError::SlackShareTooLarge`] for a share past the limit,
/// [`FormatError::DoesNotFit`] if the largest size the search may try was placed
/// successfully and still left too little room, and otherwise the failure the largest size
/// tried met.
pub(crate) fn search(
    model: &FsModel,
    options: &FormatOptions,
    slack: Slack,
) -> Result<Fitted, FormatError> {
    slack.validate()?;
    let block_size = u64::from(options.feature.block_size);
    let ceiling = ceiling_blocks(options);

    // Slack the largest filesystem the search may try could not leave free is unreachable
    // at every size below it too, so it is answered here rather than after climbing to find
    // out. That climb is what makes the check worth making: a probe's memory is a format's
    // at that size, because it *is* a format's placement, and probing sizes no source
    // needs would cost what formatting them costs.
    if slack.required_free(ceiling, block_size) >= ceiling {
        return Err(FormatError::DoesNotFit { ceiling });
    }

    // Bracket. A filesystem of no blocks holds nothing, so the lower end starts proven
    // without probing; the upper end is found by doubling until a size holds the source.
    let mut lo = 0u64;
    let mut candidate = content_floor(model, block_size).clamp(1, ceiling);
    let (mut hi, mut fitted) = loop {
        let miss = match probe(model, options, slack, candidate) {
            Ok(fitted) => break (candidate, fitted),
            Err(miss) => miss,
        };
        lo = candidate;
        if candidate == ceiling {
            // Why the largest size the search may try was rejected is the whole of what
            // there is to report: a size that failed says what it failed at, and one that
            // planned and placed perfectly well and was merely too tight failed at nothing
            // — so it gets an answer of its own rather than the failure some far smaller
            // size met.
            return Err(match miss {
                Miss::Failed(e) => e,
                Miss::TooTight => FormatError::DoesNotFit { ceiling },
            });
        }
        candidate = candidate.saturating_mul(2).min(ceiling);
    };

    // Bisect. `lo` is a size that did not hold the source and `hi` is one that did, and
    // every step keeps that true, so the loop closes with `hi` one block above `lo`: a size
    // that formats, with the size below it proven not to. Why a rejected candidate was
    // rejected no longer matters here — the bracket already holds an answer, so the search
    // can only succeed from this point on.
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        match probe(model, options, slack, mid) {
            Ok(next) => {
                hi = mid;
                fitted = next;
            }
            Err(_) => lo = mid,
        }
    }
    Ok(fitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::{FeatureSet, Profile};
    use crate::materialize::{FormatPlan, format};
    use crate::model::{ModelConfig, build_model};
    use crate::ondisk::{SuperBlock, Timestamp};
    use crate::read::Reader;
    use crate::source::{Metadata, Source, TreeBuilder};

    const MIB: u64 = 1024 * 1024;

    fn time() -> Timestamp {
        Timestamp::from_secs(1_700_000_000)
    }

    fn opts() -> FormatOptions {
        FormatOptions::new([0x11; 16], time(), [0u8; 16])
    }

    /// The block size a filesystem records, from the log its superblock carries.
    fn block_size_of(sb: &SuperBlock) -> u64 {
        1024u64 << sb.log_block_size
    }

    /// A tree of `count` files of `bytes` each, under one directory.
    fn tree(count: usize, bytes: usize) -> TreeBuilder {
        let mut builder =
            TreeBuilder::new().directory(b"/data".to_vec(), Metadata::new(0o755, time()));
        for i in 0..count {
            builder = builder.file(
                format!("/data/f{i}").into_bytes(),
                vec![b'x'; bytes],
                Metadata::new(0o644, time()),
            );
        }
        builder
    }

    /// The failure a fit meets, for a test that expects one. `FormatPlan` holds a whole
    /// inode model and so is deliberately not `Debug`, which `expect_err` would want.
    fn fit_err(source: impl Source, options: FormatOptions, slack: Slack) -> FormatError {
        match FormatPlan::fit(source, options, slack) {
            Ok(plan) => panic!("expected a failure, fitted {} bytes", plan.size_bytes()),
            Err(e) => e,
        }
    }

    /// The model one source implies, for a test that reads what the search reads.
    fn model_of(source: impl Source, options: &FormatOptions) -> FsModel {
        let config = ModelConfig::new(options.feature, 12, options.time);
        build_model(source, config).expect("model")
    }

    #[test]
    fn a_fitted_size_formats_and_one_block_less_does_not() {
        // The whole contract of the search, and the only guarantee that matters: what it
        // returns is a size that works, and it is not one block bigger than it had to be.
        for (count, bytes) in [(0, 0), (1, 1), (16, 4096), (64, 100_000)] {
            let plan = FormatPlan::fit(tree(count, bytes), opts(), Slack::None).expect("fit");
            let size = plan.size_bytes();
            format(tree(count, bytes), size, opts())
                .unwrap_or_else(|e| panic!("{count}x{bytes}: the fitted {size} bytes: {e}"));
            let smaller = size - u64::from(opts().feature.block_size);
            assert!(
                format(tree(count, bytes), smaller, opts()).is_err(),
                "{count}x{bytes}: one block below the fitted {size} bytes formatted too"
            );
        }
    }

    #[test]
    fn a_fitted_image_reads_back_with_its_contents() {
        // A size that formats is not enough: the filesystem it produces has to be the one
        // that was asked for, contents and all.
        let plan = FormatPlan::fit(tree(8, 5000), opts(), Slack::None).expect("fit");
        let size = plan.size_bytes();
        let image = format(tree(8, 5000), size, opts()).expect("format at the fitted size");
        let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        let (_, inode) = reader
            .lookup(b"/data/f7")
            .expect("the last file is present");
        assert_eq!(inode.size, 5000);
        assert_eq!(reader.read_data(&inode).expect("read").len(), 5000);
    }

    #[test]
    fn slack_is_free_space_the_finished_filesystem_has() {
        // Slack is measured on the image, not inside the search: what it asks for is what
        // the superblock reports free once every block is placed. And it is a floor the
        // search does not overshoot — one block less does not leave that much.
        let source = || tree(32, 20_000);
        for slack in [Slack::Bytes(8 * MIB), Slack::Share(2500)] {
            let plan = FormatPlan::fit(source(), opts(), slack).expect("fit");
            let size = plan.size_bytes();
            let image = format(source(), size, opts()).expect("format");
            let reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
            let sb = reader.superblock();
            let want = match slack {
                Slack::Bytes(bytes) => bytes.div_ceil(block_size_of(sb)),
                Slack::Share(h) => Slack::share_of(sb.blocks_count, h),
                Slack::None => 0,
            };
            assert!(
                sb.free_blocks_count >= want,
                "{slack:?}: {} free of {} blocks, wanted {want}",
                sb.free_blocks_count,
                sb.blocks_count
            );

            // One block less either fails outright or leaves less room than was asked for.
            let smaller = size - u64::from(opts().feature.block_size);
            let short = match format(source(), smaller, opts()) {
                Err(_) => true,
                Ok(image) => {
                    let reader =
                        Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
                    let sb = reader.superblock();
                    let want = match slack {
                        Slack::Bytes(bytes) => bytes.div_ceil(block_size_of(sb)),
                        Slack::Share(h) => Slack::share_of(sb.blocks_count, h),
                        Slack::None => 0,
                    };
                    sb.free_blocks_count < want
                }
            };
            assert!(short, "{slack:?}: one block below the fit satisfied it too");
        }
    }

    #[test]
    fn no_slack_leaves_a_filesystem_with_almost_nothing_in_it() {
        // The floor is a floor: a fitted filesystem has room for very little more, which is
        // what makes the slack knob worth having.
        //
        // Without a journal, because on ext4 the floor is usually the journal rather than
        // the source — a log is a thousand blocks whatever goes in the filesystem, so a
        // small ext4 image is mostly journal and looks half empty however tightly it was
        // fitted. What is left once the log is gone is the contents and the filesystem's
        // own tables, which is what "fitted" should mean.
        let options = opts().profile(Profile::Ext2);
        let source = || tree(24, 30_000);
        let plan = FormatPlan::fit(source(), options, Slack::None).expect("fit");
        let image = format(source(), plan.size_bytes(), options).expect("format");
        let reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        let sb = reader.superblock();
        assert!(
            sb.free_blocks_count * 10 < sb.blocks_count,
            "{} of {} blocks free is not a fitted filesystem",
            sb.free_blocks_count,
            sb.blocks_count
        );
    }

    #[test]
    fn a_bigger_source_fits_a_bigger_filesystem() {
        let small = FormatPlan::fit(tree(4, 4096), opts(), Slack::None).expect("fit");
        let large = FormatPlan::fit(tree(4, 4 * MIB as usize), opts(), Slack::None).expect("fit");
        assert!(
            large.size_bytes() > small.size_bytes(),
            "{} is not larger than {}",
            large.size_bytes(),
            small.size_bytes()
        );
    }

    #[test]
    fn every_family_fits() {
        // The block-mapped families place their data through the classic map rather than an
        // extent tree, and ext2 has no journal to size, so each one sizes differently.
        for profile in [Profile::Ext2, Profile::Ext3, Profile::Ext4] {
            let options = opts().profile(profile);
            let plan = FormatPlan::fit(tree(12, 9000), options, Slack::None)
                .unwrap_or_else(|e| panic!("{profile:?}: {e}"));
            let size = plan.size_bytes();
            format(tree(12, 9000), size, options)
                .unwrap_or_else(|e| panic!("{profile:?} at {size}: {e}"));
            assert!(
                format(
                    tree(12, 9000),
                    size - u64::from(options.feature.block_size),
                    options
                )
                .is_err(),
                "{profile:?}: one block less formatted too"
            );
        }
    }

    #[test]
    fn a_thousand_byte_block_fits_too() {
        // The 1024-byte block moves the first data block to one, which the free-block
        // accounting the search reads is indexed from.
        let feature = FeatureSet {
            block_size: 1024,
            ..FeatureSet::EXT2
        };
        let mut options = opts();
        options.feature = feature;
        let plan = FormatPlan::fit(tree(6, 3000), options, Slack::None).expect("fit");
        let size = plan.size_bytes();
        assert_eq!(size % 1024, 0);
        format(tree(6, 3000), size, options).expect("format at the fitted size");
    }

    #[test]
    fn the_fitted_plan_is_the_plan_that_writes() {
        // `fit` keeps the model it built, so writing costs no second walk of the source and
        // the geometry written is the geometry the search settled on.
        let plan = FormatPlan::fit(tree(5, 8000), opts(), Slack::None).expect("fit");
        let blocks = plan.layout().total_blocks;
        let size = plan.size_bytes();
        let mut out = std::io::Cursor::new(vec![0u8; size as usize]);
        let layout = plan.write_to(&mut out).expect("write");
        assert_eq!(layout.total_blocks, blocks);
        Reader::open(std::io::Cursor::new(out.into_inner())).expect("the written image opens");
    }

    #[test]
    fn a_grow_target_bounds_the_search() {
        // `UpTo` names a target the filesystem must be able to grow into, so the planner
        // refuses a filesystem larger than it. The search must stop there rather than climb
        // past it, and say what it ran out of.
        let mut options = opts();
        options.grow = GrowReservation::UpTo(8 * MIB);
        // A 64 MiB source cannot fit under an 8 MiB grow target.
        let err = fit_err(tree(64, 1024 * 1024), options, Slack::None);
        // The failure the ceiling met, not a bare statement that nothing worked.
        assert!(
            matches!(
                err,
                FormatError::Alloc(_) | FormatError::JournalDoesNotFit { .. }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_share_past_the_limit_is_refused_before_any_search() {
        let err = fit_err(
            TreeBuilder::new(),
            opts(),
            Slack::Share(Slack::MAX_SHARE + 1),
        );
        assert!(
            matches!(err, FormatError::SlackShareTooLarge { limit, .. } if limit == Slack::MAX_SHARE),
            "{err}"
        );
    }

    #[test]
    fn slack_no_filesystem_could_leave_is_answered_before_any_probing() {
        // A byte count past the largest filesystem the format describes cannot be satisfied
        // at any size, and finding that out by climbing would mean planning and placing
        // filesystems of exabytes — which costs what formatting them costs. It is answered
        // from the ceiling alone instead.
        let err = fit_err(TreeBuilder::new(), opts(), Slack::Bytes(u64::MAX));
        assert!(matches!(err, FormatError::DoesNotFit { .. }), "{err}");
    }

    #[test]
    fn slack_no_filesystem_can_leave_says_so() {
        // A share the largest size the search may try cannot satisfy is not a failure of
        // anything — that size planned and placed perfectly well — so it is the one case
        // that needs an answer of its own rather than the failure some smaller size met.
        let mut options = opts().profile(Profile::Ext2);
        // The grow target is what bounds the search, so it is also what makes this finish
        // rather than climb toward the format's own ceiling.
        options.grow = GrowReservation::UpTo(8 * MIB);
        // A megabyte of files cannot be a tenth of an 8 MiB filesystem.
        let err = fit_err(
            tree(1, MIB as usize),
            options,
            Slack::Share(Slack::MAX_SHARE),
        );
        assert!(matches!(err, FormatError::DoesNotFit { .. }), "{err}");
    }

    #[test]
    fn a_feature_set_that_cannot_be_realized_fails_at_once() {
        // Not by climbing to the ceiling and reporting the last size's copy of the same
        // complaint: the feature set is wrong at every size, so it is answered once.
        let mut options = opts();
        options.feature = FeatureSet {
            block_size: 3000,
            ..FeatureSet::DEFAULT
        };
        // A 3000-byte block is not a block size at any filesystem size.
        let err = fit_err(TreeBuilder::new(), options, Slack::None);
        assert!(matches!(err, FormatError::Geometry(_)), "{err}");
    }

    #[test]
    fn the_content_floor_counts_what_the_contents_occupy() {
        // The hint is only a starting point, but a wrong one costs probes: a file of two
        // blocks and a byte is three blocks, and an inode holding its content inline is
        // none of them.
        let source = TreeBuilder::new()
            .file(
                b"/big".to_vec(),
                vec![b'x'; 8193],
                Metadata::new(0o644, time()),
            )
            .symlink(
                b"/short".to_vec(),
                b"/big".to_vec(),
                Metadata::new(0o777, time()),
            )
            .char_device(b"/dev".to_vec(), 1, 3, Metadata::new(0o600, time()));
        // The root and /lost+found are a block each, and the file is three.
        assert_eq!(content_floor(&model_of(source, &opts()), 4096), 5);
    }
}
