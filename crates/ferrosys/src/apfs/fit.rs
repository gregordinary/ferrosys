//! Sizing an APFS container to what goes in it: the search behind
//! [`FormatPlan::fit`](super::FormatPlan::fit).
//!
//! The bracket itself is [`crate::sizing`]. What this module supplies is everything about it
//! that is APFS's: the unit a candidate is counted in, where the accepted sizes lie, what a
//! probe does, and which direction each refusal points in.
//!
//! **The unit is a block.** The block size is an input, and a container occupies the whole
//! blocks of what it is given, so a block is the finest step that changes an answer.
//!
//! **The accepted sizes are one range**, from [`MIN_BLOCK_COUNT`] blocks to
//! [`MAX_CONTAINER_BYTES`]. Within it, a container one block larger can have less room than
//! the one below it: its checkpoint areas, its space manager and its internal pool grow in
//! steps with its size. A container of more than one volume needs a slot for each, and it has
//! one slot for every 512 MiB or part of it. The bracket's guarantee holds all the same: the
//! answer placed, and the block below it was placed and did not.
//!
//! **A probe is the writer's own placement.** Each candidate is planned by the planner a format
//! of that size uses, and every volume's model is placed into it by the same pass, so what
//! the search carries out of its last fitting probe is the plan a format of that size makes.
//! The models are built once, before the search, and nothing a probe does reads a file.

use super::geometry::{
    ApfsLayout, ContentPlanner, GeometryError, MAX_CONTAINER_BYTES, MIN_BLOCK_COUNT, macos_reserve,
};
use super::materialize::{FormatError, FormatOptions, PreparedVolume, place_volumes, plan_request};
use super::model::ApfsModel;
use crate::sizing::{Probe, Slack};

/// The container the search settled on: its size, the layout planned for it and where each
/// volume's content went in it.
///
/// A probe's own result, carried out of it whole. Every probe plans and places afresh, so
/// nothing in this belongs to any other candidate.
pub(super) struct Fitted {
    pub(super) container_bytes: u64,
    pub(super) layout: ApfsLayout,
    pub(super) volumes: Vec<PreparedVolume>,
}

/// Which way a planning refusal points.
///
/// One is upward-closed: a container past [`MAX_CONTAINER_BYTES`], which no larger one
/// escapes. One no size changes: no volume at all. Every other refusal is answered by more
/// blocks: fewer than [`MIN_BLOCK_COUNT`], fewer slots than volumes, and too few free blocks
/// for what the volumes hold.
fn classify(e: GeometryError) -> Probe<Fitted, FormatError> {
    match e {
        GeometryError::ContainerTooLarge { .. } => Probe::Exhausted(FormatError::Geometry(e)),
        GeometryError::NoVolumes => Probe::Impossible(FormatError::Geometry(e)),
        _ => Probe::TooSmall(FormatError::Geometry(e)),
    }
}

/// Plan a container of `blocks` blocks and place every volume of `models` into it.
fn probe(
    models: &[ApfsModel],
    options: &FormatOptions,
    time: i64,
    slack: Slack,
    blocks: u64,
) -> Probe<Fitted, FormatError> {
    let block_size = u64::from(options.block_size.bytes());
    let container_bytes = blocks.saturating_mul(block_size);
    let mut planner = match ContentPlanner::new(&plan_request(options, container_bytes)) {
        Ok(planner) => planner,
        Err(e) => return classify(e),
    };
    let volumes = match place_volumes(models, options, time, &mut planner) {
        Ok(volumes) => volumes,
        Err(FormatError::Geometry(e)) => return classify(e),
        Err(e) => return Probe::TooSmall(e),
    };
    let layout = planner.finish();
    if !leaves_room(&layout, slack, block_size) {
        return Probe::Tight;
    }
    Probe::Fits(Fitted {
        container_bytes,
        layout,
        volumes,
    })
}

/// Whether `layout` leaves the room `slack` asks for: [`Slack::None`] asks for none, and any
/// other slack for that many blocks a process of any user can write, past all macOS keeps
/// free, so that even a slack of no bytes is a container macOS writes to.
fn leaves_room(layout: &ApfsLayout, slack: Slack, block_size: u64) -> bool {
    slack == Slack::None
        || layout.free_blocks()
            >= macos_reserve(layout.block_count, block_size)
                + slack.required_free(layout.block_count, block_size)
}

/// A smallest container that holds `models` with the room `slack` asks for, formatted with
/// `options` at `time`, and what it planned: one block smaller does not hold them.
///
/// # Errors
///
/// [`FormatError::SlackShareTooLarge`] for a share past the limit,
/// [`FormatError::DoesNotFit`] when the largest container the search may try was placed and
/// left too little room, and otherwise the failure the largest size tried met.
pub(super) fn search(
    models: &[ApfsModel],
    options: &FormatOptions,
    time: i64,
    slack: Slack,
) -> Result<Fitted, FormatError> {
    if let Some(hundredths) = slack.share_over_limit() {
        return Err(FormatError::SlackShareTooLarge {
            hundredths,
            limit: Slack::MAX_SHARE,
        });
    }
    let block_size = u64::from(options.block_size.bytes());
    let ceiling = MAX_CONTAINER_BYTES / block_size;
    let does_not_fit = FormatError::DoesNotFit {
        ceiling: ceiling * block_size,
    };
    // Room the largest container could not leave is room no smaller one leaves either, so it
    // is answered before a probe plans a container of that size to find out.
    if slack != Slack::None
        && slack.required_free(ceiling, block_size) + macos_reserve(ceiling, block_size) >= ceiling
    {
        return Err(does_not_fit);
    }
    let floor = content_floor(models, block_size)
        .max(MIN_BLOCK_COUNT)
        .min(ceiling);
    match crate::sizing::bracket(floor, ceiling, |blocks| {
        probe(models, options, time, slack, blocks)
    }) {
        Ok((_, fitted)) => Ok(fitted),
        Err(Some(e)) => Err(e),
        Err(None) => Err(does_not_fit),
    }
}

/// The blocks the volumes' streams alone occupy, before any of the container's own objects:
/// a count the answer is above, since a container holds its streams and more.
fn content_floor(models: &[ApfsModel], block_size: u64) -> u64 {
    models
        .iter()
        .flat_map(|model| &model.streams)
        .map(|stream| stream.len.div_ceil(block_size))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs::ondisk::SpaceManager;
    use crate::apfs::{
        BlockSize, FormatPlan, Image, NameKind, Reader, VolumeName, VolumeRequest, format,
    };
    use crate::source::{Metadata, Source, TreeBuilder};
    use crate::time::Timestamp;

    const TIME: Timestamp = Timestamp::from_secs(1_700_000_000);

    fn opts() -> FormatOptions {
        let volume = VolumeRequest::new(VolumeName::new("Data").expect("a name"), [0x22; 16])
            .names(NameKind::CaseKeeping);
        FormatOptions::new([0x11; 16], TIME, volume)
    }

    /// A tree of `count` files of `bytes` each, under one directory.
    fn tree(count: usize, bytes: usize) -> TreeBuilder {
        let mut builder = TreeBuilder::new().directory("/data", Metadata::new(0o755, TIME));
        for i in 0..count {
            builder = builder.file(
                format!("/data/f{i}"),
                vec![b'x'; bytes],
                Metadata::new(0o644, TIME),
            );
        }
        builder
    }

    /// The failure a fit meets, for a test that expects one: a plan holds whole models and so
    /// is not `Debug`, which `expect_err` would want.
    fn fit_err(source: impl Source, options: FormatOptions, slack: Slack) -> FormatError {
        match FormatPlan::fit(source, options, slack) {
            Ok(plan) => panic!(
                "expected a failure, fitted {} bytes",
                plan.container_bytes()
            ),
            Err(e) => e,
        }
    }

    /// The blocks the newest space manager of `image` records free, read back off its bytes.
    fn free_read_back(image: &Image) -> u64 {
        let layout = image.layout();
        let size = usize::try_from(layout.block_size).expect("a block fits memory");
        let at = usize::try_from(layout.newest().space_manager).expect("fits") * size;
        let len = usize::try_from(layout.space_manager.blocks).expect("fits") * size;
        let manager =
            SpaceManager::read_from(&image.as_bytes()[at..at + len]).expect("a space manager");
        manager.devices[SpaceManager::MAIN].free_count
    }

    #[test]
    fn a_fitted_size_formats_and_one_block_less_does_not() {
        // The whole contract of the search: what it returns is a size that formats, and the
        // block below it does not.
        for (count, bytes) in [(0, 0), (1, 1), (16, 4096), (40, 100_000)] {
            let plan = FormatPlan::fit(tree(count, bytes), opts(), Slack::None).expect("fit");
            let size = plan.container_bytes();
            assert_eq!(size % 4096, 0, "{count}x{bytes}: a whole number of blocks");
            format(tree(count, bytes), size, opts())
                .unwrap_or_else(|e| panic!("{count}x{bytes}: the fitted {size} bytes: {e}"));
            assert!(
                FormatPlan::new(tree(count, bytes), size - 4096, opts()).is_err(),
                "{count}x{bytes}: one block below the fitted {size} bytes planned too"
            );
        }
    }

    #[test]
    fn the_fitted_plan_is_the_plan_a_format_of_its_size_makes() {
        // What the search carries out of its winning probe is written as it is, so it has to be
        // the plan `new` makes at that size, byte for byte.
        let source = || tree(24, 9000);
        let plan = FormatPlan::fit(source(), opts(), Slack::None).expect("fit");
        let size = plan.container_bytes();
        let mut fitted = std::io::Cursor::new(Vec::new());
        plan.write_to(&mut fitted).expect("write");
        let named = format(source(), size, opts()).expect("format at the fitted size");
        assert!(
            fitted.into_inner() == named.as_bytes(),
            "the fitted plan wrote other bytes than a format of {size} bytes"
        );
        assert_eq!(plan.layout(), named.layout());
    }

    #[test]
    fn a_fitted_container_reads_back_with_its_contents_and_scans_clean() {
        let plan = FormatPlan::fit(tree(8, 5000), opts(), Slack::None).expect("fit");
        let image = format(tree(8, 5000), plan.container_bytes(), opts()).expect("format");
        let mut reader = Reader::open(std::io::Cursor::new(image.as_bytes())).expect("open");
        let node = reader
            .lookup(b"/data/f7")
            .expect("the last file is present");
        assert_eq!(reader.read_data(&node).expect("read"), vec![b'x'; 5000]);
        assert!(
            reader.scan().anomalies().is_empty(),
            "{:?}",
            reader.scan().anomalies()
        );
    }

    #[test]
    fn slack_is_room_any_user_writes_and_the_block_below_leaves_less() {
        // Slack is measured on the image: what its space manager records free once every block
        // is placed, less what macOS keeps free before a write. And it is a floor the search
        // does not overshoot.
        let source = || tree(32, 20_000);
        for slack in [Slack::Bytes(8 << 20), Slack::Share(2500), Slack::Bytes(0)] {
            let plan = FormatPlan::fit(source(), opts(), slack).expect("fit");
            let size = plan.container_bytes();
            let image = format(source(), size, opts()).expect("format");
            let free = free_read_back(&image);
            assert_eq!(
                free,
                plan.layout().free_blocks(),
                "{slack:?}: the plan's count"
            );
            let blocks = size / 4096;
            let reserve = macos_reserve(blocks, 4096);
            assert_eq!(
                plan.layout().writable_blocks(),
                free - reserve,
                "{slack:?}: the writable count"
            );
            assert!(
                free >= reserve + slack.required_free(blocks, 4096),
                "{slack:?}: {free} free of {blocks} blocks"
            );
            let short = match FormatPlan::new(source(), size - 4096, opts()) {
                Err(_) => true,
                Ok(below) => !leaves_room(below.layout(), slack, 4096),
            };
            assert!(short, "{slack:?}: one block below the fit satisfied it too");
        }
    }

    #[test]
    fn what_macos_keeps_free_is_its_ask_and_margin_at_every_size() {
        // The margin for a process of any user, as macOS 15, 26 and 27 printed it beside every
        // change they refused, the most a write of a mebibyte asked for beside it, and the
        // largest room ahead of a growing file with the most a transaction held, 4,095 and 143.
        for (blocks, margin) in [
            (1152, 125),
            (3293, 132),
            (122_934, 2458),
            (402_141, 8021),
            (414_165, 8096),
            (2_008_944, 8096),
        ] {
            for (block_size, ask) in [(4096, 172 + 256), (16_384, 172 + 64), (65_536, 172 + 16)] {
                assert_eq!(
                    macos_reserve(blocks, block_size),
                    ask + margin + 4095 + 143,
                    "{blocks} blocks of {block_size}"
                );
            }
        }
    }

    #[test]
    fn no_slack_leaves_a_container_with_almost_nothing_free() {
        // A fitted container has room for very little more, which is what makes slack worth
        // having. The tree is larger than the smallest container, so its contents decide the
        // size rather than the floor.
        let plan = FormatPlan::fit(tree(64, 200_000), opts(), Slack::None).expect("fit");
        assert!(plan.layout().block_count > MIN_BLOCK_COUNT);
        assert!(
            plan.layout().free_blocks() * 50 < plan.layout().block_count,
            "{} of {} blocks free is not a fitted container",
            plan.layout().free_blocks(),
            plan.layout().block_count
        );
    }

    #[test]
    fn every_block_size_and_a_second_volume_fit() {
        // A second volume needs a slot, and a container has one for every 512 MiB or part of
        // it, so the search has to climb past every size with one slot.
        for size in BlockSize::ALL {
            let options = opts().block_size(size).volume(VolumeRequest::new(
                VolumeName::new("Second").expect("a name"),
                [0x33; 16],
            ));
            let plan = FormatPlan::fit(tree(6, 3000), options.clone(), Slack::None)
                .unwrap_or_else(|e| panic!("{size:?}: {e}"));
            let bytes = plan.container_bytes();
            let block = u64::from(size.bytes());
            assert_eq!(bytes % block, 0);
            assert!(bytes > 512 << 20, "{size:?}: {bytes} bytes has two slots");
            assert!(
                FormatPlan::new(tree(6, 3000), bytes - block, options).is_err(),
                "{size:?}: one block below {bytes} planned too"
            );
        }
    }

    #[test]
    fn a_share_past_the_limit_is_refused_before_a_probe() {
        let e = fit_err(tree(1, 1), opts(), Slack::Share(Slack::MAX_SHARE + 1));
        assert!(matches!(
            e,
            FormatError::SlackShareTooLarge {
                hundredths: 9001,
                limit: 9000
            }
        ));
    }

    #[test]
    fn room_no_container_leaves_is_refused_as_not_fitting() {
        let e = fit_err(tree(1, 1), opts(), Slack::Bytes(MAX_CONTAINER_BYTES));
        assert!(
            matches!(e, FormatError::DoesNotFit { ceiling } if ceiling == MAX_CONTAINER_BYTES),
            "{e}"
        );
    }

    #[test]
    fn what_no_size_changes_is_refused_as_new_refuses_it() {
        // A source the volume cannot hold is refused before any size is tried, by the model.
        let source = TreeBuilder::new().file("/bad\u{FFFF}", "x", Metadata::new(0o644, TIME));
        assert!(matches!(
            fit_err(source, opts(), Slack::None),
            FormatError::Model(_)
        ));
        let mut options = opts();
        options.volumes[0].uuid = [0; 16];
        assert!(matches!(
            fit_err(tree(1, 1), options, Slack::None),
            FormatError::ZeroIdentifier { .. }
        ));
    }

    #[test]
    fn the_refusals_point_where_a_larger_container_answers_them() {
        assert!(matches!(
            classify(GeometryError::ContainerTooLarge { bytes: 0 }),
            Probe::Exhausted(_)
        ));
        assert!(matches!(
            classify(GeometryError::NoVolumes),
            Probe::Impossible(_)
        ));
        for e in [
            GeometryError::ContainerTooSmall {
                bytes: 0,
                block_size: 4096,
                block_count: 0,
            },
            GeometryError::TooManyVolumes {
                bytes: 0,
                volumes: 2,
                max_volumes: 1,
            },
            GeometryError::ContainerFull { bytes: 0, free: 0 },
        ] {
            assert!(matches!(classify(e), Probe::TooSmall(_)), "{e}");
        }
    }
}
