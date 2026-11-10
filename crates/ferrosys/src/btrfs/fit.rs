//! Sizing a btrfs to what goes in it: the search behind
//! [`FormatPlan::fit`](crate::btrfs::FormatPlan::fit).
//!
//! The bracket itself is [`crate::sizing`]. What this module supplies is everything about it
//! that is btrfs's: the unit a candidate is counted in, what a probe does, which direction each
//! refusal points in, and what a candidate leaves free.
//!
//! **The unit is a sector**, the granularity a device's length is recorded at. A candidate is
//! planned whole, chunks and reservation, from the tree's summary alone, so a probe is
//! arithmetic and the tree is built once.

use crate::btrfs::geometry::{
    BtrfsLayout, GeometryError, PlanRequest, RESERVED_HEAD, block_sizes, minimum_volume_bytes,
    mirror_windows, plan_layout,
};
use crate::btrfs::materialize::FormatError;
use crate::btrfs::ondisk::BlockGroupFlags;
use crate::sizing::{Probe, Slack};

/// Which way a planning refusal points.
///
/// A size too small for the profiles, or for the content's chunks, is answered by a larger one;
/// so is a chunk map too large, since a larger volume can take longer replicated data chunks.
/// A block size or a feature the format does not have is answered by no size.
fn classify(e: GeometryError) -> Probe<BtrfsLayout, FormatError> {
    match e {
        GeometryError::VolumeTooSmall { .. }
        | GeometryError::ContentTooLarge { .. }
        | GeometryError::ChunkMapTooLarge { .. } => Probe::TooSmall(FormatError::Geometry(e)),
        _ => Probe::Impossible(FormatError::Geometry(e)),
    }
}

/// Bytes of file data a writer could still store in `layout`: the room left in its data
/// chunks, less the windows superblock copies take from them, and the device space no chunk
/// claims past the reserved head, shared out between the data profile's copies.
fn free_bytes(layout: &BtrfsLayout, request: &PlanRequest) -> u64 {
    let windows = |chunk: &crate::btrfs::MappedChunk| {
        mirror_windows(chunk, &layout.superblock_mirrors).len() as u64
            * crate::btrfs::geometry::STRIPE_LEN
    };
    let capacity: u64 = layout
        .chunks_of(BlockGroupFlags::DATA)
        .map(|chunk| chunk.length.saturating_sub(windows(chunk)))
        .sum();
    let in_chunks = capacity.saturating_sub(request.content.data_bytes);
    let unallocated = layout
        .volume_bytes
        .saturating_sub(RESERVED_HEAD)
        .saturating_sub(layout.device_bytes_used());
    in_chunks + unallocated / request.data_profile.copies()
}

/// Plan one candidate of `sectors` sectors and judge what it leaves free.
fn probe(
    request: &PlanRequest,
    slack: Slack,
    sector: u64,
    sectors: u64,
) -> Probe<BtrfsLayout, FormatError> {
    let mut candidate = *request;
    candidate.volume_bytes = sectors.saturating_mul(sector);
    let layout = match plan_layout(&candidate) {
        Ok(layout) => layout,
        Err(e) => return classify(e),
    };
    // Slack is measured in sectors, the unit a filesystem's free space is counted in here.
    let free = free_bytes(&layout, &candidate) / sector;
    if free < slack.required_free(sectors, sector) {
        Probe::Tight
    } else {
        Probe::Fits(layout)
    }
}

/// The smallest filesystem that holds what `request` describes with `slack` free.
///
/// # Errors
///
/// [`FormatError::SlackShareTooLarge`] for a share past the limit,
/// [`FormatError::DoesNotFit`] when no size holds the tree with the room asked for, and
/// otherwise the failure the search met.
pub(crate) fn search(request: &PlanRequest, slack: Slack) -> Result<BtrfsLayout, FormatError> {
    if let Some(hundredths) = slack.share_over_limit() {
        return Err(FormatError::SlackShareTooLarge {
            hundredths,
            limit: Slack::MAX_SHARE,
        });
    }
    let (sector_size, _) = block_sizes(request)?;
    let sector = u64::from(sector_size);
    // Nothing smaller than the profiles' own minimum plans, and nothing smaller than the
    // file data is worth probing.
    let floor = minimum_volume_bytes(request.metadata_profile, request.data_profile)
        .max(request.content.data_bytes)
        .div_ceil(sector);
    let ceiling = u64::MAX / sector;
    match crate::sizing::bracket(floor, ceiling, |sectors| {
        probe(request, slack, sector, sectors)
    }) {
        Ok((_, layout)) => Ok(layout),
        Err(Some(e)) => Err(e),
        Err(None) => Err(FormatError::DoesNotFit {
            ceiling: ceiling.saturating_mul(sector),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::materialize::{FormatOptions, FormatPlan};
    use crate::btrfs::{Profile, Reader};
    use crate::source::{Metadata, TreeBuilder};
    use crate::time::Timestamp;

    const TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    fn opts() -> FormatOptions {
        FormatOptions::new([0x11; 16], TIME)
    }

    /// `/d` holding `files` files of `each` bytes.
    fn tree(files: usize, each: usize) -> TreeBuilder {
        let mut b = TreeBuilder::new().directory(b"/d".to_vec(), Metadata::new(0o755, TIME));
        for i in 0..files {
            b = b.file(
                format!("/d/f{i:05}").into_bytes(),
                vec![(i % 251) as u8; each],
                Metadata::new(0o644, TIME),
            );
        }
        b
    }

    #[test]
    fn a_fitted_size_formats_and_one_sector_less_does_not() {
        let plan = FormatPlan::fit(tree(20, 3 << 20), opts(), Slack::None).expect("fit");
        let bytes = plan.volume_bytes();
        let sector = u64::from(plan.layout().sector_size);
        assert!(FormatPlan::new(tree(20, 3 << 20), bytes, opts()).is_ok());
        assert!(FormatPlan::new(tree(20, 3 << 20), bytes - sector, opts()).is_err());
        let mut out = std::io::Cursor::new(Vec::new());
        plan.write_to(&mut out).expect("write");
        let mut r =
            Reader::open(std::io::Cursor::new(out.into_inner())).expect("a strict read of it");
        assert_eq!(
            r.walk().expect("walk").len(),
            22,
            "the root, the directory, the files"
        );
    }

    #[test]
    fn an_empty_tree_fits_the_profiles_own_minimum() {
        let plan = FormatPlan::fit(TreeBuilder::new(), opts(), Slack::None).expect("fit");
        assert_eq!(
            plan.volume_bytes(),
            minimum_volume_bytes(Profile::Dup, Profile::Single)
        );
    }

    #[test]
    fn slack_is_room_for_file_data_the_filesystem_has() {
        let tight = FormatPlan::fit(tree(10, 1 << 20), opts(), Slack::None).expect("fit");
        let roomy =
            FormatPlan::fit(tree(10, 1 << 20), opts(), Slack::Bytes(256 << 20)).expect("fit");
        assert!(roomy.volume_bytes() > tight.volume_bytes());
        let mut request = opts().plan;
        request.content = roomy.content();
        assert!(free_bytes(roomy.layout(), &request) >= 256 << 20);
    }

    #[test]
    fn a_share_past_the_limit_is_refused_before_any_search() {
        let err = FormatPlan::fit(tree(1, 1), opts(), Slack::Share(9500))
            .err()
            .expect("refused");
        assert!(
            matches!(err, FormatError::SlackShareTooLarge { .. }),
            "{err}"
        );
    }
}
