//! Sizing an exFAT volume to what goes in it: the search behind
//! [`FormatPlan::fit`](crate::exfat::FormatPlan::fit).
//!
//! The bracket itself is [`crate::sizing`]. What this module supplies is everything about it
//! that is exFAT's: the unit a candidate is counted in, where the accepted sizes lie, what a
//! probe does, and which direction each refusal points in.
//!
//! **The unit is a sector.** A volume is a whole number of sectors, and the cluster an
//! automatic request takes is derived from the volume's size, so a cluster is not a fixed
//! quantity to search in.
//!
//! **An automatic cluster size makes the accepted sizes a list of bands.** The conventional
//! cluster grows at 7 MiB, past 256 MiB and past 32 GiB, and a tree of many small files fits
//! a volume just below a step that a volume just above it, with eight times the cluster,
//! does not. A search over one range would climb past the smaller answer, so each band of one
//! cluster size is searched in turn and the first that holds the tree wins. A pinned cluster
//! size is one band.

use crate::exfat::geometry::{ClusterSize, ExfatLayout, GeometryError, PlanRequest, plan_layout};
use crate::exfat::materialize::{FormatError, FormatOptions};
use crate::exfat::model::{ModelError, PlacedTree};
use crate::sizing::{Probe, Slack};

/// One contiguous run of volume sizes, in sectors, that one cluster size covers.
type Band = (u64, u64);

/// The volume sizes, in bytes, at which the conventional cluster size changes: the first size
/// that takes the next cluster.
const CLUSTER_STEPS: [u64; 3] = [7 << 20, (256 << 20) + 1, (32 << 30) + 1];

/// The bands of volume sizes this request could be satisfied within, in sectors, smallest
/// first.
fn bands(request: &PlanRequest, floor: u64) -> Vec<Band> {
    let sector = u64::from(request.bytes_per_sector);
    let ceiling = u64::MAX / sector;
    if !matches!(request.cluster_size, ClusterSize::Auto) {
        return vec![(floor, ceiling)];
    }
    let mut bands = Vec::new();
    let mut low = floor;
    for step in CLUSTER_STEPS {
        // The first whole number of sectors that reaches the step.
        let first = step.div_ceil(sector);
        if first > low {
            bands.push((low, first - 1));
            low = first;
        }
    }
    bands.push((low, ceiling));
    bands
}

/// Which way a planning refusal points.
///
/// Only one is upward-closed: more clusters than a cluster number addresses, which a larger
/// volume at the same cluster size makes worse. Everything else a size can answer is answered
/// by a larger one.
fn classify(e: GeometryError) -> Probe<ExfatLayout, FormatError> {
    match e {
        GeometryError::TooManyClusters { .. } => Probe::Exhausted(FormatError::Geometry(e)),
        GeometryError::SectorSizeUnsupported { .. }
        | GeometryError::ClusterSizeUnsupported { .. }
        | GeometryError::ClusterTooLarge { .. }
        | GeometryError::BoundaryAlignUnsupported { .. } => {
            Probe::Impossible(FormatError::Geometry(e))
        }
        _ => Probe::TooSmall(FormatError::Geometry(e)),
    }
}

/// Plan one candidate and allocate the tree into it. Nothing is written and no file is read.
fn probe(
    tree: &mut PlacedTree,
    options: &FormatOptions,
    slack: Slack,
    sectors: u64,
) -> Probe<ExfatLayout, FormatError> {
    let mut request = options.plan;
    request.volume_bytes = sectors.saturating_mul(u64::from(request.bytes_per_sector));
    let layout = match plan_layout(&request) {
        Ok(layout) => layout,
        Err(e) => return classify(e),
    };
    let used = match tree.allocate(&layout) {
        Ok(used) => used,
        Err(e @ ModelError::VolumeFull { .. }) => return Probe::TooSmall(FormatError::Model(e)),
        // A directory too large, a name, a time: properties of the tree, which no size fixes.
        Err(e) => return Probe::Impossible(FormatError::Model(e)),
    };
    // Slack is measured in clusters, the unit the volume's own free count is in.
    let free = u64::from(layout.cluster_count - used);
    let required = slack.required_free(
        u64::from(layout.cluster_count),
        u64::from(layout.bytes_per_cluster),
    );
    if free < required {
        Probe::Tight
    } else {
        Probe::Fits(layout)
    }
}

/// The volume the search settled on, with the tree allocated against it last.
#[derive(Debug)]
pub(crate) struct Fitted {
    pub(crate) layout: ExfatLayout,
    pub(crate) used_clusters: u32,
}

/// The smallest volume that holds `tree` with `slack` free, and what it planned.
///
/// # Errors
///
/// [`FormatError::SlackShareTooLarge`] for a share past the limit,
/// [`FormatError::DoesNotFit`] when no band held the tree with the room asked for, and
/// otherwise the failure the search met.
pub(crate) fn search(
    tree: &mut PlacedTree,
    options: &FormatOptions,
    slack: Slack,
) -> Result<Fitted, FormatError> {
    if let Some(hundredths) = slack.share_over_limit() {
        return Err(FormatError::SlackShareTooLarge {
            hundredths,
            limit: Slack::MAX_SHARE,
        });
    }
    let sector = u64::from(options.plan.bytes_per_sector);
    let floor = tree.content_sectors(sector).max(1);
    let mut refusal = None;
    for (low, high) in bands(&options.plan, floor) {
        match crate::sizing::bracket(low, high, |sectors| probe(tree, options, slack, sectors)) {
            Ok((_, layout)) => {
                // Every probe allocates into the one tree, and the bracket's last probe need
                // not be its answer, so the answer is allocated again before the tree is read.
                let used_clusters = tree.allocate(&layout)?;
                return Ok(Fitted {
                    layout,
                    used_clusters,
                });
            }
            // A band that could not hold the tree leaves the next one to try; a refusal no
            // size changes ends the search.
            Err(Some(FormatError::Model(e))) if !matches!(e, ModelError::VolumeFull { .. }) => {
                return Err(FormatError::Model(e));
            }
            Err(Some(e)) => refusal = Some(e),
            Err(None) => {}
        }
    }
    Err(refusal.unwrap_or(FormatError::DoesNotFit {
        ceiling: (u64::MAX / sector).saturating_mul(sector),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exfat::geometry::conventional_cluster_size;
    use crate::exfat::materialize::FormatPlan;
    use crate::source::{Metadata, TreeBuilder};
    use crate::time::Timestamp;

    const TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    fn opts() -> FormatOptions {
        FormatOptions::new(0x1234_5678).accepted_loss(crate::AcceptedLoss::ALL)
    }

    /// `/d` holding `files` files of `each` bytes.
    fn tree(files: usize, each: usize) -> TreeBuilder {
        let mut b = TreeBuilder::new().directory(b"/d".to_vec(), Metadata::new(0o755, TIME));
        for i in 0..files {
            b = b.file(
                format!("/d/f{i:05}").into_bytes(),
                vec![0xAB; each],
                Metadata::new(0o644, TIME),
            );
        }
        b
    }

    #[test]
    fn the_bands_follow_the_conventional_cluster_size() {
        // Within a band the cluster is one size, and it changes at every band's start.
        let request = PlanRequest::new(0);
        let bands = bands(&request, 1);
        assert_eq!(bands.len(), 4);
        for pair in bands.windows(2) {
            assert_eq!(pair[0].1 + 1, pair[1].0, "the bands meet");
            let below = conventional_cluster_size(pair[0].1 * 512);
            let above = conventional_cluster_size(pair[1].0 * 512);
            assert!(above > below, "{pair:?}");
        }
        for (low, high) in &bands[..3] {
            assert_eq!(
                conventional_cluster_size(low * 512),
                conventional_cluster_size(high * 512)
            );
        }
        let pinned = PlanRequest::new(0).cluster_size(ClusterSize::Bytes(4096));
        assert_eq!(super::bands(&pinned, 9).len(), 1);
    }

    #[test]
    fn a_fitted_size_formats_and_one_sector_less_does_not() {
        let plan = FormatPlan::fit(tree(40, 3000), opts(), Slack::None).expect("fit");
        let bytes = plan.volume_bytes();
        assert!(FormatPlan::new(tree(40, 3000), bytes, opts()).is_ok());
        let sector = u64::from(plan.layout().bytes_per_sector);
        assert!(FormatPlan::new(tree(40, 3000), bytes - sector, opts()).is_err());
        let mut out = std::io::Cursor::new(Vec::new());
        plan.write_to(&mut out).expect("write");
        let mut r = crate::exfat::Reader::open(std::io::Cursor::new(out.into_inner()))
            .expect("a strict read of the fitted volume");
        assert_eq!(r.walk().expect("walk").len(), 41);
    }

    #[test]
    fn slack_is_free_room_the_volume_has() {
        let tight = FormatPlan::fit(tree(10, 5000), opts(), Slack::None).expect("fit");
        let roomy = FormatPlan::fit(tree(10, 5000), opts(), Slack::Bytes(4 << 20)).expect("fit");
        assert!(roomy.volume_bytes() > tight.volume_bytes());
        let free = u64::from(roomy.free_clusters()) * u64::from(roomy.layout().bytes_per_cluster);
        assert!(free >= 4 << 20, "{free} bytes free");
    }

    #[test]
    fn a_tree_just_below_a_cluster_step_is_not_fitted_past_it() {
        // 60,000 files of one byte take a 4 KiB cluster each below 256 MiB and a 32 KiB one
        // above it, where they need nearly 2 GiB. The answer is the volume below the step.
        let plan = FormatPlan::fit(tree(60_000, 1), opts(), Slack::None).expect("fit");
        assert!(plan.volume_bytes() <= 256 << 20, "{}", plan.volume_bytes());
        assert_eq!(plan.layout().bytes_per_cluster, 4096);
    }
}
