//! Sizing a FAT volume to what goes in it: the search behind
//! [`FormatPlan::fit`](crate::fat::FormatPlan::fit).
//!
//! The bracket itself is [`crate::sizing`]. What this module supplies is everything about it
//! that is FAT's: the unit a candidate is counted in, where the accepted sizes lie, what a
//! probe does, and which direction each refusal points in.
//!
//! **The unit is a sector, and it has to be.** A volume is an integer number of sectors and
//! the sector size is an input, but the cluster size is *derived* from the volume size — so a
//! cluster is not a fixed quantity to search in, and a byte-granular search would bisect
//! within one layout for no gain. A sector is the finest step that changes an answer.
//!
//! **The accepted sizes are a short list of bands rather than one range.** For most requests
//! there is exactly one band. For [`FatTypeRequest::Auto`] there are two, because the type
//! derivation changes at half a gibibyte: below it a volume may come out FAT12 or FAT16, and
//! at or above it the request becomes FAT32 outright and must clear FAT32's cluster minimum.
//! With a pinned cluster size those two bands do not meet — the sizes between the largest
//! FAT16 a pinned cluster reaches and the smallest FAT32 it reaches are all refused — and a
//! search that treated the domain as one range would climb straight through the gap and
//! answer with a volume many times larger than the smallest one that works. Each band is
//! searched separately and the smaller success wins.

use crate::fat::geometry::{
    FAT32_AUTO_THRESHOLD_BYTES, FatLayout, FatTypeRequest, GeometryError, PlanRequest, plan_layout,
};
use crate::fat::materialize::{FormatError, FormatOptions};
use crate::fat::model::{ModelError, PlacedTree};
use crate::sizing::{Probe, Slack};

/// The volume the search settled on: the geometry it planned and what the tree occupies in
/// it.
///
/// The counts are deliberately not something a probe carries out. Every probe allocates into
/// the one shared tree, so the tree's cluster runs belong to whichever candidate ran last —
/// which the bracket does not promise is the one it returns. Counts taken from a probe could
/// therefore describe a different geometry than the runs the model would be finished from.
/// [`settle`] is the only thing that builds this, and it builds it from an allocation of the
/// winning layout, so the layout, the counts, and the tree all describe one volume.
#[derive(Debug)]
pub(crate) struct Fitted {
    pub(crate) layout: FatLayout,
    pub(crate) used_clusters: u32,
    pub(crate) next_free: u32,
}

/// One contiguous run of volume sizes, in sectors, that one type derivation covers.
type Band = (u64, u64);

/// The largest volume any FAT type addresses, in sectors — the sector count itself is a
/// 32-bit field, so nothing beyond it is nameable however the clusters work out.
const MAX_SECTORS: u64 = u32::MAX as u64;

/// The bands of volume sizes this request could be satisfied within, in sectors.
///
/// One band for every request but [`FatTypeRequest::Auto`], which has two: the derivation
/// changes at [`FAT32_AUTO_THRESHOLD_BYTES`], and with a pinned cluster size the two do not
/// meet.
fn bands(request: &PlanRequest, floor: u64) -> Vec<Band> {
    let sector = u64::from(request.bytes_per_sector);
    let threshold = FAT32_AUTO_THRESHOLD_BYTES.div_ceil(sector);
    let whole: Band = (floor, MAX_SECTORS);
    match request.fat_type {
        // Below the threshold the derivation may reach FAT12 or FAT16; at or above it the
        // request is rewritten to FAT32. Searched as two bands, smaller answer first.
        FatTypeRequest::Auto if threshold > floor => {
            vec![(floor, threshold - 1), (threshold, MAX_SECTORS)]
        }
        _ => vec![whole],
    }
}

/// Which way a planning refusal points.
///
/// Only two are upward-closed, and both are provable rather than guessed: `plan_layout`
/// reports [`GeometryError::ClustersAboveMaximum`] only after its cluster-size sweep has run
/// to the largest cluster it may use, so no larger volume has a larger cluster to escape
/// into; and a volume past [`MAX_SECTORS`] cannot be named at all.
fn classify(e: GeometryError) -> Probe<FatLayout, FormatError> {
    match e {
        GeometryError::ClustersAboveMaximum { .. } | GeometryError::VolumeTooLarge { .. } => {
            Probe::Exhausted(FormatError::Geometry(e))
        }
        // Refused for something no volume size changes. `PlanRequest::validate` catches these
        // before the search starts, so this arm is depth rather than a path a caller reaches.
        GeometryError::SectorSizeUnsupported { .. }
        | GeometryError::FatCountUnsupported { .. }
        | GeometryError::ClusterSizeUnsupported { .. }
        | GeometryError::ClusterTooLarge { .. } => Probe::Impossible(FormatError::Geometry(e)),
        _ => Probe::TooSmall(FormatError::Geometry(e)),
    }
}

/// Plan one candidate and allocate the tree into it.
///
/// Nothing is written and no file is read: the tree's clusters follow from each file's
/// declared length, which is what makes a probe cost arithmetic rather than a format.
fn probe(
    tree: &mut PlacedTree,
    options: &FormatOptions,
    slack: Slack,
    sectors: u64,
) -> Probe<FatLayout, FormatError> {
    let sector = u64::from(options.plan.bytes_per_sector);
    let mut request = options.plan;
    request.volume_bytes = sectors.saturating_mul(sector);

    let layout = match plan_layout(&request) {
        Ok(layout) => layout,
        Err(e) => return classify(e),
    };
    // The counts are the probe's own verdict on the candidate and go no further: what the
    // tree ends up allocated against is settled once, after the search.
    let (used_clusters, _) = match tree.allocate(&layout, &options.model_config()) {
        Ok(counts) => counts,
        // A tree larger than the volume, or a root region too small for its entries: both
        // are answered by a larger volume.
        Err(e @ (ModelError::VolumeFull { .. } | ModelError::RootDirectoryFull { .. })) => {
            return Probe::TooSmall(FormatError::Model(e));
        }
        // Anything else is a property of the tree, not of the volume — a name, a shape, a
        // time out of range, a loss the caller did not accept. No size fixes it.
        Err(e) => return Probe::Impossible(FormatError::Model(e)),
    };

    // Slack is measured in the unit the volume's own free count carries, which for this
    // family is a cluster.
    let free = u64::from(layout.clusters - used_clusters);
    if free
        < slack.required_free(
            u64::from(layout.clusters),
            u64::from(layout.bytes_per_cluster()),
        )
    {
        return Probe::Tight;
    }
    Probe::Fits(layout)
}

/// The smallest volume that holds `tree` with `slack` free, in sectors, and what it planned.
///
/// # Errors
///
/// [`FormatError::SlackShareTooLarge`] for a share past the limit,
/// [`FormatError::DoesNotFit`] when every band was searched and none held the tree with the
/// room asked for, and otherwise the failure the search met.
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
    // Refused once here rather than found again at every candidate, and reported as what it
    // is rather than as a size that could not be found.
    options.plan.validate()?;

    let sector = u64::from(options.plan.bytes_per_sector);
    let floor = content_floor(tree, options).max(1);
    let mut last: Option<FormatError> = None;

    // Smallest band first, and the first success wins: within a band the bracket returns the
    // smallest fitting size, and the bands ascend, so the first answer is the smallest there
    // is. A band that refuses does not stop the search — the next one may hold the tree.
    for (lo, hi) in bands(&options.plan, floor) {
        match crate::sizing::bracket(lo, hi, |sectors| probe(tree, options, slack, sectors)) {
            Ok((_, layout)) => return settle(tree, options, layout),
            Err(Some(e @ FormatError::Model(ModelError::VolumeFull { .. }))) => last = Some(e),
            // A refusal no size changes is the whole answer, whatever the other bands say.
            Err(Some(e @ (FormatError::Geometry(_) | FormatError::Model(_)))) => last = Some(e),
            Err(Some(e)) => return Err(e),
            Err(None) => {}
        }
    }
    Err(last.unwrap_or(FormatError::DoesNotFit {
        ceiling: MAX_SECTORS.saturating_mul(sector),
    }))
}

/// Leave the tree allocated against the layout that won.
///
/// Every probe allocates into the shared tree, and the probe the bracket stops on is not
/// necessarily the one it returns: a bisection ends the moment the range closes, which is
/// routinely on a candidate that did not fit. The tree's cluster runs are then that
/// candidate's while the layout handed back is the winner's, and the two disagree whenever
/// the candidates differed in cluster size or FAT width — which every search band contains a
/// transition of. A materializer taking chains and directory `first_cluster` fields from one
/// and sector arithmetic from the other writes a volume no driver can follow.
///
/// So the winner is allocated last, always, and the counts come from that pass rather than
/// from the probe — which is why a probe carries a layout and nothing else. It is one
/// arithmetic pass over the placed tree, no file read and nothing written, and it cannot fail:
/// this same layout and this same tree already allocated successfully inside the probe that
/// returned the layout. The result is propagated rather than unwrapped all the same, because a
/// failure here would mean allocation is not the pure function of layout and tree it is
/// documented to be, and that is worth reporting rather than panicking over.
fn settle(
    tree: &mut PlacedTree,
    options: &FormatOptions,
    layout: FatLayout,
) -> Result<Fitted, FormatError> {
    let (used_clusters, next_free) = tree.allocate(&layout, &options.model_config())?;
    Ok(Fitted {
        layout,
        used_clusters,
        next_free,
    })
}

/// The clusters the contents alone would occupy, converted to a sector count that cannot be
/// above the answer.
///
/// A floor only has to be a size the answer is at or above; it exists to save the climb
/// through sizes nothing could fit in. The conversion deliberately understates: the smallest
/// cluster is one sector, so counting each file's bytes in sectors is a bound whatever the
/// derivation picks.
fn content_floor(tree: &PlacedTree, options: &FormatOptions) -> u64 {
    let sector = u64::from(options.plan.bytes_per_sector);
    tree.content_sectors(sector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat::geometry::{ClusterSize, FatType};
    use crate::fat::materialize::FormatPlan;
    use crate::fat::model::place_tree;
    use crate::source::{Metadata, Source, TreeBuilder};
    use crate::time::Timestamp;

    const TIME: Timestamp = Timestamp::from_secs(1_426_325_212);

    fn opts() -> FormatOptions {
        FormatOptions::new(0x1234_5678, TIME).accept_all_loss()
    }

    /// A tree of `files` files of `each` bytes, plus a directory to hold them.
    fn tree(files: usize, each: usize) -> TreeBuilder {
        let mut b = TreeBuilder::new().directory(b"/d".to_vec(), Metadata::new(0o755, TIME));
        for i in 0..files {
            b = b.file(
                format!("/d/f{i:04}").into_bytes(),
                vec![0xAB; each],
                Metadata::new(0o644, TIME),
            );
        }
        b
    }

    fn fit(
        source: impl Source,
        options: FormatOptions,
        slack: Slack,
    ) -> Result<Fitted, FormatError> {
        let mut placed = place_tree(source.into_entries(), &options.model_config()).expect("place");
        search(&mut placed, &options, slack)
    }

    #[test]
    fn a_fitted_volume_formats_and_one_sector_less_does_not() {
        // The guarantee, at each way of asking for a type. Both ends are established by
        // probing, so it holds whether or not fit is monotone in size.
        for request in [
            FatTypeRequest::Auto,
            FatTypeRequest::Exactly(FatType::Fat12),
            FatTypeRequest::Exactly(FatType::Fat16),
            FatTypeRequest::Exactly(FatType::Fat32),
        ] {
            let options = opts().plan(PlanRequest::new(0).fat_type(request));
            let fitted = fit(tree(40, 3_000), options, Slack::None)
                .unwrap_or_else(|e| panic!("{request:?} does not fit: {e}"));
            let sector = u64::from(fitted.layout.bytes_per_sector);
            let bytes = u64::from(fitted.layout.total_sectors) * sector;

            FormatPlan::new(tree(40, 3_000), bytes, options)
                .unwrap_or_else(|e| panic!("{request:?} at the fitted size: {e}"));
            assert!(
                FormatPlan::new(tree(40, 3_000), bytes - sector, options).is_err(),
                "{request:?}: one sector below the fitted size must not hold the tree"
            );
        }
    }

    #[test]
    fn the_fitted_volume_is_exactly_the_filesystem() {
        // The smallest volume holding a tree is one whose last cluster is used, so it is
        // never inside the band the planner shortens a volume out of — and the size a caller
        // creates is the filesystem's own extent rather than that plus a remainder.
        for files in [1usize, 7, 40, 200] {
            let fitted = fit(tree(files, 5_000), opts(), Slack::None).expect("fits");
            let l = &fitted.layout;
            assert_eq!(
                u64::from(l.total_sectors) - u64::from(l.first_data_sector),
                u64::from(l.clusters) * u64::from(l.sectors_per_cluster),
                "a fitted volume has no tail past its last cluster ({files} files)"
            );
        }
    }

    #[test]
    fn a_pinned_cluster_size_with_an_auto_type_finds_the_lower_band() {
        // The defect the band split exists for, and it takes a tree of a particular size to
        // reach. With the cluster size pinned, `Auto` accepts a run of small volumes and a
        // run of large ones with a wide gap between: below half a gibibyte the derivation may
        // reach FAT16, and at or above it the request becomes FAT32 outright and must clear
        // 65525 clusters, which a 32 KiB cluster only reaches past 2 GiB. Every refusal in
        // that gap reads as "too small", so a search over one unbroken range climbs straight
        // through it and answers with the bottom of the upper band.
        //
        // A tree of about 300 MiB is what lands there: it needs more than half the lower
        // band and still fits inside it.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bulk");
        std::fs::write(&path, b"x").expect("write");
        let file = std::sync::Arc::new(std::fs::File::open(&path).expect("open"));
        let src = TreeBuilder::new().file(
            b"/bulk".to_vec(),
            crate::source::FileContent::Range(crate::source::FileRange::new(
                file,
                &path,
                0,
                300 << 20,
            )),
            Metadata::new(0o644, TIME),
        );

        let options = opts().plan(
            PlanRequest::new(0)
                .cluster_size(ClusterSize::Sectors(64))
                .fat_type(FatTypeRequest::Auto),
        );
        let fitted = fit(src, options, Slack::None).expect("fits");
        let bytes =
            u64::from(fitted.layout.total_sectors) * u64::from(fitted.layout.bytes_per_sector);
        assert!(
            bytes < FAT32_AUTO_THRESHOLD_BYTES,
            "the answer is in the lower band rather than the bottom of the upper one: \
             {bytes} bytes, {:?}",
            fitted.layout.fat_type
        );
        assert_ne!(fitted.layout.fat_type, FatType::Fat32);
    }

    #[test]
    fn the_tree_ends_the_search_allocated_against_the_layout_the_search_returns() {
        // The bracket ends on whichever candidate closed the range, which is routinely one
        // that did not fit — so the tree's cluster runs at that moment are that candidate's,
        // not the winner's. Here the wrong state is created deliberately, at a cluster size
        // the winner does not use, and `settle` has to make the tree the winner's again.
        // Without it the model would be finished from runs numbered for another geometry.
        let options =
            opts().plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat12)));
        let place =
            || place_tree(tree(64, 9_000).into_entries(), &options.model_config()).expect("place");
        let mut placed = place();
        let fitted = search(&mut placed, &options, Slack::None).expect("fits");
        // The same search over a second copy of the same tree, kept as the answer to compare
        // against. `finish` consumes the tree it was allocated into, so the comparison needs
        // two of them rather than a snapshot of one.
        let want = {
            let mut other = place();
            let f = search(&mut other, &options, Slack::None).expect("fits");
            other.finish(f.used_clusters, f.next_free).chain_ends()
        };

        // The same volume at twice the winner's cluster size: every run moves, and the tree
        // still allocates, so the wrong state is a complete one rather than a half-written
        // failure. Both are wrong in the same way.
        let bytes =
            u64::from(fitted.layout.total_sectors) * u64::from(fitted.layout.bytes_per_sector) * 2;
        let request = PlanRequest::new(bytes)
            .fat_type(FatTypeRequest::Exactly(FatType::Fat12))
            .cluster_size(ClusterSize::Sectors(fitted.layout.sectors_per_cluster * 2));
        let other = plan_layout(&request).expect("the doubled cluster plans");
        assert_ne!(
            other.sectors_per_cluster, fitted.layout.sectors_per_cluster,
            "the second geometry has to differ, or it proves nothing"
        );
        placed
            .allocate(&other, &options.model_config())
            .expect("allocating against the other geometry");

        let repaired = settle(&mut placed, &options, fitted.layout).expect("settle");
        assert_eq!(repaired.used_clusters, fitted.used_clusters);
        assert_eq!(repaired.next_free, fitted.next_free);
        assert_eq!(
            placed
                .finish(repaired.used_clusters, repaired.next_free)
                .chain_ends(),
            want,
            "the tree is the winner's again"
        );
    }

    #[test]
    fn a_fitted_volume_written_out_reads_back_across_a_cluster_size_transition() {
        // Every probe allocates into the shared tree, and the bracket does not end on the
        // candidate it returns. Where the candidates either side of the answer take different
        // cluster sizes — which is what the ~8.4 MB FAT12 step is — a tree left allocated
        // against the wrong one yields chains and directory cluster numbers that mean nothing
        // under the layout actually written. The volume still opens, so only reading the
        // bytes back catches it.
        //
        // Sized to sit on the step: 4 sectors per cluster below it, 8 above.
        for each in [8_150usize, 8_180, 8_210, 8_240] {
            let files = 1_024;
            let options =
                opts().plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat12)));
            let source = || {
                let mut b =
                    TreeBuilder::new().directory(b"/d".to_vec(), Metadata::new(0o755, TIME));
                for i in 0..files {
                    b = b.file(
                        format!("/d/f{i:04}").into_bytes(),
                        // Distinct per file, so a chain following the wrong run reads bytes
                        // that name the file they came from.
                        vec![(i % 251) as u8; each],
                        Metadata::new(0o644, TIME),
                    );
                }
                b
            };
            let plan = FormatPlan::fit(source(), options, Slack::None)
                .unwrap_or_else(|e| panic!("{each}-byte files do not fit: {e}"));
            let mut image = std::io::Cursor::new(vec![0u8; plan.volume_bytes() as usize]);
            plan.write_to(&mut image)
                .unwrap_or_else(|e| panic!("{each}: write: {e}"));

            let mut reader = crate::fat::Reader::open(std::io::Cursor::new(image.into_inner()))
                .unwrap_or_else(|e| panic!("{each}: open: {e}"));
            for i in [0usize, 1, files / 2, files - 1] {
                let path = format!("/d/f{i:04}").into_bytes();
                let node = reader
                    .lookup(&path)
                    .unwrap_or_else(|e| panic!("{each}: lookup f{i:04}: {e}"));
                let data = reader
                    .read_data(&node)
                    .unwrap_or_else(|e| panic!("{each}: read f{i:04}: {e}"));
                assert_eq!(data.len(), each, "{each}: f{i:04} is the wrong length");
                assert!(
                    data.iter().all(|&b| b == (i % 251) as u8),
                    "{each}: f{i:04} holds another file's bytes"
                );
            }
        }
    }

    #[test]
    fn slack_is_free_clusters_the_finished_volume_has() {
        // Slack is measured in the unit the volume's own free counter carries, which is a
        // cluster — not a sector, and not a byte.
        let want = Slack::Share(2500);
        let fitted = fit(tree(30, 4_000), opts(), want).expect("fits");
        let free = u64::from(fitted.layout.clusters - fitted.used_clusters);
        assert!(
            free >= Slack::share_of(u64::from(fitted.layout.clusters), 2500),
            "a quarter of the cluster heap is free: {free} of {}",
            fitted.layout.clusters
        );

        let tight = fit(tree(30, 4_000), opts(), Slack::None).expect("fits");
        assert!(
            tight.layout.clusters < fitted.layout.clusters,
            "asking for room produces a larger volume than not asking"
        );
    }

    #[test]
    fn a_type_the_tree_outgrows_is_refused_by_name() {
        // FAT12 addresses 4084 clusters, so a tree past that has no FAT12 volume however
        // large. It comes back as that refusal rather than as a size that could not be found,
        // and it comes back without climbing to the top of the sector range to discover it.
        let options =
            opts().plan(PlanRequest::new(0).fat_type(FatTypeRequest::Exactly(FatType::Fat12)));
        let err = fit(tree(500, 200_000), options, Slack::None).expect_err("no FAT12 holds it");
        assert!(
            matches!(
                err,
                FormatError::Geometry(GeometryError::ClustersAboveMaximum { .. })
            ),
            "{err}"
        );
    }

    #[test]
    fn a_geometry_that_cannot_be_realized_fails_at_once() {
        // Volume-independent, so it is answered before any candidate is planned rather than
        // after climbing the whole range to find out.
        let options = opts().plan(PlanRequest::new(0).bytes_per_sector(3000));
        let err = fit(tree(4, 100), options, Slack::None).expect_err("3000 is not a sector size");
        assert!(
            matches!(
                err,
                FormatError::Geometry(GeometryError::SectorSizeUnsupported { .. })
            ),
            "{err}"
        );
    }

    #[test]
    fn a_share_past_the_limit_is_refused_before_any_search() {
        let err = fit(tree(2, 100), opts(), Slack::Share(9001)).expect_err("past the limit");
        assert!(
            matches!(err, FormatError::SlackShareTooLarge { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_probe_sizes_a_file_without_reading_it() {
        // A probe costs arithmetic. The clusters a file needs follow from its declared
        // length, so a range that claims far more than its file holds still sizes — which is
        // what lets a search try thirty candidates over a tree of any size.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("short");
        std::fs::write(&path, b"tiny").expect("write");
        let file = std::sync::Arc::new(std::fs::File::open(&path).expect("open"));

        let src = TreeBuilder::new().file(
            b"/claims-more".to_vec(),
            crate::source::FileContent::Range(crate::source::FileRange::new(
                file, &path, 0, 400_000,
            )),
            Metadata::new(0o644, TIME),
        );
        let fitted = fit(src, opts(), Slack::None).expect("a declared length is enough to size it");
        assert!(
            u64::from(fitted.layout.clusters) * u64::from(fitted.layout.bytes_per_cluster())
                >= 400_000,
            "the volume was sized for the length the range declared"
        );
    }

    #[test]
    fn a_fitted_plan_writes_the_volume_it_planned() {
        // The size the caller creates and the layout the plan holds describe one filesystem.
        let plan = FormatPlan::fit(tree(25, 6_000), opts(), Slack::Bytes(1 << 20)).expect("fit");
        assert_eq!(
            plan.volume_bytes(),
            plan.layout().total_bytes(),
            "a fitted volume is exactly its filesystem"
        );
        let mut out = std::io::Cursor::new(Vec::new());
        let written = plan.write_to(&mut out).expect("write");
        assert_eq!(out.into_inner().len() as u64, plan.volume_bytes());
        assert_eq!(written.clusters, plan.layout().clusters);
    }
}
