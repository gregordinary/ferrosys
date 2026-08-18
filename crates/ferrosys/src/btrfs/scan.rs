//! What a whole-filesystem scan finds, in btrfs's own taxonomy.
//!
//! A read stops at the first thing it cannot do. A scan does not: it walks the whole
//! filesystem and reports every deviation it meets, which is what a caller asking "is anything
//! wrong with this image" wants and what a caller asking "give me this file" does not.
//!
//! # The two things this family reports that no other here can
//!
//! **A live log tree.** A filesystem that was not cleanly unmounted has a nonzero `log_root`,
//! and the committed trees are stale with respect to it. This crate never replays a log, so
//! what it reads is the last committed transaction — and it says so. The finding is cosmetic
//! because every byte read is trustworthy and the image is conformant, but the message says
//! what is *missing* rather than only that something is: the filesystem genuinely holds writes
//! the committed trees do not.
//!
//! **An item type this reader has no opinion about.** That is not a fault and not a refusal.
//! A feature flag is the format telling a reader in advance that it will not understand what
//! follows; an unrecognized item type is a record sitting beside records this reader does
//! understand, and a filesystem that has been used carries several. So it is skipped, counted,
//! and named — a reader that refused what it could not name would refuse Fedora.

use std::collections::BTreeMap;
use std::io::{Read, Seek};

use crate::finding::{Deviation, Family, Finding, Findings, Severity, project};

use super::ondisk::{ItemType, objectid};
use super::volume::{Mirror, ReadError};

/// What a whole-filesystem [`scan`](super::Reader::scan) found.
///
/// This is the crate's [`ScanReport`](crate::ScanReport) over btrfs's [`Anomaly`].
pub type ScanReport = crate::ScanReport<Anomaly>;

/// The part of a filesystem a deviation was found in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Category {
    /// The superblock, or one of its copies.
    Superblock,
    /// The map from logical addresses onto the device.
    ChunkMap,
    /// A tree block: its checksum, its own account of where it lives, or its shape.
    Tree,
    /// One record inside a leaf.
    Item,
    /// A file's bytes, held against the checksums recorded for them.
    Data,
}

impl Category {
    /// The lowercase name this category is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::Superblock => "superblock",
            Category::ChunkMap => "chunk-map",
            Category::Tree => "tree",
            Category::Item => "item",
            Category::Data => "data",
        }
    }
}

/// One deviation a scan found: where it was, how serious it is, and what it was.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Anomaly {
    /// The part of the filesystem it was found in.
    pub category: Category,
    /// How serious it is.
    pub severity: Severity,
    /// The tree it was found in, where one applies.
    pub tree: Option<u64>,
    /// The logical address it was found at, where one applies.
    ///
    /// **A logical address, not a place on the device.** The two differ by the chunk map, and
    /// a projection that multiplied this by an addressing unit would name a byte offset that is
    /// nothing in particular — which is why [`to_finding`](Deviation::to_finding) reports it as
    /// a coordinate and leaves the offset empty.
    pub logical: Option<u64>,
    /// What was wrong, in a sentence a person reads.
    pub detail: String,
}

impl Deviation for Anomaly {
    fn severity(&self) -> Severity {
        self.severity
    }

    fn to_finding(&self, _unit: u32) -> Finding {
        // No addressed coordinate, and the reason is this family's alone: every address it
        // reports is logical, and turning one into a byte offset means going through the chunk
        // map — which is a structure of the filesystem rather than a multiplication. A finding
        // with no offset is honest; one with a wrong offset is not.
        project(
            self.severity,
            Family::Btrfs,
            self.category.as_str(),
            &[("tree", self.tree), ("logical", self.logical)],
            None,
            0,
            &self.detail,
        )
    }
}

/// Everything a scan gathers while walking, so the walk is one pass rather than one per kind.
pub(super) struct Scan {
    pub(super) found: Findings<Anomaly>,
    /// Every item type met that this reader has no opinion about, and how many of each.
    ///
    /// Counted rather than reported one by one: a used filesystem carries thousands of records
    /// of a handful of types nothing here interprets, and a report with one entry per record
    /// would be a report nobody reads.
    unknown: BTreeMap<u8, u64>,
}

impl Scan {
    pub(super) fn new(cap: usize) -> Self {
        Self {
            found: Findings::new(cap),
            unknown: BTreeMap::new(),
        }
    }

    /// Record a deviation at a logical address in a tree.
    pub(super) fn at(
        &mut self,
        category: Category,
        severity: Severity,
        tree: Option<u64>,
        logical: Option<u64>,
        detail: String,
    ) {
        self.found.push(Anomaly {
            category,
            severity,
            tree,
            logical,
            detail,
        });
    }

    /// Note that an item of `kind` was met and not interpreted.
    pub(super) fn met_unknown(&mut self, kind: ItemType) {
        if kind.name().is_none() {
            *self.unknown.entry(kind.value()).or_default() += 1;
        }
    }

    /// The report, with the unknown types folded into one finding each.
    pub(super) fn finish(mut self) -> ScanReport {
        let unknown = std::mem::take(&mut self.unknown);
        for (kind, count) in unknown {
            self.at(
                Category::Item,
                Severity::Cosmetic,
                None,
                None,
                format!(
                    "{count} record{} of item type {kind}, which this release of the format has \
                     not given a meaning this reader knows; each was skipped",
                    if count == 1 { "" } else { "s" }
                ),
            );
        }
        // The unit is zero because no anomaly here is addressed in units of anything: see
        // `to_finding`.
        self.found.into_report(0)
    }
}

/// What each superblock copy contributes to a scan.
///
/// The live copy contributes nothing, and every other state is a deviation of its own kind: a
/// copy the device has no room for was never written and is not a fault, one that is missing or
/// fails its checksum is an integrity finding, and one recording another place as its own is
/// what an image carved out at the wrong offset looks like.
pub(super) fn mirror_anomaly(state: Mirror, live: u64) -> Option<(Severity, &'static str)> {
    match state {
        Mirror::OutsideDevice => None,
        Mirror::Present { generation } if generation == live => None,
        Mirror::Present { .. } => Some((
            Severity::Conformance,
            "a copy of the superblock is behind the live one",
        )),
        Mirror::Truncated => Some((
            Severity::Structural,
            "the source is shorter than the device it describes, so this copy is not in it",
        )),
        Mirror::Absent => Some((
            Severity::Integrity,
            "a copy of the superblock the device has room for is missing",
        )),
        Mirror::Damaged => Some((
            Severity::Integrity,
            "a copy of the superblock fails its own checksum",
        )),
        Mirror::Misplaced { .. } => Some((
            Severity::Integrity,
            "a copy of the superblock records another place as its own, which is what an image \
             carved out of a disk at the wrong offset looks like",
        )),
    }
}

/// How a failure met while walking one tree is reported rather than returned.
///
/// A scan does not stop at the first thing it cannot do, so every refusal a walk produces
/// becomes a finding — and which kind it is is the same classification the extraction surface
/// makes, kept here because a scan reports rather than converts.
pub(super) fn walk_anomaly(err: &ReadError) -> (Category, Severity) {
    match err {
        ReadError::BadChecksum { .. } | ReadError::DataChecksum { .. } => {
            (Category::Tree, Severity::Integrity)
        }
        ReadError::BadItem { .. } | ReadError::BadRootItem { .. } => {
            (Category::Item, Severity::Structural)
        }
        ReadError::UnmappedLogical { .. }
        | ReadError::ChunkOverlap { .. }
        | ReadError::BadChunk { .. }
        | ReadError::BadBootstrap { .. } => (Category::ChunkMap, Severity::Structural),
        _ => (Category::Tree, Severity::Structural),
    }
}

/// The name a tree is reported under: the format's own where it has one, and its id where the
/// tree is a subvolume.
///
/// Public because a finding names a tree this way and so does anything that lists them, and the
/// two must agree — a report calling a tree by one name where a finding about it calls it
/// another is two vocabularies for one filesystem.
#[must_use]
pub fn tree_name(objectid: u64) -> String {
    objectid::name(objectid).map_or_else(|| format!("subvolume {objectid}"), str::to_string)
}

/// Whether this filesystem holds a log tree the committed trees do not account for.
pub(super) fn has_live_log<R: Read + Seek>(volume: &super::Volume<R>) -> bool {
    volume.superblock().log_root != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_anomaly_reports_its_address_as_a_coordinate_and_never_as_an_offset() {
        // Every address this family reports is logical, and the byte it sits at is on the far
        // side of the chunk map. A finding with no offset is honest; one carrying a logical
        // address multiplied by something would name a byte that is nothing in particular.
        let anomaly = Anomaly {
            category: Category::Tree,
            severity: Severity::Integrity,
            tree: Some(objectid::FS_TREE),
            logical: Some(30_605_312),
            detail: "the checksum does not cover it".to_string(),
        };
        let finding = anomaly.to_finding(4096);
        assert_eq!(finding.offset, None);
        assert_eq!(finding.category, "tree");
        assert_eq!(finding.severity, Severity::Integrity);
        let named: Vec<(&str, u64)> = finding
            .coordinates
            .iter()
            .map(|(name, value)| (name.as_ref(), *value))
            .collect();
        assert_eq!(named, vec![("tree", 5), ("logical", 30_605_312)]);
    }

    #[test]
    fn an_anomaly_with_no_address_reports_no_coordinate_for_one() {
        let anomaly = Anomaly {
            category: Category::Superblock,
            severity: Severity::Cosmetic,
            tree: None,
            logical: None,
            detail: "a log tree is live".to_string(),
        };
        assert!(anomaly.to_finding(4096).coordinates.is_empty());
    }

    #[test]
    fn every_record_of_a_type_this_reader_does_not_interpret_is_one_finding() {
        // A used filesystem carries thousands of them and a report with one entry per record
        // is a report nobody reads. What must survive the folding is the type's own byte,
        // which is the only thing that says what was skipped.
        let mut scan = Scan::new(64);
        for _ in 0..1000 {
            scan.met_unknown(ItemType::from_value(77));
        }
        scan.met_unknown(ItemType::from_value(201));
        // And a type this reader does name is not an unknown one, however little it does with
        // it: the question is whether the format has given the byte a meaning.
        scan.met_unknown(ItemType::QGROUP_INFO);
        let report = scan.finish();
        assert_eq!(report.anomalies().len(), 2);
        assert!(report.anomalies()[0].detail.contains("1000 records"));
        assert!(report.anomalies()[0].detail.contains("item type 77"));
        assert!(
            report.anomalies()[1]
                .detail
                .contains("1 record of item type 201")
        );
        assert!(
            report
                .anomalies()
                .iter()
                .all(|a| a.severity == Severity::Cosmetic)
        );
    }

    #[test]
    fn the_live_copy_of_the_superblock_is_not_a_finding_and_every_other_state_is() {
        // A copy the device has no room for was never written, which is the format's own rule
        // rather than a fault — and reporting one would make every small filesystem look
        // damaged.
        assert!(mirror_anomaly(Mirror::OutsideDevice, 8).is_none());
        assert!(mirror_anomaly(Mirror::Present { generation: 8 }, 8).is_none());
        for state in [
            Mirror::Present { generation: 7 },
            Mirror::Truncated,
            Mirror::Absent,
            Mirror::Damaged,
            Mirror::Misplaced { bytenr: 0 },
        ] {
            assert!(mirror_anomaly(state, 8).is_some(), "{state:?}");
        }
    }

    #[test]
    fn a_tree_is_reported_by_the_name_the_format_gives_it_or_by_its_own_id() {
        assert_eq!(tree_name(objectid::FS_TREE), "FS_TREE");
        assert_eq!(tree_name(objectid::CSUM_TREE), "CSUM_TREE");
        assert_eq!(tree_name(257), "subvolume 257");
    }
}
