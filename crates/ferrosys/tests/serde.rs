//! Gate for the `serde` feature: the shape a consumer embedding these values in its own
//! document actually sees, in every family the build carries.
//!
//! The crate's own `to_json` emitters are the schema-versioned canonical form and are
//! tested elsewhere. What is asserted here is the derived serialization — that the values
//! serialize at all, that a private field a report keeps for its own bookkeeping stays out
//! of the document, that a feature word arrives as the on-disk word it wraps, and that a
//! closed domain arrives as the word the crate prints for it.
//!
//! Every value here is one the crate produced: a report from a real scan, a layout from
//! the planner. That is the only way to obtain most of them, and the right one — these
//! types are outputs, and what a consumer serializes is what a scan or a plan handed it.
//!
//! Each family has a module of its own, holding its scan report and its planned layout to
//! the same rules, so a family whose values stop serializing fails here in that family's
//! name. Runs only with the `serde` feature enabled, and each module only with its family.
#![cfg(feature = "serde")]

use ferrosys::{Direction, Property, Severity};

/// The value as a JSON document.
fn json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).expect("the value serializes")
}

#[test]
fn a_closed_domain_serializes_as_the_word_this_crate_writes_it_as() {
    // The rule for every closed set on this surface: what a consumer embedding one of these
    // values reads is the word the crate prints, not the spelling its variants happen to
    // have in Rust. A second vocabulary for one set is a vocabulary a reader has to learn
    // twice, and the derived one is the half nothing else in the crate ever says.
    //
    // Held over every such type at once rather than over the one that prompted it: the
    // spellings that differ most are the ones a derive would mangle worst -- a compound
    // name, a family whose word is not its capitalization, a property whose word has a
    // space in it. Each family's own closed sets are held in that family's module.
    assert_eq!(
        json(&Property::ChangeTime),
        serde_json::json!("change time")
    );
    assert_eq!(
        json(&Property::ExtendedAttributes),
        serde_json::json!("extended attributes")
    );
    assert_eq!(
        json(&Direction::Synthesized),
        serde_json::json!("synthesized")
    );
    assert_eq!(
        json(&Severity::Conformance),
        serde_json::json!("conformance")
    );

    // And the rule itself, over every variant of every one of them: the serialization is
    // the name, with nothing between them to drift.
    for property in [
        Property::Ownership,
        Property::Permissions,
        Property::SpecialBits,
        Property::Kind,
        Property::ExtendedAttributes,
        Property::AccessTime,
        Property::ChangeTime,
        Property::ModificationTime,
        Property::TimePrecision,
        Property::Name,
        Property::BsdFlags,
    ] {
        assert_eq!(json(&property), serde_json::json!(property.as_str()));
    }
    for severity in Severity::NAMES {
        assert_eq!(json(severity), serde_json::json!(severity.as_str()));
    }
}

#[test]
fn a_finding_is_spelled_the_same_in_both_serializations() {
    // Two serializations, and each has a job: `to_json` emits the versioned document a
    // consumer parses, and the derives serialize the Rust value as it stands for a caller
    // embedding a report in a structure of its own.
    //
    // Where the two describe the same thing they must agree, or a consumer reading either
    // document has to learn one closed vocabulary twice. A severity is the case here, and
    // each family's module holds its family's word the same way.
    for (severity, spelled) in [
        (Severity::Cosmetic, "cosmetic"),
        (Severity::Conformance, "conformance"),
        (Severity::Integrity, "integrity"),
        (Severity::Structural, "structural"),
    ] {
        assert_eq!(json(&severity), serde_json::json!(spelled));
        assert_eq!(severity.as_str(), spelled);
    }
}

#[cfg(feature = "ext")]
mod ext {
    use super::json;
    use ferrosys::Family;
    use ferrosys::ext::Timestamp;
    use ferrosys::ext::{
        BlockRange, Category, FeatureSet, FormatOptions, GrowReservation, Layout, PlanRequest,
        Profile, Reader, ScanReport, TreeBuilder, format, plan_layout,
    };

    const MIB: u64 = 1024 * 1024;

    /// A 16 MiB image this crate wrote.
    fn image() -> Vec<u8> {
        format(
            TreeBuilder::new(),
            16 * MIB,
            FormatOptions::new([0x44; 16], Timestamp::from_secs(1_700_000_000), [0; 16]),
        )
        .expect("format an image")
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn an_anomaly_serializes_with_its_severity_category_location_and_detail() {
        // A real finding, from an image whose first group descriptor no longer agrees with
        // its own checksum. Nothing here assembles an `Anomaly` by hand: the type is an
        // output, and a scan is what produces one.
        let mut bytes = image();
        let descriptors = 4096;
        bytes[descriptors + 8] ^= 0xff;
        let mut reader = Reader::open_with(
            std::io::Cursor::new(&bytes[..]),
            &ferrosys::ext::OpenOptions::new().policy(ferrosys::ext::ReadPolicy::Lenient),
        )
        .expect("a lenient read opens a quirky image");
        let report = reader.scan();
        let anomalies = report.anomalies();
        assert!(
            !anomalies.is_empty(),
            "a descriptor that contradicts its checksum is a finding"
        );

        let doc = json(&anomalies[0]);
        // A closed domain serializes as its variant name, which is what a consumer branches
        // on.
        assert!(
            doc["severity"].is_string() && doc["category"].is_string(),
            "{doc}"
        );
        assert!(doc["detail"].is_string(), "{doc}");
        assert!(doc["location"].is_object(), "{doc}");
        // Every coordinate is present as a key, null where the finding does not carry it,
        // so a consumer reads the same shape from every anomaly.
        for coordinate in ["block", "group", "inode"] {
            assert!(
                doc["location"].get(coordinate).is_some(),
                "the location names {coordinate}: {doc}"
            );
        }

        // The whole report serializes too, findings and all.
        let whole = json(&report);
        assert_eq!(
            whole["anomalies"].as_array().expect("an array").len(),
            anomalies.len()
        );
    }

    #[test]
    fn a_report_carries_its_findings_and_not_the_cap_it_ran_under() {
        let bytes = image();
        let mut reader = Reader::open(std::io::Cursor::new(&bytes[..])).expect("open");
        let report: ScanReport = reader.scan();

        let doc = json(&report);
        assert_eq!(doc["anomalies"], serde_json::json!([]));
        assert_eq!(doc["truncated"], serde_json::json!(false));
        // The cap is a property of the scan that ran, not of the findings, and `truncated`
        // already says whether it was reached.
        assert!(
            doc.get("cap").is_none(),
            "the bookkeeping field is not part of the document: {doc}"
        );
    }

    #[test]
    fn a_feature_set_serializes_as_the_on_disk_words_it_holds() {
        let feature = FeatureSet::DEFAULT;
        let doc = json(&feature);
        // Each word is the raw little-endian value a superblock holds, which is what
        // `bits()` returns; the names are a projection of it, not a second encoding.
        assert_eq!(
            doc["compat"],
            serde_json::json!(feature.compat.bits()),
            "{doc}"
        );
        assert_eq!(doc["incompat"], serde_json::json!(feature.incompat.bits()));
        assert_eq!(
            doc["ro_compat"],
            serde_json::json!(feature.ro_compat.bits())
        );
        assert_eq!(doc["block_size"], serde_json::json!(4096));
        assert_eq!(doc["inode_size"], serde_json::json!(256));

        // The family selector is a closed domain and serializes as the word it is written
        // as everywhere else -- `ext2`, not `Ext2`.
        assert_eq!(
            json(&Profile::Ext2),
            serde_json::json!(Profile::Ext2.as_str())
        );
        assert_eq!(json(&Profile::Ext4), serde_json::json!("ext4"));
    }

    #[test]
    fn the_family_and_a_category_serialize_as_their_words() {
        assert_eq!(json(&Family::Ext), serde_json::json!("ext"));
        assert_eq!(Family::Ext.as_str(), "ext");
        assert_eq!(
            json(&Category::GroupDescriptor),
            serde_json::json!("group descriptor")
        );
    }

    #[test]
    fn a_layout_serializes_whole_including_every_group() {
        let layout: Layout = plan_layout(
            &PlanRequest::new(64 * MIB, FeatureSet::DEFAULT).grow(GrowReservation::None),
        )
        .expect("plan a layout");

        let doc = json(&layout);
        assert_eq!(doc["block_size"], serde_json::json!(layout.block_size));
        assert_eq!(doc["total_blocks"], serde_json::json!(layout.total_blocks));
        assert_eq!(
            doc["groups"]
                .as_array()
                .expect("the groups are an array")
                .len(),
            layout.groups.len()
        );
        assert_eq!(
            doc["groups"][0]["block_bitmap"],
            serde_json::json!(layout.groups[0].block_bitmap)
        );
        // The feature set is nested rather than flattened, so a consumer reaches it by name.
        assert_eq!(
            doc["feature"]["block_size"],
            serde_json::json!(layout.feature.block_size)
        );

        // A block range is a plain pair, and is reachable on its own.
        let range = BlockRange { start: 3, len: 4 };
        assert_eq!(json(&range), serde_json::json!({"start": 3, "len": 4}));
    }

    #[test]
    fn the_crates_own_emitters_are_unaffected_by_the_derives() {
        // The hand-rolled JSON stays the schema-versioned canonical form: a consumer that
        // reads it sees the same document whether or not this feature is on.
        let report = ScanReport::default();
        let text = report.to_report().to_json();
        assert!(text.contains("\"schema\":3"), "{text}");
        assert!(text.contains("\"findings\":[]"), "{text}");
    }
}

#[cfg(feature = "fat")]
mod fat {
    use super::json;
    use ferrosys::fat::{
        Category, FormatOptions, PlanRequest, Reader, Timestamp, format, plan_layout,
    };
    use ferrosys::{Family, TreeBuilder};

    #[test]
    fn an_anomaly_and_its_report_serialize_with_the_words_a_scan_prints() {
        // A volume a driver had mounted and did not put down: bit 0 of a FAT16 boot
        // sector's reserved byte, which a Linux driver sets and a scan reports.
        let mut bytes = format(
            TreeBuilder::new(),
            64 << 20,
            FormatOptions::new(0x1234_abcd, Timestamp::from_secs(1_700_000_000)),
        )
        .expect("format a volume")
        .as_bytes()
        .to_vec();
        bytes[37] |= 1;
        let mut reader = Reader::open(std::io::Cursor::new(&bytes[..])).expect("open");
        let report = reader.scan();
        let anomalies = report.anomalies();
        assert!(!anomalies.is_empty(), "an unclean unmount is a finding");

        let doc = json(&anomalies[0]);
        assert_eq!(
            doc["category"],
            serde_json::json!(anomalies[0].category.as_str())
        );
        assert_eq!(
            doc["severity"],
            serde_json::json!(anomalies[0].severity.as_str())
        );
        assert!(doc["detail"].is_string(), "{doc}");
        for coordinate in ["sector", "cluster", "entry"] {
            assert!(
                doc["location"].get(coordinate).is_some(),
                "the location names {coordinate}: {doc}"
            );
        }
        assert_eq!(
            json(&report)["anomalies"]
                .as_array()
                .expect("an array")
                .len(),
            anomalies.len()
        );
    }

    #[test]
    fn a_layout_serializes_whole_with_its_type_as_the_word_it_is_written_as() {
        let layout = plan_layout(&PlanRequest::new(512 << 20)).expect("plan a layout");
        let doc = json(&layout);
        assert_eq!(doc["fat_type"], serde_json::json!(layout.fat_type.as_str()));
        assert_eq!(doc["clusters"], serde_json::json!(layout.clusters));
        assert_eq!(doc["fat_sectors"], serde_json::json!(layout.fat_sectors));
        assert_eq!(doc["fat32"].is_object(), layout.fat32.is_some(), "{doc}");
    }

    #[test]
    fn the_family_and_every_category_serialize_as_their_words() {
        assert_eq!(json(&Family::Fat), serde_json::json!("fat"));
        for category in [
            Category::BootSector,
            Category::InfoSector,
            Category::AllocationTable,
            Category::Directory,
            Category::Source,
        ] {
            assert_eq!(json(&category), serde_json::json!(category.as_str()));
        }
    }
}

#[cfg(feature = "exfat")]
mod exfat {
    use super::json;
    use ferrosys::exfat::{Category, FormatOptions, PlanRequest, Reader, format, plan_layout};
    use ferrosys::{Family, TreeBuilder};

    #[test]
    fn an_anomaly_and_its_report_serialize_with_the_words_a_scan_prints() {
        // A volume a driver had mounted and did not put down: the dirty bit of the boot
        // sector's volume flags, which sit outside its checksum so a driver can set them.
        let mut bytes = format(
            TreeBuilder::new(),
            64 << 20,
            FormatOptions::new(0x1234_abcd),
        )
        .expect("format a volume")
        .as_bytes()
        .to_vec();
        bytes[106] |= 0b10;
        let mut reader = Reader::open(std::io::Cursor::new(&bytes[..])).expect("open");
        let report = reader.scan();
        let anomalies = report.anomalies();
        assert!(!anomalies.is_empty(), "an unclean unmount is a finding");

        let doc = json(&anomalies[0]);
        assert_eq!(
            doc["category"],
            serde_json::json!(anomalies[0].category.as_str())
        );
        assert_eq!(
            doc["severity"],
            serde_json::json!(anomalies[0].severity.as_str())
        );
        assert!(doc["detail"].is_string(), "{doc}");
        for coordinate in ["sector", "cluster", "entry"] {
            assert!(
                doc["location"].get(coordinate).is_some(),
                "the location names {coordinate}: {doc}"
            );
        }
        assert_eq!(
            json(&report)["anomalies"]
                .as_array()
                .expect("an array")
                .len(),
            anomalies.len()
        );
    }

    #[test]
    fn a_layout_serializes_whole() {
        let layout = plan_layout(&PlanRequest::new(512 << 20)).expect("plan a layout");
        let doc = json(&layout);
        assert_eq!(
            doc["bytes_per_cluster"],
            serde_json::json!(layout.bytes_per_cluster)
        );
        assert_eq!(
            doc["cluster_count"],
            serde_json::json!(layout.cluster_count)
        );
        assert_eq!(
            doc["first_cluster_of_root"],
            serde_json::json!(layout.first_cluster_of_root)
        );
    }

    #[test]
    fn the_family_and_every_category_serialize_as_their_words() {
        assert_eq!(json(&Family::ExFat), serde_json::json!("exfat"));
        for category in [
            Category::BootRegion,
            Category::AllocationTable,
            Category::AllocationBitmap,
            Category::UpcaseTable,
            Category::Directory,
            Category::Source,
        ] {
            assert_eq!(json(&category), serde_json::json!(category.as_str()));
        }
    }
}

#[cfg(feature = "btrfs")]
mod btrfs {
    use super::json;
    use ferrosys::btrfs::{
        Category, FormatOptions, PlanRequest, Pool, Profile, Reader, format, plan_layout,
    };
    use ferrosys::{Family, OpenOptions, ReadPolicy, Timestamp, TreeBuilder};

    #[test]
    fn an_anomaly_and_its_report_serialize_with_the_words_a_scan_prints() {
        // A damaged superblock copy: the one at 64 MiB, which a 128 MiB device holds.
        // A lenient read opens through the primary and a scan names the copy.
        let options = FormatOptions::new([0x11; 16], Timestamp::from_secs(1_700_000_000));
        let mut bytes = format(TreeBuilder::new(), 128 << 20, options)
            .expect("format a filesystem")
            .as_bytes()
            .to_vec();
        bytes[(64 << 20) + 0x200] ^= 0xff;
        let mut reader = Reader::open_with(
            std::io::Cursor::new(&bytes[..]),
            &OpenOptions::new().policy(ReadPolicy::Lenient),
        )
        .expect("a lenient read opens through the primary");
        let report = reader.scan();
        let anomalies = report.anomalies();
        assert!(!anomalies.is_empty(), "a damaged copy is a finding");

        let doc = json(&anomalies[0]);
        assert_eq!(
            doc["category"],
            serde_json::json!(anomalies[0].category.as_str())
        );
        assert_eq!(
            doc["severity"],
            serde_json::json!(anomalies[0].severity.as_str())
        );
        assert!(doc["detail"].is_string(), "{doc}");
        // Every coordinate is present as a key, null where the finding does not carry it.
        for coordinate in ["tree", "logical"] {
            assert!(
                doc.get(coordinate).is_some(),
                "the anomaly names {coordinate}: {doc}"
            );
        }
        assert_eq!(
            json(&report)["anomalies"]
                .as_array()
                .expect("an array")
                .len(),
            anomalies.len()
        );
    }

    #[test]
    fn a_layout_serializes_whole_with_its_flags_as_the_on_disk_words() {
        let layout = plan_layout(&PlanRequest::new(1 << 30)).expect("plan a layout");
        let doc = json(&layout);
        assert_eq!(doc["node_size"], serde_json::json!(layout.node_size));
        // A feature word and a block group's flags are the raw words the superblock and a
        // chunk item hold, as ext's feature words are.
        assert_eq!(
            doc["incompat_flags"],
            serde_json::json!(layout.incompat_flags.bits())
        );
        assert_eq!(
            doc["compat_ro_flags"],
            serde_json::json!(layout.compat_ro_flags.bits())
        );
        let chunks = doc["chunks"].as_array().expect("the chunks are an array");
        assert_eq!(chunks.len(), layout.chunks.len());
        assert_eq!(
            chunks[0]["flags"],
            serde_json::json!(layout.chunks[0].flags.bits())
        );
        assert_eq!(
            chunks[0]["copies"],
            serde_json::json!(layout.chunks[0].copies)
        );
        assert_eq!(
            doc["superblock_mirrors"],
            serde_json::json!(layout.superblock_mirrors)
        );
        assert_eq!(
            doc["reservation"]["node_size"],
            serde_json::json!(layout.reservation.node_size)
        );
    }

    #[test]
    fn the_family_and_every_category_serialize_as_their_words() {
        assert_eq!(json(&Family::Btrfs), serde_json::json!("btrfs"));
        assert_eq!(json(&Category::ChunkMap), serde_json::json!("chunk-map"));
        // The planner's own closed sets, in the words the format's tooling uses for them.
        for profile in [Profile::Single, Profile::Dup] {
            assert_eq!(json(&profile), serde_json::json!(profile.as_str()));
        }
        assert_eq!(json(&Profile::Dup), serde_json::json!("dup"));
        for pool in [Pool::Metadata, Pool::System] {
            assert_eq!(json(&pool), serde_json::json!(pool.as_str()));
        }
        for category in [
            Category::Superblock,
            Category::ChunkMap,
            Category::Tree,
            Category::Item,
            Category::Data,
            Category::Source,
        ] {
            assert_eq!(json(&category), serde_json::json!(category.as_str()));
        }
    }
}

#[cfg(feature = "apfs")]
mod apfs {
    use super::json;
    use ferrosys::apfs::{
        Category, FormatOptions, OpenOptions, PlanRequest, Reader, VolumeName, VolumeRequest,
        format, plan_layout,
    };
    use ferrosys::{Family, ReadPolicy, Timestamp, TreeBuilder};

    #[test]
    fn an_anomaly_and_its_report_serialize_with_the_words_a_scan_prints() {
        // Block zero that no longer verifies: a lenient read opens at the live checkpoint,
        // and a scan names block zero.
        let volume = VolumeRequest::new(VolumeName::new("Data").expect("a name"), [0x22; 16]);
        let options = FormatOptions::new([0x11; 16], Timestamp::from_secs(1_700_000_000), volume);
        let mut bytes = format(TreeBuilder::new(), 64 << 20, options)
            .expect("format a container")
            .as_bytes()
            .to_vec();
        bytes[0xF00] ^= 0xff;
        let lenient =
            OpenOptions::new().common(ferrosys::OpenOptions::new().policy(ReadPolicy::Lenient));
        let mut reader = Reader::open_with(std::io::Cursor::new(&bytes[..]), &lenient)
            .expect("a lenient read opens at the live checkpoint");
        let report = reader.scan();
        let anomalies = report.anomalies();
        assert!(
            !anomalies.is_empty(),
            "a block zero that fails is a finding"
        );

        let doc = json(&anomalies[0]);
        assert_eq!(
            doc["category"],
            serde_json::json!(anomalies[0].category.as_str())
        );
        assert_eq!(
            doc["severity"],
            serde_json::json!(anomalies[0].severity.as_str())
        );
        assert!(doc["detail"].is_string(), "{doc}");
        // Every coordinate is present as a key, null where the finding does not carry it.
        for coordinate in ["block", "inode"] {
            assert!(
                doc.get(coordinate).is_some(),
                "the anomaly names {coordinate}: {doc}"
            );
        }
        assert_eq!(
            json(&report)["anomalies"]
                .as_array()
                .expect("an array")
                .len(),
            anomalies.len()
        );
    }

    #[test]
    fn a_layout_serializes_whole_including_both_checkpoints() {
        let layout = plan_layout(&PlanRequest::new(64 << 20)).expect("plan a layout");
        let doc = json(&layout);
        assert_eq!(doc["block_size"], serde_json::json!(layout.block_size));
        assert_eq!(doc["block_count"], serde_json::json!(layout.block_count));
        // A block range is a plain pair.
        assert_eq!(
            doc["data_area"],
            serde_json::json!({
                "start": layout.data_area.start,
                "count": layout.data_area.count,
            })
        );
        assert_eq!(
            doc["chunks"]["chunk_count"],
            serde_json::json!(layout.chunks.chunk_count)
        );
        let checkpoints = doc["checkpoints"]
            .as_array()
            .expect("the checkpoints are an array");
        assert_eq!(checkpoints.len(), 2);
        for (doc, checkpoint) in checkpoints.iter().zip(&layout.checkpoints) {
            assert_eq!(doc["xid"], serde_json::json!(checkpoint.xid));
            assert_eq!(
                doc["object_map"]["root"],
                serde_json::json!(checkpoint.object_map.root)
            );
            assert_eq!(
                doc["volumes"].as_array().expect("an array").len(),
                checkpoint.volumes.len()
            );
        }
    }

    #[test]
    fn the_family_and_every_category_serialize_as_their_words() {
        assert_eq!(json(&Family::Apfs), serde_json::json!("apfs"));
        for category in [
            Category::Source,
            Category::Checkpoint,
            Category::Tree,
            Category::Record,
            Category::Volume,
            Category::Space,
        ] {
            assert_eq!(json(&category), serde_json::json!(category.as_str()));
        }
    }
}
