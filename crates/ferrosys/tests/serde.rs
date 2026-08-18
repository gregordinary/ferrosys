//! Gate for the `serde` feature: the shape a consumer embedding these values in its own
//! document actually sees.
//!
//! The crate's own `to_json` emitters are the schema-versioned canonical form and are
//! tested elsewhere. What is asserted here is the derived serialization — that the values
//! serialize at all, that a private field a report keeps for its own bookkeeping stays out
//! of the document, and that a feature word arrives as the on-disk word it wraps.
//!
//! Every value here is one the crate produced: a report from a real scan, a layout from
//! the planner. That is the only way to obtain most of them, and the right one — these
//! types are outputs, and what a consumer serializes is what a scan or a plan handed it.
//!
//! Runs only with the `serde` feature enabled.
#![cfg(all(feature = "serde", feature = "ext"))]

use ferrosys::ext::Timestamp;
use ferrosys::ext::{
    BlockRange, FeatureSet, FormatOptions, GrowReservation, Layout, PlanRequest, Profile, Reader,
    ScanReport, TreeBuilder, format, plan_layout,
};
use ferrosys::{Family, Severity};

const MIB: u64 = 1024 * 1024;

/// The value as a JSON document.
fn json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).expect("the value serializes")
}

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
    // A closed domain serializes as its variant name, which is what a consumer branches on.
    assert!(
        doc["severity"].is_string() && doc["category"].is_string(),
        "{doc}"
    );
    assert!(doc["detail"].is_string(), "{doc}");
    assert!(doc["location"].is_object(), "{doc}");
    // Every coordinate is present as a key, null where the finding does not carry it, so
    // a consumer reads the same shape from every anomaly.
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
    // Each word is the raw little-endian value a superblock holds, which is what `bits()`
    // returns; the names are a projection of it, not a second encoding.
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

    // The family selector is a closed domain and serializes as the word it is written as
    // everywhere else -- `ext2`, not `Ext2`.
    assert_eq!(
        json(&Profile::Ext2),
        serde_json::json!(Profile::Ext2.as_str())
    );
    assert_eq!(json(&Profile::Ext4), serde_json::json!("ext4"));
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
    // space in it.
    use ferrosys::ext::Category;
    use ferrosys::{Direction, Family, Property, Severity};

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
        json(&Category::GroupDescriptor),
        serde_json::json!("group descriptor")
    );
    assert_eq!(json(&Family::ExFat), serde_json::json!("exfat"));
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
    ] {
        assert_eq!(json(&property), serde_json::json!(property.as_str()));
    }
    for severity in Severity::NAMES {
        assert_eq!(json(severity), serde_json::json!(severity.as_str()));
    }
}

#[test]
fn a_layout_serializes_whole_including_every_group() {
    let layout: Layout =
        plan_layout(&PlanRequest::new(64 * MIB, FeatureSet::DEFAULT).grow(GrowReservation::None))
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
fn a_finding_is_spelled_the_same_in_both_serializations() {
    // Two serializations, and each has a job: `to_json` emits the versioned document a
    // consumer parses, and the derives serialize the Rust value as it stands for a caller
    // embedding a report in a structure of its own.
    //
    // Where the two describe the same thing they must agree, or a consumer reading either
    // document has to learn one closed vocabulary twice. A severity and a family are the
    // cases: one lower-case spelling each, whichever asked.
    for (severity, spelled) in [
        (Severity::Cosmetic, "cosmetic"),
        (Severity::Conformance, "conformance"),
        (Severity::Integrity, "integrity"),
        (Severity::Structural, "structural"),
    ] {
        assert_eq!(json(&severity), serde_json::json!(spelled));
        assert_eq!(severity.as_str(), spelled);
    }
    assert_eq!(json(&Family::Ext), serde_json::json!("ext"));
    assert_eq!(Family::Ext.as_str(), "ext");
}

#[test]
fn the_crates_own_emitters_are_unaffected_by_the_derives() {
    // The hand-rolled JSON stays the schema-versioned canonical form: a consumer that
    // reads it sees the same document whether or not this feature is on.
    let report = ScanReport::default();
    let text = report.to_report().to_json();
    assert!(text.contains("\"schema\":2"), "{text}");
    assert!(text.contains("\"findings\":[]"), "{text}");
}
