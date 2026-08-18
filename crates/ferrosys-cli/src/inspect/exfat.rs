//! The exFAT body of an `inspect` report: what a volume's boot region says about itself, the
//! three residents the format allocates before a caller's first file, and the two flags a
//! driver writes.
//!
//! Everything here is exFAT's own vocabulary — a boot region, an allocation bitmap, an
//! up-case table, a cluster heap. The envelope above this module carries the five fields that
//! mean the same thing for every family and knows none of it.
//!
//! # Four of these fields are in no boot sector
//!
//! Where the allocation bitmap and the up-case table begin, and how long each is, are
//! recorded nowhere but in the root directory — the format stores them as ordinary directory
//! entries. So they are reported as what a reading of that directory recovered, and a volume
//! whose root cannot be read has no reader open over it to report anything at all.
//!
//! # The two flags are a driver's, not a formatter's
//!
//! `VolumeDirty` and `MediaFailure` sit outside the boot region's checksum precisely so a
//! mounted driver can write them without recomputing it. Reporting them is reporting the last
//! thing a driver said about the volume, which is why they are here and why a strict read
//! still succeeds with either set.

use std::fs::File;

use ferrosys::exfat::ondisk::{PERCENT_IN_USE_MAX, PERCENT_IN_USE_UNKNOWN};
use ferrosys::exfat::{ExfatLayout, Reader};

use crate::args::InspectArgs;
use crate::inspect::{Dialect, Head, Report};
use crate::{Error, render};

/// Describe the exFAT volume `reader` is open over.
pub fn report(
    mut reader: Reader<File>,
    args: &InspectArgs,
    dialect: Dialect,
) -> Result<Report, Error> {
    // A block group is ext's unit of self-description and an exFAT volume has nothing of the
    // kind, so the option is refused rather than passed over — the same answer the FAT body
    // gives and for the same reason. A report that quietly omitted the section would read as a
    // volume with no groups in it, which is a different claim from the question not applying.
    if args.groups {
        return Err(Error::NotForFamily {
            option: "--groups",
            family: "exfat",
            reason: "block groups are how an ext filesystem divides itself, and an exFAT \
                     volume has one flat cluster heap",
        });
    }

    // A scan follows every stream in the volume, reads every directory, and holds every
    // cluster the tree occupies against the allocation bitmap in both directions, so it is
    // the expensive part and the part that reaches a verdict.
    let findings = if args.quick {
        None
    } else {
        Some(reader.scan().to_report())
    };

    let layout = *reader.layout();
    let boot = *reader.boot_sector();
    let label = reader.volume_label().map(<[u8]>::to_vec);
    let state = State {
        volume_dirty: reader.volume_dirty(),
        media_failure: reader.media_failure(),
        percent_in_use: boot.percent_in_use,
        partition_offset: boot.partition_offset,
    };

    let head = Head {
        family: "exfat",
        // The family is the finest answer there is: one revision of one format, and every
        // volume in circulation records it.
        variant: "exfat",
        size: layout.total_bytes(),
        allocation_unit: u64::from(layout.bytes_per_cluster),
        // This family's identity is its volume serial number, written the way every tool that
        // shows one writes it: two hex groups of four digits.
        identifier: render::volume_serial(boot.volume_serial),
    };
    let body = match dialect {
        Dialect::Table => table(&layout, &state, label.as_deref()),
        Dialect::Json => json(&layout, &state, label.as_deref()),
        Dialect::None => String::new(),
    };
    Ok(Report {
        head,
        findings,
        body,
    })
}

/// What a driver and a formatter each left behind, gathered so the two renderings read the
/// same fields.
struct State {
    /// The volume was mounted and has not been cleanly unmounted since.
    volume_dirty: bool,
    /// A driver met a medium failure and recorded it.
    media_failure: bool,
    /// How full the volume is, to the whole percent, or nothing where the field holds the
    /// value that means unknown.
    percent_in_use: u8,
    /// Where the volume begins on its medium, in sectors, as the formatter recorded it. Zero
    /// on a volume formatted into a file, which is every volume this crate writes.
    partition_offset: u64,
}

/// The `PercentInUse` field, or what a value that is not a percentage means.
///
/// Three answers, because the byte has three cases. A percentage is 0 through
/// [`PERCENT_IN_USE_MAX`]; [`PERCENT_IN_USE_UNKNOWN`] is the format's "not known", which is a
/// different answer from 255 and from zero; and everything between the two is a value the
/// field does not define, which is a different answer again from a percentage that is merely
/// out of date. A report that printed the byte would say a volume nobody measured is 255%
/// used and a volume carrying a wrong byte is 200% used.
fn percent_in_use(value: u8) -> String {
    match value {
        PERCENT_IN_USE_UNKNOWN => "<unknown>".to_string(),
        0..=PERCENT_IN_USE_MAX => format!("{value}%"),
        other => format!("<not a percentage: {other}>"),
    }
}

/// The label as a person reads it, or that the volume carries none.
///
/// Two answers rather than the FAT body's three: an exFAT label is read out of the same root
/// directory the reader had to walk to open the volume at all, so there is no third state in
/// which the label alone could not be read.
fn label_text(label: Option<&[u8]>) -> String {
    match label {
        Some(bytes) => render::printable(bytes),
        None => "<none>".to_string(),
    }
}

/// What the two flags say, in the words the finding for each says it.
fn volume_state(state: &State) -> String {
    match (state.volume_dirty, state.media_failure) {
        (false, false) => "clean".to_string(),
        (true, false) => "not cleanly unmounted".to_string(),
        (false, true) => "a medium failure was recorded".to_string(),
        (true, true) => "not cleanly unmounted; a medium failure was recorded".to_string(),
    }
}

/// The description a person reads.
fn table(layout: &ExfatLayout, state: &State, label: Option<&[u8]>) -> String {
    let mut rows = render::Rows::report();
    let mut line = |k: &str, v: String| rows.row(k, v);

    line("Volume label:", label_text(label));
    line("Volume state:", volume_state(state));
    line("Percent in use:", percent_in_use(state.percent_in_use));
    line("Partition offset:", state.partition_offset.to_string());
    line("Bytes per sector:", layout.bytes_per_sector.to_string());
    line(
        "Sectors per cluster:",
        layout.sectors_per_cluster().to_string(),
    );
    line("Bytes per cluster:", layout.bytes_per_cluster.to_string());
    line("Allocation table at sector:", layout.fat_offset.to_string());
    line("Sectors per table:", layout.fat_length.to_string());
    line(
        "Cluster heap at sector:",
        layout.cluster_heap_offset.to_string(),
    );
    line("Total sectors:", layout.volume_length.to_string());
    line("Clusters:", layout.cluster_count.to_string());

    // The three the format allocates before a caller's first file, and the only place a
    // report says where they are: no boot sector records any of it, and only a reading of the
    // root directory recovers it.
    rows.blank();
    let mut line = |k: &str, v: String| rows.row(k, v);
    line(
        "Allocation bitmap at cluster:",
        layout.bitmap_cluster.to_string(),
    );
    line("Allocation bitmap bytes:", layout.bitmap_bytes.to_string());
    line(
        "Up-case table at cluster:",
        layout.upcase_cluster.to_string(),
    );
    line("Up-case table bytes:", layout.upcase_bytes.to_string());
    line(
        "Root directory at cluster:",
        layout.first_cluster_of_root.to_string(),
    );
    rows.finish()
}

/// The description a machine reads: the object the envelope splices under `"exfat"`.
fn json(layout: &ExfatLayout, state: &State, label: Option<&[u8]>) -> String {
    let mut out = String::new();
    let mut exfat = crate::json::Object::new(&mut out);

    let mut b = exfat.obj("boot");
    match label {
        Some(bytes) => b.bytes("volume_label", bytes),
        None => b.raw("volume_label", "null"),
    }
    b.bool("volume_dirty", state.volume_dirty);
    b.bool("media_failure", state.media_failure);
    // The byte, and separately whether it means anything: the field is a percentage or the
    // format's "not known", so a consumer that read the number alone would take an unknown
    // volume for a full one and a volume carrying a byte that was never a percentage for one
    // twice full. Both non-percentages are `null` and the value is repeated raw beside them,
    // so nothing is lost and nothing reads as a measurement.
    match state.percent_in_use {
        value @ 0..=PERCENT_IN_USE_MAX => b.u64("percent_in_use", u64::from(value)),
        _ => b.raw("percent_in_use", "null"),
    }
    b.u64("percent_in_use_field", u64::from(state.percent_in_use));
    b.u64("partition_offset", state.partition_offset);
    b.u64("bytes_per_sector", u64::from(layout.bytes_per_sector));
    b.u64(
        "sectors_per_cluster",
        u64::from(layout.sectors_per_cluster()),
    );
    b.u64("bytes_per_cluster", u64::from(layout.bytes_per_cluster));
    b.u64("fat_offset", u64::from(layout.fat_offset));
    b.u64("fat_length", u64::from(layout.fat_length));
    b.u64("cluster_heap_offset", u64::from(layout.cluster_heap_offset));
    b.u64("total_sectors", layout.volume_length);
    b.u64("clusters", u64::from(layout.cluster_count));
    b.end();

    // Under a key of their own because they are a different kind of fact: everything above is
    // read out of the boot sector, and every one of these is read out of the root directory.
    let mut r = exfat.obj("residents");
    r.u64("bitmap_cluster", u64::from(layout.bitmap_cluster));
    r.u64("bitmap_bytes", layout.bitmap_bytes);
    r.u64("upcase_cluster", u64::from(layout.upcase_cluster));
    r.u64("upcase_bytes", layout.upcase_bytes);
    r.u64("root_cluster", u64::from(layout.first_cluster_of_root));
    r.end();

    exfat.end();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unknown_percentage_is_not_a_percentage() {
        assert_eq!(percent_in_use(0), "0%");
        assert_eq!(percent_in_use(47), "47%");
        assert_eq!(percent_in_use(PERCENT_IN_USE_MAX), "100%");
        // The format's "not known". Printing the byte would report a volume nobody measured
        // as one that is two and a half times full.
        assert_eq!(percent_in_use(PERCENT_IN_USE_UNKNOWN), "<unknown>");
        // And the third case, which is neither: a byte between a percentage and "not known"
        // is a value the field does not define, which is a different thing to be told from a
        // percentage that is out of date.
        assert_eq!(percent_in_use(200), "<not a percentage: 200>");
        assert_eq!(percent_in_use(101), "<not a percentage: 101>");
    }

    #[test]
    fn the_volume_state_names_each_bit_and_both_together() {
        let state = |dirty, failure| State {
            volume_dirty: dirty,
            media_failure: failure,
            percent_in_use: 0,
            partition_offset: 0,
        };
        assert_eq!(volume_state(&state(false, false)), "clean");
        assert_eq!(volume_state(&state(true, false)), "not cleanly unmounted");
        assert_eq!(
            volume_state(&state(false, true)),
            "a medium failure was recorded"
        );
        // Both, because a card pulled out of a reader that had also met a bad sector says two
        // things and a report that named one of them would be dropping the other.
        assert_eq!(
            volume_state(&state(true, true)),
            "not cleanly unmounted; a medium failure was recorded"
        );
    }
}
