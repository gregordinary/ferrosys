//! `ferrosys inspect`: report what a filesystem says about itself, and whether it is
//! sound.
//!
//! The report is the run's artifact, so it goes to the standard output — as a table a
//! person reads, or as JSON a machine does.
//!
//! The whole image is scanned unless `--quick` says otherwise. Without a scan, an image
//! that is bad would still be *described*, and described accurately: a filesystem says what
//! it says whatever the rest of the image holds. The scan is what turns a description into a
//! verdict.
//!
//! # The shape of a report
//!
//! Every report is a family-tagged envelope: a head that means the same thing whatever the
//! image holds — which family, which variant of it, how large, what it allocates in, what
//! identifies it, and what a scan found — and then a body that is entirely that family's
//! own. A consumer that wants "is this sound and how big is it" reads the head and never
//! learns what a group descriptor is; one that wants ext4's geometry, or a FAT's parameter
//! block, reads the body.
//!
//! The findings sit in the head, because how serious a fault is and where in the bytes it
//! sits are the two things that mean the same for every format. In the table they come last
//! instead, because a person reads the description and then the verdict.
//!
//! # One spine, one body per family
//!
//! The image is opened through [`ferrosys::open_with`], which classifies it and hands back
//! the reader of whichever family claimed it. Everything above the `match` — the envelope,
//! the SARIF projection, the verdict, the exit code — is written once and knows no family;
//! everything below it is one module per family, each filling the same [`Head`] and
//! rendering its own body. A later family is a module and a `match` arm, and reshapes
//! nothing.

mod btrfs;
mod exfat;
mod ext;
mod fat;

use std::fs::File;

use ferrosys::{FindingReport, FsReader, OpenOptions, ReadPolicy};

use crate::args::InspectArgs;
use crate::{Error, emit, render};

/// The part of a report that means the same thing whatever family the image holds.
///
/// Built by whichever family answered, so a later family fills in the same five fields and
/// adds a body rather than reshaping the document.
pub struct Head {
    /// The family, as a report names it: `ext`, `fat`, `exfat`, or `btrfs`.
    pub family: &'static str,
    /// The family's own sub-classification: `ext2`, `ext3`, `ext4`, `fat12`, `fat16`,
    /// `fat32`. The same word `ferrosys detect` prints — and for a family with nothing to
    /// sub-classify it is the family's own word, which is what `exfat` and `btrfs` carry.
    pub variant: &'static str,
    /// The filesystem's size in bytes — what it occupies, not what the file holding it is.
    pub size: u64,
    /// The unit the family allocates in, in bytes: a block for ext, a cluster for FAT and
    /// for exFAT, a sector for btrfs data.
    pub allocation_unit: u64,
    /// What identifies this filesystem: its UUID for ext, its volume serial number for FAT
    /// and for exFAT — different fields of different formats that happen to be the same
    /// width — and its filesystem id for btrfs, the one `blkid` reports and a `UUID=`
    /// mount names.
    pub identifier: String,
}

/// What one family made of the image: the head every family fills, what a scan found, and
/// that family's own description already rendered.
pub struct Report {
    /// The five fields that mean the same thing for every family.
    pub head: Head,
    /// The scan's findings, or `None` under `--quick`, where no scan ran and there is no
    /// verdict to reach.
    pub findings: Option<FindingReport>,
    /// The family's own description, in whichever dialect was asked for: the table's rows,
    /// or the JSON object that goes under the family's own key. Empty under `--sarif`,
    /// which projects the findings alone and never asks a family to describe anything.
    pub body: String,
}

/// Which dialect a family should render its body in.
///
/// Passed down rather than having each family render both, because a report is emitted in
/// one of them and building the other is work for nothing — and because `--sarif` asks for
/// neither.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dialect {
    /// The rows a person reads.
    Table,
    /// The object a machine reads, which the envelope splices under the family's key.
    Json,
    /// Neither: `--sarif` projects the findings and nothing else.
    None,
}

/// Report on the filesystem the arguments name.
pub fn run(args: InspectArgs) -> Result<(), Error> {
    let path = args.image.display().to_string();
    let file = File::open(&args.image).map_err(|e| Error::io(&args.image, e))?;

    // The read collects rather than aborts: an image is worth describing even when it is
    // malformed, and what to make of the deviations is the verdict's business, not the
    // reader's. `--fail-on` sets where that verdict's line falls.
    //
    // Opening goes through the root rather than through one family's reader, which is what
    // makes the envelope's family field an answer rather than a constant.
    let reader = ferrosys::open_with(
        file,
        &OpenOptions::new()
            .base(args.offset)
            .policy(ReadPolicy::Lenient),
    )
    .map_err(|source| Error::NotAFilesystem {
        path: path.clone(),
        source,
    })?;

    // SARIF is a findings dialect: it projects the scan alone, not the description the table
    // and JSON reports lead with, so no family is asked to render a body for it.
    let dialect = match (args.sarif, args.json) {
        (true, _) => Dialect::None,
        (false, true) => Dialect::Json,
        (false, false) => Dialect::Table,
    };

    let report = match reader {
        FsReader::Ext(reader) => ext::report(reader, &args, dialect)?,
        FsReader::Fat(reader) => fat::report(reader, &args, dialect)?,
        FsReader::ExFat(reader) => exfat::report(reader, &args, dialect)?,
        FsReader::Btrfs(reader) => btrfs::report(reader, &args, dialect)?,
        // A family the library compiled in and this command has no body for. The binary
        // compiles every family the library has, so nothing in this workspace reaches it;
        // it is here because the enum is `#[non_exhaustive]` and a newer library linked
        // against an older tool would.
        _ => return Err(Error::UnsupportedFamily),
    };

    if args.sarif {
        // The parser guarantees a scan ran (`--sarif` rejects `--quick`), so a `--sarif`
        // report is always present here.
        //
        // The image is located by a URI reference, not by the path as typed: SARIF's
        // `artifactLocation.uri` is a URI, and a path with a space or a `#` in it is not one.
        let sarif = report
            .findings
            .as_ref()
            .expect("--sarif requires a scan, enforced at parse time")
            .to_sarif(Some(&render::uri_reference(&args.image)));
        emit(sarif.as_bytes())?;
        emit(b"\n")?;
    } else if args.json {
        emit(json(&report, args.offset).as_bytes())?;
    } else {
        emit(table(&report).as_bytes())?;
    }

    // The verdict. A scan that was not run reaches none, and the parser refuses the one way
    // a caller could ask for both — `--quick` with `--fail-on` — so a threshold that arrives
    // here always has a scan to judge.
    if let (Some(findings), Some(threshold)) = (&report.findings, args.fail_on)
        && let Some(worst) = findings.worst_severity()
        && worst >= threshold
    {
        return Err(Error::Verdict {
            count: findings.findings().len(),
            worst,
            truncated: findings.is_truncated(),
        });
    }
    Ok(())
}

/// The envelope a person reads: the head, then the family's own description, then the
/// verdict.
fn table(report: &Report) -> String {
    let mut rows = render::Rows::report();
    rows.row("Filesystem family:", report.head.family);
    rows.row("Filesystem variant:", report.head.variant);
    rows.row("Filesystem size:", report.head.size);
    rows.row("Allocation unit:", report.head.allocation_unit);
    rows.row("Filesystem identifier:", &report.head.identifier);
    rows.blank();
    rows.text(&report.body);
    if let Some(findings) = &report.findings {
        rows.blank();
        rows.text(&findings.to_table());
    }
    rows.finish()
}

/// The envelope a machine reads: the head, the findings, then the family's own key.
fn json(report: &Report, offset: u64) -> String {
    crate::json::document(|o| {
        // The head: five fields and the findings, all of which mean the same thing whatever
        // family answered. A consumer reading only these never learns what a group is.
        o.str("family", report.head.family);
        o.str("variant", report.head.variant);
        o.u64("size", report.head.size);
        o.u64("allocation_unit", report.head.allocation_unit);
        o.str("identifier", &report.head.identifier);
        // Where in the file the filesystem begins -- the same field, spelled the same way,
        // that `detect --json` carries. A caller scanning a disk correlates the two
        // documents by it, and a report that dropped the coordinate would make the pair
        // that describes one partition impossible to line up.
        o.u64("offset", offset);
        // The findings' own rendering, spliced in as a value: it is already JSON, and
        // escaping a document that is already JSON would turn it into a string of JSON.
        // Absent under `--quick`, where no scan ran and there is no verdict to report.
        if let Some(findings) = &report.findings {
            o.raw("findings", &findings.to_json());
        }
        // The body: everything under this key is that family's own, and a later family adds
        // a key of its own beside it rather than reshaping anything above.
        o.raw(report.head.family, &report.body);
    })
}
