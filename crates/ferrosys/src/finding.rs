//! What a scan found, in the vocabulary every family shares: a [`Severity`], a byte offset,
//! the [`Family`] that reported it, and that family's own description of the fault.
//!
//! The split here follows what is genuinely family-agnostic. **How serious a finding is**,
//! is: a structure that cannot be parsed, one that parses but fails its own checksum, one
//! that is valid but not what this crate emits, and one that is merely cosmetic are
//! statements about a finding rather than about any format. **Where it sits** mostly is: a
//! byte offset means the same thing in every image, while a block, a cluster, a group, and
//! an inode do not — so the offset is here and the rest is carried as the family's own
//! named coordinates. **What it is about** is not: `superblock` and `extent tree` are ext's
//! subsystem vocabulary, and a FAT's subsystems are its own.
//!
//! So a family keeps its typed taxonomy and projects into a [`Finding`], and everything
//! that renders — a JSON document, a SARIF log, a table a person reads, a threshold a
//! policy applies — is written once here against that projection rather than once per
//! family.
//!
//! This module is pure: it holds values and renders them, and performs no I/O.

use std::borrow::Cow;

use crate::json::{Array, Object};

/// How serious a deviation from what this crate emits is, ordered least to most serious so
/// a policy can set a fatal threshold over it.
///
/// The order is the comparison order: `Cosmetic < Conformance < Integrity < Structural`.
/// [`ReadPolicy::Strict`](crate::ReadPolicy) is fatal at [`Conformance`](Self::Conformance)
/// and above.
///
/// The domain is closed and the type is exhaustive: these four are the whole scale, and
/// adding a fifth *should* break a caller that switches on it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    /// Valid and harmless: a representation a conformant reader accepts without remark.
    Cosmetic,
    /// Valid for the format, but not the form this crate emits.
    Conformance,
    /// Parses, but fails its own checksum — the bytes are self-inconsistent.
    Integrity,
    /// Cannot be parsed further: a structure the reader must follow is unreadable or out of
    /// range.
    Structural,
}

// The scale a report prints and a caller sets a threshold on, in the order it is offered:
// least serious first, which is the comparison order and the order a `--fail-on` list reads.
crate::naming::named_choice!(Severity {
    Severity::Cosmetic => "cosmetic",
    Severity::Conformance => "conformance",
    Severity::Integrity => "integrity",
    Severity::Structural => "structural",
});

crate::naming::serialize_as_name!(Severity);

/// Which filesystem family reported a finding.
///
/// This is the bare tag, not a classification: [`Filesystem`](crate::Filesystem) is what
/// says *which* ext or *which* FAT an image holds, and a finding does not repeat it —
/// whatever carries a set of findings names the filesystem once.
///
/// A build compiles in the variants of the families it compiles in, so a build with no
/// family has no way to name one and no way to produce a finding either.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Family {
    /// The ext2/ext3/ext4 family.
    #[cfg(feature = "ext")]
    Ext,
    /// The FAT12/FAT16/FAT32 family.
    #[cfg(feature = "fat")]
    Fat,
    /// The exFAT family.
    #[cfg(feature = "exfat")]
    ExFat,
    /// The btrfs family.
    #[cfg(feature = "btrfs")]
    Btrfs,
}

impl Family {
    /// The lowercase name of this family, for a rendered report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        // One arm per compiled-in family. A build with no family compiles no variant, so
        // the type is uninhabited, the match has no arms, and there is no value to name.
        match self {
            #[cfg(feature = "ext")]
            Family::Ext => "ext",
            #[cfg(feature = "fat")]
            Family::Fat => "fat",
            #[cfg(feature = "exfat")]
            Family::ExFat => "exfat",
            #[cfg(feature = "btrfs")]
            Family::Btrfs => "btrfs",
        }
    }
}

crate::naming::serialize_as_name!(Family);

/// One named coordinate a family locates a finding by: `("group", 3)`, `("inode", 12)`,
/// `("cluster", 57)`.
///
/// The name is the family's own word for the thing it addresses, which is why it is a
/// string and not a variant: a root enum wide enough to hold every family's addressing
/// would grow once per family and mean nothing to any of them. What is shared is the shape
/// — a name and a number — and the rendering built on it.
pub type Coordinate = (Cow<'static, str>, u64);

/// A typed deviation from what a family's writer would emit, carrying its severity, where
/// it sits, and that family's own description.
///
/// This is the projection every family produces and every renderer consumes. A family's own
/// taxonomy is richer — it knows that a checksum failure was a group descriptor's rather
/// than an inode's, as a value rather than as a word — and that taxonomy stays with the
/// family; what crosses into here is what a report has to render and a policy has to
/// threshold.
///
/// A JSON record, a rendered table row, and a SARIF result are projections of this,
/// computed in [`FindingReport`] rather than at the edge: a projection written outside this
/// crate would enumerate the fields from outside, where `#[non_exhaustive]` blocks the
/// exhaustive destructure that keeps it complete, so a fact learned about a finding would
/// silently stop being reported.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Finding {
    /// How serious the deviation is.
    pub severity: Severity,
    /// The family that found it.
    pub family: Family,
    /// The subsystem it was found in, in the family's own vocabulary.
    pub category: Cow<'static, str>,
    /// Byte offset within the image, when the finding is at a known one. Absent where the
    /// family locates the fault by something it cannot convert — a group, an inode number,
    /// a directory entry — rather than by a place in the bytes.
    pub offset: Option<u64>,
    /// The family's own coordinates, in the order it reports them. Empty when the finding
    /// is about the image as a whole.
    pub coordinates: Vec<Coordinate>,
    /// A human-readable description.
    pub detail: String,
}

/// The version of the emitted findings schema — the JSON a report renders and the record
/// each finding renders within it.
///
/// The Rust types are pinned by the compiler and by the crate's API snapshot; the *emitted
/// document* is a contract of its own that neither of those sees, so it carries a version a
/// consumer can branch on. It changes only when the shape changes: a field added, renamed,
/// or removed, or a value's spelling altered. The [SARIF](FindingReport::to_sarif)
/// projection is versioned by SARIF itself and does not carry this.
pub const FINDINGS_SCHEMA_VERSION: u32 = 2;

/// A set of findings and what the scan that produced them managed to look at.
///
/// A lenient read rejects no image, so an empty report means the image is conformant to
/// what its family's writer emits and a non-empty one is a list of findings, not a failure.
/// [`has_fatal`](Self::has_fatal) applies a [`ReadPolicy`](crate::ReadPolicy) threshold back
/// to those findings, and [`to_json`](Self::to_json), [`to_sarif`](Self::to_sarif), and
/// [`to_table`](Self::to_table) project them for a machine or a person.
///
/// A report says through [`is_truncated`](Self::is_truncated) when the scan stopped at its
/// findings cap with the image still unfinished.
/// # Two serializations, and which is the document
///
/// [`to_json`](Self::to_json) and [`to_sarif`](Self::to_sarif) emit *documents*: a shape
/// this crate versions through [`FINDINGS_SCHEMA_VERSION`], leading with that version and
/// with the verdict and count computed from the findings. That is what a consumer parses.
///
/// The `serde` implementation is something else, and deliberately: it serializes the Rust
/// value as it stands, so a caller embedding a report inside a structure of its own gets the
/// fields the type has and nothing derived. It carries no schema version, because it is not
/// the schema. Where the two describe the same thing they agree — a severity and a family
/// are spelled the same in both — and a [`Coordinate`] is a tuple in one and an object in
/// the other because in one it is a Rust tuple and in the other it is a document field.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FindingReport {
    findings: Vec<Finding>,
    truncated: bool,
    /// The findings cap the scan that produced this report ran under, which a caller may
    /// set to anything. Kept so a truncation notice names the bound that actually applied
    /// rather than the default constant, which need not be the same number.
    ///
    /// It is not serialized: the cap is a property of the scan that ran, not of the
    /// report's findings, and `truncated` already says whether it was reached.
    #[cfg_attr(feature = "serde", serde(skip))]
    cap: usize,
}

impl Default for FindingReport {
    /// An empty report from a scan under the default limits.
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            truncated: false,
            cap: Self::MAX_FINDINGS,
        }
    }
}

impl FindingReport {
    /// The default of [`Limits::max_findings`](crate::Limits::max_findings): the most
    /// findings one report holds unless a caller names another cap.
    ///
    /// A scan reads an image it has no reason to trust, and how many findings that image
    /// yields is the image's own claim: a handful of crafted structures can name the same
    /// blocks over and over, and each faulty one is a finding carrying an owned
    /// description. The cap is what keeps a report's memory a property of this crate rather
    /// than of the bytes it was pointed at, and it is far past the count anyone reads: a
    /// filesystem with ten thousand findings is diagnosed by its first ten.
    pub const MAX_FINDINGS: usize = 10_000;

    /// A report holding `findings`, from a scan that ran under `cap` and stopped early if
    /// `truncated`.
    ///
    /// A family builds one of these from its own taxonomy; nothing else needs to.
    #[must_use]
    pub fn new(findings: Vec<Finding>, truncated: bool, cap: usize) -> Self {
        Self {
            findings,
            truncated,
            cap,
        }
    }

    /// The findings, in the order the scan walked them.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Whether the scan stopped at its findings cap with the image still unfinished.
    ///
    /// A truncated report is a floor, not a full accounting: the image holds at least these
    /// findings, and the scan did not look at the rest of it. Everything derived from the
    /// report — [`worst_severity`](Self::worst_severity), [`has_fatal`](Self::has_fatal) —
    /// is likewise a floor, and [`is_clean`](Self::is_clean) is `false` whatever the report
    /// holds, since a scan that stopped short has seen nothing that would let it call an
    /// image clean.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Whether the scan looked at the whole image and found nothing.
    ///
    /// A [`truncated`](Self::is_truncated) report is never clean, however few findings it
    /// holds. The cap can be set low enough that a scan stops before reporting anything —
    /// at zero, before reading a single structure — and an empty report from a scan that
    /// stopped is an absence of looking, not an absence of faults.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.truncated && self.findings.is_empty()
    }

    /// The severity of the most serious finding, or `None` when the report is clean.
    #[must_use]
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Whether any finding is fatal under `policy` — the same threshold
    /// [`ReadPolicy::Strict`](crate::ReadPolicy) enforces when opening an image. Under
    /// [`ReadPolicy::Lenient`](crate::ReadPolicy) it is always `false`.
    #[must_use]
    pub fn has_fatal(&self, policy: crate::ReadPolicy) -> bool {
        self.findings.iter().any(|f| policy.is_fatal(f.severity))
    }

    /// Render the report as a JSON object: `schema`, `clean` (bool), `count`, `truncated`
    /// (bool), and a `findings` array. A projection computed here, not a stored wire
    /// format.
    ///
    /// `truncated` is always present, true or false: a consumer must be able to tell a
    /// complete report from one that stopped at its findings cap, and an absent field would
    /// read as complete.
    ///
    /// The document opens with `"schema"`, holding [`FINDINGS_SCHEMA_VERSION`]. A
    /// downstream parser has a contract that no Rust signature describes, so the emitted
    /// shape names its own version rather than leaving a change to be discovered by a parse
    /// failure.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let mut o = Object::new(&mut out);
        o.u64("schema", u64::from(FINDINGS_SCHEMA_VERSION));
        o.bool("clean", self.is_clean());
        o.u64("count", self.findings.len() as u64);
        o.bool("truncated", self.truncated);
        let mut findings = o.arr("findings");
        for f in &self.findings {
            push_finding_json(findings.obj(), f);
        }
        findings.end();
        o.end();
        out
    }

    /// Render the report as a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log: a
    /// single run whose tool is this crate and whose results are the findings, one per
    /// finding, for a static-analysis or forensic pipeline that speaks SARIF.
    ///
    /// Severity maps onto SARIF's three actionable levels — `structural` and `integrity`
    /// are `error`, `conformance` is `warning`, `cosmetic` is `note` — and the exact
    /// severity, family, subsystem, byte offset, and coordinates ride in each result's
    /// `properties`, so nothing the level collapse would lose is lost. The coordinates
    /// become a SARIF logical location, and a known byte offset becomes the physical
    /// location's address. Like [`to_json`](Self::to_json), the document is a pure function
    /// of the report — no tool version or timestamp enters it — so identical findings
    /// render identical bytes.
    ///
    /// A report that stopped at its findings cap carries a warning-level
    /// `toolExecutionNotifications` entry saying so, naming the cap that applied, which is
    /// where SARIF records something about the run rather than about the artifact. A
    /// complete report emits no `invocations` at all, so the document a clean or short scan
    /// renders is unchanged by the cap existing.
    ///
    /// `artifact_uri`, when set, becomes each result's physical artifact location: a reader
    /// reads an anonymous stream, so the image's identity is the caller's to supply. It is
    /// written through unchanged, which makes it a precondition that the string is already
    /// a URI reference as [RFC 3986] defines one. A host path is not: a space is not
    /// allowed in a URI at all, and `#`, `?`, and `%` each mean something else, so a strict
    /// SARIF consumer rejects a document carrying one. Percent-encode a path — every byte
    /// outside `A`-`Z`, `a`-`z`, `0`-`9`, `-`, `.`, `_`, `~`, keeping `/` — before passing
    /// it here.
    ///
    /// [RFC 3986]: https://www.rfc-editor.org/rfc/rfc3986
    #[must_use]
    pub fn to_sarif(&self, artifact_uri: Option<&str>) -> String {
        let mut out = String::new();
        let mut doc = Object::new(&mut out);
        doc.str("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        doc.str("version", "2.1.0");
        let mut runs = doc.arr("runs");
        let mut run = runs.obj();

        let mut tool = run.obj("tool");
        let mut driver = tool.obj("driver");
        driver.str("name", "ferrosys");
        push_sarif_rules(driver.arr("rules"), &self.findings);
        driver.end();
        tool.end();

        let mut results = run.arr("results");
        for f in &self.findings {
            push_sarif_result(results.obj(), f, artifact_uri);
        }
        results.end();

        if self.truncated {
            let mut invocations = run.arr("invocations");
            let mut invocation = invocations.obj();
            // `executionSuccessful` is required of an invocation: the scan did run to the
            // cap, so it succeeded — the notification is what says the results stop short of
            // the image.
            invocation.bool("executionSuccessful", true);
            let mut notifications = invocation.arr("toolExecutionNotifications");
            let mut notification = notifications.obj();
            notification.str("level", "warning");
            let mut message = notification.obj("message");
            message.str("text", &self.truncation_notice());
            message.end();
            notification.end();
            notifications.end();
            invocation.end();
            invocations.end();
        }

        run.end();
        runs.end();
        doc.end();
        out
    }

    /// Render the report as a fixed-column human table: a header row, then one line per
    /// finding with its severity, category, location, and detail. A clean report renders a
    /// single `no findings` line.
    ///
    /// A [`truncated`](Self::is_truncated) report ends with the notice saying so, whether
    /// or not it holds findings — an empty one is the case where saying so matters most,
    /// since `no findings` on its own would read as a verdict the scan never reached.
    #[must_use]
    pub fn to_table(&self) -> String {
        if self.findings.is_empty() {
            let mut out = String::from("no findings\n");
            if self.truncated {
                out.push('\n');
                out.push_str(&self.truncation_notice());
                out.push('\n');
            }
            return out;
        }
        let rows: Vec<(&str, &str, String, &str)> = self
            .findings
            .iter()
            .map(|f| {
                (
                    f.severity.as_str(),
                    f.category.as_ref(),
                    location_compact(f),
                    f.detail.as_str(),
                )
            })
            .collect();
        let mut sev_w = "SEVERITY".len();
        let mut cat_w = "CATEGORY".len();
        let mut loc_w = "LOCATION".len();
        for (s, c, l, _) in &rows {
            sev_w = sev_w.max(s.len());
            cat_w = cat_w.max(c.len());
            loc_w = loc_w.max(l.len());
        }
        let mut out = format!(
            "{:<sev_w$}  {:<cat_w$}  {:<loc_w$}  {}\n",
            "SEVERITY", "CATEGORY", "LOCATION", "DETAIL"
        );
        for (s, c, l, d) in &rows {
            out.push_str(&format!("{s:<sev_w$}  {c:<cat_w$}  {l:<loc_w$}  {d}\n"));
        }
        if self.truncated {
            out.push('\n');
            out.push_str(&self.truncation_notice());
            out.push('\n');
        }
        out
    }

    /// The one sentence a truncated report renders, in whichever projection asks for it.
    ///
    /// It names the cap the scan actually ran under, which is a caller's
    /// [`Limits::max_findings`](crate::Limits::max_findings) and not necessarily
    /// [`MAX_FINDINGS`](Self::MAX_FINDINGS): a report that stopped at seven findings
    /// because seven is what was asked for must not say it stopped at ten thousand.
    fn truncation_notice(&self) -> String {
        format!(
            "report truncated at {} findings; the rest of the image was not scanned",
            self.cap
        )
    }
}

/// A family's own typed deviation from what its writer emits, and how it reaches the shared
/// frame.
///
/// Each family keeps its taxonomy typed and its own — its subsystem as a value rather than a
/// word, its location in the coordinates that family's consumers reason about. This is the
/// two things everything above a family needs of one regardless: how serious it is, and what
/// it looks like as a [`Finding`].
pub trait Deviation {
    /// How serious the deviation is.
    fn severity(&self) -> Severity;

    /// Project into the family-agnostic frame, resolving a location addressed in units of
    /// `unit` bytes to the byte offset a [`Finding`] carries.
    ///
    /// The unit is the family's addressing unit — a block for ext, a sector for a FAT — and
    /// it is supplied rather than carried by the deviation because it is a property of the
    /// filesystem the scan ran over rather than of any one finding in it.
    fn to_finding(&self, unit: u32) -> Finding;
}

/// Build a [`Finding`] from a family's severity, subsystem, description, and named
/// coordinates, resolving the one coordinate that addresses bytes into an offset.
///
/// Every family's projection is this shape: name the coordinates outermost first, drop the
/// ones the deviation does not carry, and turn the unit-addressed one into a byte offset
/// under the filesystem's addressing unit. What differs between them is *which* coordinates
/// and which of those addresses bytes — a block for ext, a sector for a FAT — so those are
/// the arguments and the rest is here.
///
/// `coordinates` are `(name, value)` pairs in the order the family reports them, and a `None`
/// value is a coordinate this deviation does not have. `addressed` is the value that counts
/// in units of `unit` bytes, or [`None`] where the deviation is located only by something
/// whose place depends on the layout rather than on the number — a group, an inode, a
/// cluster — and so carries no offset.
///
/// The multiplication is checked. A block or sector number out of an untrusted image can be
/// anything, and a product that does not fit means the unit is not in the image at all, so
/// there is no offset to name rather than a wrapped one to name wrongly.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) fn project(
    severity: Severity,
    family: Family,
    category: &'static str,
    coordinates: &[(&'static str, Option<u64>)],
    addressed: Option<u64>,
    unit: u32,
    detail: &str,
) -> Finding {
    Finding {
        severity,
        family,
        category: Cow::Borrowed(category),
        offset: addressed.and_then(|value| value.checked_mul(u64::from(unit))),
        coordinates: coordinates
            .iter()
            .filter_map(|&(name, value)| value.map(|value| (Cow::Borrowed(name), value)))
            .collect(),
        detail: detail.to_string(),
    }
}

/// What a whole-filesystem scan found: every [`Deviation`] it met, in the order it walked
/// them.
///
/// A lenient read rejects no image, so an empty report means the filesystem is conformant to
/// what this crate's writer for that family emits, and a non-empty one is a list of findings
/// rather than a failure. [`has_fatal`](Self::has_fatal) applies a
/// [`ReadPolicy`](crate::ReadPolicy) threshold back to those findings.
///
/// This holds the family's own taxonomy, kept typed, which is what a consumer reasoning about
/// that format wants. Rendering it — as JSON, as SARIF, as a table — goes through
/// [`to_report`](Self::to_report), which projects into [`FindingReport`] so one document shape
/// serves every family.
///
/// A report holds at most [`Limits::max_findings`](crate::Limits::max_findings) deviations and
/// says so through [`is_truncated`](Self::is_truncated) when it stopped there.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ScanReport<A> {
    anomalies: Vec<A>,
    truncated: bool,
    /// The findings cap the scan that produced this report ran under — the
    /// [`Limits::max_findings`](crate::Limits::max_findings) it was opened with, which a
    /// caller may set to anything. Kept so a truncation notice names the bound that actually
    /// applied rather than the default constant, which need not be the same number.
    ///
    /// It is not serialized: the cap is a property of the scan that ran, not of the report's
    /// findings, and `truncated` already says whether it was reached.
    #[cfg_attr(feature = "serde", serde(skip))]
    cap: usize,
    /// The addressing unit of the filesystem scanned, in bytes, which turns a location into
    /// the byte offset a [`Finding`] carries. Zero for a report no scan produced, where there
    /// is nothing to convert.
    ///
    /// Not serialized for the same reason the cap is not: it describes the filesystem the
    /// scan ran over rather than any finding in it.
    #[cfg_attr(feature = "serde", serde(skip))]
    unit: u32,
}

impl<A> Default for ScanReport<A> {
    /// An empty report from a scan under the default limits.
    fn default() -> Self {
        Self {
            anomalies: Vec::new(),
            truncated: false,
            cap: FindingReport::MAX_FINDINGS,
            unit: 0,
        }
    }
}

impl<A> ScanReport<A> {
    /// The deviations found, in scan order.
    #[must_use]
    pub fn anomalies(&self) -> &[A] {
        &self.anomalies
    }

    /// Whether the scan stopped at its findings cap with the filesystem still unfinished.
    ///
    /// A truncated report is a floor, not a full accounting: the filesystem holds at least
    /// these findings, and the scan did not look at the rest of it. Everything derived from
    /// the report — [`worst_severity`](Self::worst_severity), [`has_fatal`](Self::has_fatal)
    /// — is likewise a floor, and [`is_clean`](Self::is_clean) is `false` whatever the report
    /// holds, since a scan that stopped short has seen nothing that would let it call a
    /// filesystem clean.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Whether the scan looked at the whole filesystem and found nothing.
    ///
    /// A [`truncated`](Self::is_truncated) report is never clean, however few findings it
    /// holds. The cap can be set low enough that a scan stops before reporting anything — at
    /// zero, before reading a single structure — and an empty report from a scan that stopped
    /// is an absence of looking, not an absence of faults.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.truncated && self.anomalies.is_empty()
    }
}

impl<A: Deviation> ScanReport<A> {
    /// A report holding `anomalies`, from a scan that ran under `cap` over a filesystem
    /// addressing in units of `unit` bytes, and stopped early if `truncated`.
    ///
    /// Compiled where a family is: with none there is no scan to produce one.
    #[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
    pub(crate) fn new(anomalies: Vec<A>, truncated: bool, cap: usize, unit: u32) -> Self {
        Self {
            anomalies,
            truncated,
            cap,
            unit,
        }
    }

    /// The severity of the most serious deviation, or `None` when the report is clean.
    #[must_use]
    pub fn worst_severity(&self) -> Option<Severity> {
        self.anomalies.iter().map(Deviation::severity).max()
    }

    /// Whether any deviation the scan found is fatal under `policy` — the same threshold
    /// [`ReadPolicy::Strict`] enforces when opening a filesystem. Under
    /// [`ReadPolicy::Lenient`] it is always `false`.
    ///
    /// This is the scan's verdict, which is not the whole of a strict read. A scan checks the
    /// metadata a strict read checks, but it does not follow every path, so a fault only a
    /// full read reaches leaves the scan clean while the read that reaches it still fails.
    ///
    /// [`ReadPolicy::Strict`]: crate::ReadPolicy::Strict
    /// [`ReadPolicy::Lenient`]: crate::ReadPolicy::Lenient
    #[must_use]
    pub fn has_fatal(&self, policy: crate::ReadPolicy) -> bool {
        self.anomalies.iter().any(|a| policy.is_fatal(a.severity()))
    }

    /// Project the report into the crate's family-agnostic frame, which is what renders.
    ///
    /// Each deviation becomes a [`Finding`] carrying the same severity, its family's own
    /// subsystem word as the category, its coordinates under that family's own names, and —
    /// where the location resolves to one — the byte offset it sits at. Truncation and the cap
    /// that caused it carry across, so the projected report says the same thing about how much
    /// of the filesystem was looked at.
    #[must_use]
    pub fn to_report(&self) -> FindingReport {
        let findings = self
            .anomalies
            .iter()
            .map(|a| a.to_finding(self.unit))
            .collect();
        FindingReport::new(findings, self.truncated, self.cap)
    }
}

/// A bounded accumulator of deviations, which is what a scan collects into.
///
/// The bound is the whole reason it exists: how many deviations a filesystem yields is that
/// filesystem's own claim, and a handful of crafted structures can name the same blocks over
/// and over. A scan that collected all of them would have its memory decided by the bytes it
/// was pointed at.
///
/// Pushing past the cap drops the deviation and records the truncation, so what a scan holds
/// never exceeds what its report will carry. [`is_full`](Self::is_full) is what lets a scan
/// stop *looking* as well, rather than reading the rest of a filesystem for findings it would
/// discard.
///
/// Compiled where a family is: with none there is no scan to collect into one.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) struct Findings<A> {
    anomalies: Vec<A>,
    cap: usize,
    truncated: bool,
}

#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
impl<A> Findings<A> {
    /// An empty accumulator holding at most `cap` deviations.
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            anomalies: Vec::new(),
            cap,
            truncated: false,
        }
    }

    /// Record `anomaly`, or record that it was dropped because the cap was reached.
    pub(crate) fn push(&mut self, anomaly: A) {
        if self.anomalies.len() >= self.cap {
            self.truncated = true;
        } else {
            self.anomalies.push(anomaly);
        }
    }

    /// Whether the cap has been reached, so a scan may stop looking rather than keep reading
    /// a filesystem for deviations it would discard.
    ///
    /// Asking is not idle, which is why this takes `&mut self`: a scan that stops here has
    /// not looked at the rest of the filesystem, so reaching the cap *is* the truncation and
    /// is recorded as one. That is what makes a cap of zero produce an empty report that is
    /// not clean — an absence of findings from a scan that never looked is not a verdict
    /// about the image.
    pub(crate) fn is_full(&mut self) -> bool {
        if self.anomalies.len() >= self.cap {
            self.truncated = true;
        }
        self.truncated
    }
}

#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
impl<A: Deviation> Findings<A> {
    /// The report these deviations make, over a filesystem addressing in units of `unit`
    /// bytes.
    pub(crate) fn into_report(self, unit: u32) -> ScanReport<A> {
        ScanReport::new(self.anomalies, self.truncated, self.cap, unit)
    }
}

/// Write one finding into `o`: `severity`, `family`, `category`, an `offset` when one is
/// known, a `location` holding the family's own coordinates, and the `detail`.
fn push_finding_json(mut o: Object<'_>, f: &Finding) {
    // Destructured exhaustively on purpose: a field added to `Finding` is a compile error
    // here, which forces a decision about the emitted record rather than letting a new fact
    // about a finding go silently unreported.
    let Finding {
        severity,
        family,
        category,
        offset,
        coordinates,
        detail,
    } = f;
    o.str("severity", severity.as_str());
    o.str("family", family.as_str());
    o.str("category", category);
    if let Some(offset) = offset {
        o.u64("offset", *offset);
    }
    push_coordinates_json(o.obj("location"), coordinates);
    o.str("detail", detail);
    o.end();
}

/// Write a finding's coordinates into `o`, one member per coordinate in the order the family
/// reported them.
fn push_coordinates_json(mut o: Object<'_>, coordinates: &[Coordinate]) {
    for (name, value) in coordinates {
        o.u64(name, *value);
    }
    o.end();
}

/// A compact one-line location for the human table: the coordinates as `name value`, joined
/// by spaces, or `-` when the finding carries none.
fn location_compact(f: &Finding) -> String {
    if f.coordinates.is_empty() {
        return "-".to_string();
    }
    f.coordinates
        .iter()
        .map(|(name, value)| format!("{name} {value}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The SARIF result level a severity maps to. SARIF offers three actionable levels;
/// `structural` and `integrity` both mean the image is unsound, so both are `error`, and
/// the exact severity is preserved in the result's `properties`.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Structural | Severity::Integrity => "error",
        Severity::Conformance => "warning",
        Severity::Cosmetic => "note",
    }
}

/// Append the SARIF `rules` array: one rule per distinct category present, in the order the
/// categories first appear, so every `ruleId` a result names is defined without emitting a
/// rule for a subsystem the scan said nothing about.
///
/// A rule is identified by `family/category`, because two families' subsystems may share a
/// word — a `directory` finding about a FAT is not a `directory` finding about an ext4 — and
/// a SARIF consumer grouping by `ruleId` would otherwise merge them.
fn push_sarif_rules(mut rules: Array<'_>, findings: &[Finding]) {
    let mut seen: Vec<String> = Vec::new();
    for f in findings {
        let id = rule_id(f);
        if seen.contains(&id) {
            continue;
        }
        let mut rule = rules.obj();
        rule.str("id", &id);
        rule.str("name", &id);
        let mut description = rule.obj("shortDescription");
        description.str(
            "text",
            &format!("{} {} finding", f.family.as_str(), f.category),
        );
        description.end();
        rule.end();
        seen.push(id);
    }
    rules.end();
}

/// The SARIF rule a finding belongs to: the family and its own subsystem word.
fn rule_id(f: &Finding) -> String {
    format!("{}/{}", f.family.as_str(), f.category)
}

/// Append one SARIF result: its rule, level (from the severity), message (the detail), a
/// location carrying the artifact, the byte offset, and the logical address when any is
/// known, and the full typed value in `properties`.
fn push_sarif_result(mut result: Object<'_>, f: &Finding, artifact_uri: Option<&str>) {
    result.str("ruleId", &rule_id(f));
    result.str("level", sarif_level(f.severity));
    let mut message = result.obj("message");
    message.str("text", &f.detail);
    message.end();

    // Emit `locations` only when there is something to record: an empty location object
    // would carry nothing.
    let has_address = !f.coordinates.is_empty();
    if artifact_uri.is_some() || f.offset.is_some() || has_address {
        let mut locations = result.arr("locations");
        let mut location = locations.obj();
        if artifact_uri.is_some() || f.offset.is_some() {
            let mut physical = location.obj("physicalLocation");
            if let Some(uri) = artifact_uri {
                let mut artifact = physical.obj("artifactLocation");
                artifact.str("uri", uri);
                artifact.end();
            }
            if let Some(offset) = f.offset {
                let mut address = physical.obj("address");
                address.u64("absoluteAddress", offset);
                address.end();
            }
            physical.end();
        }
        if has_address {
            let mut logical = location.arr("logicalLocations");
            let mut named = logical.obj();
            named.str("fullyQualifiedName", &location_compact(f));
            named.end();
            logical.end();
        }
        location.end();
        locations.end();
    }

    push_sarif_properties(result.obj("properties"), f);
    result.end();
}

/// Append the SARIF `properties` bag: the exact severity, family, and category as strings,
/// the byte offset when known, and each coordinate — everything SARIF's three-level `level`
/// and its location model cannot themselves carry.
fn push_sarif_properties(mut o: Object<'_>, f: &Finding) {
    o.str("severity", f.severity.as_str());
    o.str("family", f.family.as_str());
    o.str("category", &f.category);
    if let Some(offset) = f.offset {
        o.u64("offset", offset);
    }
    for (name, value) in &f.coordinates {
        o.u64(name, *value);
    }
    o.end();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every case here needs a family to attribute a finding to, and a build with no family
    /// compiles no `Family` variant. The rendering is the same whichever family reports it,
    /// so one is enough.
    #[cfg(feature = "ext")]
    fn finding(
        severity: Severity,
        category: &'static str,
        coords: &[(&'static str, u64)],
    ) -> Finding {
        Finding {
            severity,
            family: Family::Ext,
            category: Cow::Borrowed(category),
            offset: None,
            coordinates: coords
                .iter()
                .map(|(n, v)| (Cow::Borrowed(*n), *v))
                .collect(),
            detail: "something is wrong".to_string(),
        }
    }

    #[test]
    fn severity_orders_least_to_most_serious() {
        // A policy sets its fatal line by comparison, so the order is the contract.
        assert!(Severity::Cosmetic < Severity::Conformance);
        assert!(Severity::Conformance < Severity::Integrity);
        assert!(Severity::Integrity < Severity::Structural);
    }

    #[cfg(feature = "ext")]
    #[test]
    fn a_finding_renders_its_coordinates_as_a_location_object() {
        let mut f = finding(Severity::Integrity, "group descriptor", &[("group", 3)]);
        f.offset = Some(4096);
        let report = FindingReport::new(vec![f], false, 10);
        let json = report.to_json();
        assert!(json.contains("\"family\":\"ext\""), "{json}");
        assert!(json.contains("\"category\":\"group descriptor\""), "{json}");
        assert!(json.contains("\"offset\":4096"), "{json}");
        assert!(json.contains("\"location\":{\"group\":3}"), "{json}");
    }

    #[cfg(feature = "ext")]
    #[test]
    fn a_finding_with_no_coordinates_renders_an_empty_location() {
        // The member is always present, so a consumer reads one shape rather than two.
        let report = FindingReport::new(
            vec![finding(Severity::Cosmetic, "superblock", &[])],
            false,
            10,
        );
        assert!(report.to_json().contains("\"location\":{}"));
        // And the table says so rather than leaving the column blank.
        assert!(report.to_table().contains(" -  "));
    }

    #[cfg(feature = "ext")]
    #[test]
    fn a_clean_report_is_clean_and_a_truncated_one_never_is() {
        let clean = FindingReport::default();
        assert!(clean.is_clean());
        assert_eq!(clean.worst_severity(), None);
        assert_eq!(clean.to_table(), "no findings\n");

        // A scan that stopped short has seen nothing that would let it call an image clean,
        // however few findings it gathered on the way.
        let stopped = FindingReport::new(Vec::new(), true, 0);
        assert!(!stopped.is_clean());
        let table = stopped.to_table();
        assert!(table.contains("truncated at 0 findings"), "{table}");
        assert!(stopped.to_json().contains("\"truncated\":true"));
    }

    #[cfg(feature = "ext")]
    #[test]
    fn the_worst_severity_is_the_maximum() {
        let report = FindingReport::new(
            vec![
                finding(Severity::Cosmetic, "superblock", &[]),
                finding(Severity::Structural, "inode", &[("inode", 12)]),
                finding(Severity::Conformance, "directory", &[]),
            ],
            false,
            10,
        );
        assert_eq!(report.worst_severity(), Some(Severity::Structural));
    }

    #[cfg(feature = "ext")]
    #[test]
    fn a_sarif_rule_is_named_for_the_family_as_well_as_the_subsystem() {
        // Two families can both call a subsystem `directory`, and a consumer grouping by
        // ruleId would merge findings about different formats if the family were dropped.
        let report = FindingReport::new(
            vec![finding(Severity::Structural, "directory", &[])],
            false,
            10,
        );
        let sarif = report.to_sarif(None);
        assert!(sarif.contains("\"id\":\"ext/directory\""), "{sarif}");
        assert!(sarif.contains("\"ruleId\":\"ext/directory\""), "{sarif}");
        assert!(sarif.contains("\"level\":\"error\""), "{sarif}");
    }

    #[cfg(feature = "ext")]
    #[test]
    fn a_known_byte_offset_becomes_a_sarif_address() {
        let mut f = finding(Severity::Integrity, "superblock", &[]);
        f.offset = Some(1024);
        let sarif = FindingReport::new(vec![f], false, 10).to_sarif(None);
        assert!(sarif.contains("\"absoluteAddress\":1024"), "{sarif}");
    }

    #[cfg(feature = "ext")]
    #[test]
    fn a_detail_reaches_a_document_escaped() {
        // A finding's detail carries the image's own bytes, and both projections put it in
        // a JSON string. The escaping is `crate::escape`'s and is tested there; what is
        // asserted here is that the projections go through it, so nothing an image chose
        // reaches a document able to act on whatever prints it.
        let mut f = finding(Severity::Structural, "directory", &[]);
        f.detail = "a name \u{1b}[2J\u{202e} chose".to_string();
        for document in [
            FindingReport::new(vec![f.clone()], false, 10).to_json(),
            FindingReport::new(vec![f], false, 10).to_sarif(None),
        ] {
            assert!(document.contains(r"\u001b[2J\u202e chose"), "{document}");
            assert!(!document.chars().any(char::is_control), "{document}");
        }
    }
}
