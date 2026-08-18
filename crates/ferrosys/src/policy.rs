//! How a read runs: where the filesystem begins, how strictly it is held to its format,
//! and what one read of an untrusted image may allocate.
//!
//! These are settings rather than machinery, and they are the same three whatever family
//! answers — so they are here, and a family that grows a knob of its own puts it on its own
//! open rather than widening these.
//!
//! This module is pure: it holds values and answers questions about them, and performs no
//! I/O.

use crate::finding::Severity;

/// The longest path any read here builds, matching Linux's `PATH_MAX`.
///
/// Two bounds rest on it, and they are the same bound seen from either end. A symbolic
/// link's target is a path, so a target longer than this is one nothing could resolve — and
/// a walked path is a path, so a tree nested deeply enough to build a longer one is building
/// something no consumer could act on. Neither format bounds either, and a well-formed image
/// of either family reaches neither.
///
/// Compiled where there is a reader to hold to it.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub(crate) const MAX_PATH: usize = 4096;

/// The most symbolic links a path resolution follows before calling it a loop, matching the
/// kernel's `MAXSYMLINKS`.
///
/// A cycle (`a -> b -> a`) is the obvious case, but a chain long enough to be an effective
/// denial of service is the one that matters on an image this crate did not write.
///
/// Here rather than in the family that first needed it, because the second family to resolve a
/// path through a link has to follow exactly as many: a budget that differed between them
/// would make one filesystem's `/bin/sh` reachable and another's not, over trees a
/// distribution builds the same way.
///
/// Compiled where there is a reader at all, since the one resolution every family is driven by
/// carries the budget whether or not a given format has a link to spend it on. Public at the
/// crate root beside the resolver's other bounds, and only there — one concept, one path. A
/// build carrying no family has no reader for it to bound, so the constant arrives with the
/// first family compiled in.
#[cfg(any(feature = "ext", feature = "fat", feature = "exfat", feature = "btrfs"))]
pub const MAX_SYMLINK_HOPS: u32 = 40;

/// The conformance-strictness policy a read applies: a threshold over [`Severity`].
///
/// Robustness — bounds-checking, never panicking on malformed input — is unconditional and
/// not governed by this. The policy decides only where the fatal line sits on the severity
/// scale.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ReadPolicy {
    /// Fatal at [`Severity::Conformance`] and above: the read fails on anything a
    /// conformant filesystem of that family would not carry, so what a strict read returns
    /// is a filesystem whose every field it recognized.
    #[default]
    Strict,
    /// Fatal at nothing: a lenient read collects every finding as structured data and
    /// rejects no image, so a malformed image is reported rather than refused. This is the
    /// reading a whole-image scan reports under.
    Lenient,
}

impl ReadPolicy {
    /// Whether a finding of this severity is fatal under the policy.
    #[must_use]
    pub fn is_fatal(self, severity: Severity) -> bool {
        match self {
            ReadPolicy::Strict => severity >= Severity::Conformance,
            ReadPolicy::Lenient => false,
        }
    }
}

/// Caps on what one read of an untrusted image may allocate.
///
/// **These are caller-imposed caps on top of bounds a reader applies regardless.** A count
/// or size field in an image is the image's own claim, so every read that allocates from
/// one is bounded by what the source could actually hold: a file cannot be larger than the
/// filesystem containing it, and a tree cannot hold more names than its blocks have room
/// for. Those structural bounds are always on and cannot reject a well-formed filesystem,
/// because a well-formed filesystem satisfies them by construction.
///
/// What is left for a caller is a *tighter* bound than the structure implies — reading a
/// 9 TiB image with a gigabyte of memory, say — and one read where no structural bound
/// exists at all ([`max_file_bytes`](Self::max_file_bytes)). The defaults impose none, so a
/// legitimate image of any size reads back at the default settings.
///
/// Where a cap is reached, the answer is an error rather than a short one — with a single
/// exception, the findings cap, because a report says in the document it emits that it
/// stopped. A caller extracting a file from a truncated read would otherwise write an
/// incomplete one and see success.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Limits {
    /// The most findings one scan reports before stopping and marking its report
    /// truncated. Defaults to
    /// [`FindingReport::MAX_FINDINGS`](crate::FindingReport::MAX_FINDINGS).
    pub max_findings: usize,
    /// The most entries one read gathers into a list before refusing. Defaults to no
    /// caller-imposed cap; a read is bounded regardless by the names the image's own
    /// storage has room to describe.
    ///
    /// A whole-tree walk answers to it everywhere. Where a family reads one structure whole
    /// — a single directory, or a file's run of storage — the same cap governs that list,
    /// so a caller reading an image far larger than the memory it has is bounded at each
    /// read rather than only across the tree. Each family's reader documents which of its
    /// reads this reaches.
    pub max_walk_entries: usize,
    /// The largest file a read will hand out, and the largest one an extraction will write.
    /// Defaults to no cap, which is the documented contract: a whole-file read trusts the
    /// size the image records.
    ///
    /// A file larger than this is an error, not a shortened buffer. To read part of a file
    /// deliberately, read into a caller-supplied buffer: that form is bounded by the buffer
    /// and reports how much of it was filled, so a partial read is representable rather
    /// than silent.
    ///
    /// It governs an extraction as well, and it has to. A sink streams a file through a
    /// fixed buffer, so a sink's own memory is bounded whatever the file claims — but what
    /// it *writes* follows the length the image declares, and a hole reads back as zeros.
    /// The cap is applied to that declared length before a byte is written, so a file a
    /// whole-file read would refuse is a file an extraction refuses too.
    ///
    /// This one has no structural bound behind it, and that is a property of the formats
    /// rather than an omission. A sparse file's holes cost no storage, so a file whose
    /// logical size dwarfs the filesystem holding it is well-formed and must read back at
    /// its full size — which makes a legitimate all-hole file indistinguishable from a
    /// crafted size field. Set this when reading an image that has not earned that trust,
    /// or scan it instead, which allocates nothing per logical block.
    pub max_file_bytes: u64,
}

impl Limits {
    /// No caller-imposed cap beyond the structural bounds a reader always applies, except
    /// on findings, which stop at
    /// [`FindingReport::MAX_FINDINGS`](crate::FindingReport::MAX_FINDINGS).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_findings: crate::finding::FindingReport::MAX_FINDINGS,
            max_walk_entries: usize::MAX,
            max_file_bytes: u64::MAX,
        }
    }

    /// Report at most `max` findings per scan.
    #[must_use]
    pub const fn max_findings(mut self, max: usize) -> Self {
        self.max_findings = max;
        self
    }

    /// Refuse a walk that would gather more than `max` entries.
    #[must_use]
    pub const fn max_walk_entries(mut self, max: usize) -> Self {
        self.max_walk_entries = max;
        self
    }

    /// Return at most `max` bytes per whole-file read.
    #[must_use]
    pub const fn max_file_bytes(mut self, max: u64) -> Self {
        self.max_file_bytes = max;
        self
    }
}

impl Default for Limits {
    /// The limits in [`Limits::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// How an image is opened without naming its family: where it begins, how strictly it is
/// read, and what it may allocate.
///
/// Every input to opening an image is a field here rather than a parameter, so a knob one
/// grows arrives as a field a caller may ignore.
///
/// These are the three inputs every family's reader takes. A knob only one family has — a
/// checksum seed to verify against, say — is on that family's own open, which is reached by
/// opening its reader directly rather than through here.
///
/// ```
/// # use ferrosys::{OpenOptions, ReadPolicy};
/// // A filesystem inside a partition, read leniently so a scan can describe what is wrong
/// // with it rather than the open refusing it.
/// let options = OpenOptions::new().base(1 << 20).policy(ReadPolicy::Lenient);
/// # let _ = options;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct OpenOptions {
    /// Byte offset within the source at which the filesystem begins — zero for a bare
    /// image, the partition's start for one inside a disk image. Every read is relative to
    /// it.
    pub base: u64,
    /// How strictly the image is held to its format. Defaults to [`ReadPolicy::Strict`].
    pub policy: ReadPolicy,
    /// Caps on what one read may allocate, over and above the structural bounds a reader
    /// always applies.
    pub limits: Limits,
}

impl OpenOptions {
    /// Open at the start of the source, strictly, with the default limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            base: 0,
            policy: ReadPolicy::Strict,
            limits: Limits::new(),
        }
    }

    /// Open a filesystem that begins `base` bytes into the source.
    #[must_use]
    pub const fn base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }

    /// Read under `policy`.
    #[must_use]
    pub const fn policy(mut self, policy: ReadPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Cap what one read may allocate.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{Limits, OpenOptions, ReadPolicy};
    use crate::finding::Severity;

    #[test]
    fn strict_is_fatal_from_conformance_up_and_lenient_never_is() {
        for severity in [
            Severity::Conformance,
            Severity::Integrity,
            Severity::Structural,
        ] {
            assert!(ReadPolicy::Strict.is_fatal(severity), "{severity:?}");
            assert!(!ReadPolicy::Lenient.is_fatal(severity), "{severity:?}");
        }
        // Cosmetic is below the line under either policy: it is a remark, not a fault.
        assert!(!ReadPolicy::Strict.is_fatal(Severity::Cosmetic));
        assert!(!ReadPolicy::Lenient.is_fatal(Severity::Cosmetic));
    }

    #[test]
    fn the_default_limits_cap_only_findings() {
        let limits = Limits::new();
        assert_eq!(limits.max_walk_entries, usize::MAX);
        assert_eq!(limits.max_file_bytes, u64::MAX);
        assert_eq!(
            limits.max_findings,
            crate::finding::FindingReport::MAX_FINDINGS
        );
        assert_eq!(Limits::default(), limits);
    }

    #[test]
    fn open_options_carry_what_they_were_given() {
        let options = OpenOptions::new()
            .base(1 << 20)
            .policy(ReadPolicy::Lenient)
            .limits(Limits::new().max_file_bytes(4096));
        assert_eq!(options.base, 1 << 20);
        assert_eq!(options.policy, ReadPolicy::Lenient);
        assert_eq!(options.limits.max_file_bytes, 4096);
        assert_eq!(OpenOptions::default(), OpenOptions::new());
    }
}
