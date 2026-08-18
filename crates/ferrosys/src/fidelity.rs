//! What a filesystem could not carry, and what a read had to invent: the
//! [`FidelityReport`] and the [`Synthesis`] values a read fills a missing field with.
//!
//! Filesystems do not record the same things. A tree carrying ownership, permission bits,
//! symbolic links, and extended attributes goes into an ext4 image whole and into a FAT
//! image not at all, because the FAT directory entry has no field for any of it. That is a
//! property of the format rather than a limitation of this crate, and it runs in both
//! directions: writing *into* a format that cannot hold a property loses it, and reading
//! *out of* one that never had it means something has to invent a value before a host file
//! can be created.
//!
//! Both are the same question asked twice — a caller writing a tar into a FAT image and
//! extracting a FAT image into a tar wants the same accounting — so one report carries
//! both, and each record says which direction it is.
//!
//! # The default is to refuse
//!
//! A build that would lose a property fails, naming the entry and the property, unless the
//! caller has said it accepts the loss. A root filesystem written to FAT with silently
//! dropped permission bits is a filesystem where every file is world-writable and every
//! setuid binary has lost its bit, and nothing in the output says so. Refusing until the
//! caller acknowledges the loss is the version of "the gap is documented" that cannot be
//! missed.
//!
//! Synthesis on the read side is not refused — a file has to be created with *some* owner
//! and *some* mode — so it is stated instead: the values are [`Synthesis`] inputs with
//! documented defaults, and every one applied is recorded. The defaults are the
//! conservative ones, because a tool that silently extracts a FAT tree as world-writable
//! has produced a security bug out of a format limitation, and no report after the fact
//! makes that acceptable.
//!
//! This module is pure: it holds values and renders them, and performs no I/O.

/// A property of an entry that a filesystem may or may not record.
///
/// Named at the granularity a caller acts on. The permission bits and the
/// set-user/set-group/sticky bits are separate because a format can hold one without the
/// other and the security consequences differ; a time's *precision* is separate from the
/// time itself because rounding a modification time to two seconds is not the same as not
/// recording it at all.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Property {
    /// The owning user and group.
    Ownership,
    /// The permission bits.
    Permissions,
    /// The set-user-id, set-group-id, and sticky bits.
    SpecialBits,
    /// What the entry is: that it is a symbolic link, a second name for another entry, a
    /// device node, a named pipe, or a socket rather than a file or a directory.
    Kind,
    /// Extended attributes, and the POSIX ACLs stored as them.
    ExtendedAttributes,
    /// The access time.
    AccessTime,
    /// The change (status) time.
    ChangeTime,
    /// The modification time.
    ModificationTime,
    /// How finely a recorded time is stored — a time kept, but rounded.
    TimePrecision,
    /// The entry's name, exactly as it was given.
    Name,
}

impl Property {
    /// The lowercase name of this property, for a rendered report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Property::Ownership => "ownership",
            Property::Permissions => "permissions",
            Property::SpecialBits => "special bits",
            Property::Kind => "kind",
            Property::ExtendedAttributes => "extended attributes",
            Property::AccessTime => "access time",
            Property::ChangeTime => "change time",
            Property::ModificationTime => "modification time",
            Property::TimePrecision => "time precision",
            Property::Name => "name",
        }
    }

    /// Which bit of an [`AcceptedLoss`] set stands for this property.
    ///
    /// Private, and deliberately: the numbering is an implementation detail of the set and
    /// nothing outside it may depend on a particular bit meaning a particular property.
    const fn bit(self) -> u32 {
        match self {
            Property::Ownership => 1 << 0,
            Property::Permissions => 1 << 1,
            Property::SpecialBits => 1 << 2,
            Property::Kind => 1 << 3,
            Property::ExtendedAttributes => 1 << 4,
            Property::AccessTime => 1 << 5,
            Property::ChangeTime => 1 << 6,
            Property::ModificationTime => 1 << 7,
            Property::TimePrecision => 1 << 8,
            Property::Name => 1 << 9,
        }
    }
}

crate::naming::serialize_as_name!(Property);

/// Which properties a build may lose without being refused.
///
/// A format into a filesystem that cannot hold everything the source offered fails by
/// default, naming the entry and the property. This is how a caller says which of those
/// losses it has decided to accept — and it names them, rather than being one switch,
/// because a caller who accepted losing permission bits has not thereby decided that every
/// symbolic link in the tree may quietly disappear.
///
/// [`ALL`](Self::ALL) is every property, including any this crate names in a later version:
/// a caller who has said it accepts whatever the target cannot hold has said that about the
/// whole class, not about the members of it that existed when the call was written.
///
/// This is a set over bits and is deliberately not one of the crate's flag newtypes. Its
/// element is a typed [`Property`] rather than another instance of itself, so the operations
/// take a property — [`and`](Self::and), [`without`](Self::without), and
/// [`contains`](Self::contains) — and `BitOr` between two sets is not an operation a caller
/// asks for. The bit each property occupies is an implementation detail nothing outside may
/// depend on, which is the opposite of a flag word, whose whole point is that the bits are
/// the format's.
///
/// ```
/// # use ferrosys::{AcceptedLoss, Property};
/// // Modes and ownership, and nothing else: a symbolic link still refuses.
/// let precise = AcceptedLoss::NONE
///     .and(Property::Ownership)
///     .and(Property::Permissions);
/// assert!(precise.contains(Property::Permissions));
/// assert!(!precise.contains(Property::Kind));
///
/// // Or the whole class, for a caller that has decided it does not care.
/// assert!(AcceptedLoss::ALL.contains(Property::Kind));
/// assert!(!AcceptedLoss::NONE.contains(Property::Kind));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct AcceptedLoss(u32);

impl AcceptedLoss {
    /// Nothing may be lost: any property the target cannot hold refuses the build. The
    /// default.
    pub const NONE: Self = Self(0);

    /// Every property may be lost, including any named in a later version of this crate.
    pub const ALL: Self = Self(u32::MAX);

    /// This set with `property` added.
    #[must_use]
    pub const fn and(self, property: Property) -> Self {
        Self(self.0 | property.bit())
    }

    /// This set without `property`.
    ///
    /// The useful case is subtracting from [`ALL`](Self::ALL) — accepting whatever the
    /// target cannot hold *except* one thing that must not vanish quietly.
    #[must_use]
    pub const fn without(self, property: Property) -> Self {
        Self(self.0 & !property.bit())
    }

    /// Whether losing `property` is accepted.
    #[must_use]
    pub const fn contains(self, property: Property) -> bool {
        self.0 & property.bit() != 0
    }

    /// Whether nothing at all may be lost.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Which way a fidelity record runs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Direction {
    /// The source offered the property and the target filesystem has nowhere to put it, so
    /// what was written does not carry it.
    Dropped,
    /// The source filesystem has no such field, so the value handed back was invented from
    /// a [`Synthesis`] input rather than read.
    Synthesized,
}

impl Direction {
    /// The lowercase name of this direction, for a rendered report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::Dropped => "dropped",
            Direction::Synthesized => "synthesized",
        }
    }
}

crate::naming::serialize_as_name!(Direction);

/// One property that did not survive, and the entry it belonged to.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FidelityRecord {
    /// Whether the property was dropped on the way in or invented on the way out.
    pub direction: Direction,
    /// The entry's path, in the spelling the source or the image used.
    pub path: Vec<u8>,
    /// The property.
    pub property: Property,
}

/// Everything a build could not carry and everything a read had to invent.
///
/// An empty report is the whole claim a caller wants: what was written is what was offered,
/// or what was handed back is what was stored. [`is_faithful`](Self::is_faithful) is that
/// question.
///
/// A report holds at most [`MAX_RECORDS`](Self::MAX_RECORDS) records and says through
/// [`is_truncated`](Self::is_truncated) when it stopped there. The cap exists for the same
/// reason a scan's does: how many records a tree produces is the tree's own claim, and a
/// report's memory should be a property of this crate rather than of what it was pointed
/// at. A truncated report is a floor — the counts in [`count`](Self::count) still say how
/// many of each there were, because they are counted rather than stored.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FidelityReport {
    records: Vec<FidelityRecord>,
    /// Every (direction, property) pair seen and how many entries it applied to, counted
    /// whether or not the record itself was kept. This is what makes a truncated report
    /// still answer "how much was lost".
    counts: Vec<((Direction, Property), u64)>,
    truncated: bool,
}

impl Default for FidelityReport {
    /// A report of nothing lost and nothing invented — a faithful build.
    fn default() -> Self {
        Self::new()
    }
}

impl FidelityReport {
    /// The most records one report holds before it stops storing them and counts only.
    ///
    /// Far past the number anyone reads entry by entry, and far below the number a large
    /// tree could produce: a root filesystem written to a format that holds no ownership
    /// loses it on every one of its entries, which is hundreds of thousands of records
    /// saying one thing.
    pub const MAX_RECORDS: usize = 10_000;

    /// An empty report.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            counts: Vec::new(),
            truncated: false,
        }
    }

    /// Record that `property` of the entry at `path` ran in `direction`.
    ///
    /// A family calls this as it writes or reads; nothing else needs to.
    pub fn record(&mut self, direction: Direction, path: &[u8], property: Property) {
        let key = (direction, property);
        match self.counts.iter_mut().find(|(k, _)| *k == key) {
            Some((_, n)) => *n += 1,
            None => self.counts.push((key, 1)),
        }
        if self.records.len() < Self::MAX_RECORDS {
            self.records.push(FidelityRecord {
                direction,
                path: path.to_vec(),
                property,
            });
        } else {
            self.truncated = true;
        }
    }

    /// Whether nothing was lost and nothing was invented.
    #[must_use]
    pub fn is_faithful(&self) -> bool {
        self.counts.is_empty()
    }

    /// The records held, in the order they were made.
    ///
    /// A [`truncated`](Self::is_truncated) report holds the first
    /// [`MAX_RECORDS`](Self::MAX_RECORDS) of them; [`count`](Self::count) is the complete
    /// accounting either way.
    #[must_use]
    pub fn records(&self) -> &[FidelityRecord] {
        &self.records
    }

    /// Whether more records were made than the report stores.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// How many entries had `property` run in `direction`, counted over the whole run
    /// whether or not each record was stored.
    #[must_use]
    pub fn count(&self, direction: Direction, property: Property) -> u64 {
        self.counts
            .iter()
            .find(|(k, _)| *k == (direction, property))
            .map_or(0, |(_, n)| *n)
    }

    /// Every (direction, property) pair the run produced and how many entries each applied
    /// to, in the order they were first seen.
    #[must_use]
    pub fn summary(&self) -> Vec<(Direction, Property, u64)> {
        self.counts.iter().map(|((d, p), n)| (*d, *p, *n)).collect()
    }

    /// Render the summary as a fixed-column human table: one line per (direction,
    /// property) pair with the number of entries it applied to. A faithful report renders a
    /// single line saying so.
    ///
    /// The summary rather than the records, because the records are one line per entry and
    /// a tree that loses a property loses it on nearly every entry. A caller that wants the
    /// entries has [`records`](Self::records).
    #[must_use]
    pub fn to_table(&self) -> String {
        if self.counts.is_empty() {
            return "nothing dropped or synthesized\n".to_string();
        }
        let rows: Vec<(&str, &str, String)> = self
            .summary()
            .into_iter()
            .map(|(d, p, n)| (d.as_str(), p.as_str(), n.to_string()))
            .collect();
        let mut dir_w = "DIRECTION".len();
        let mut prop_w = "PROPERTY".len();
        for (d, p, _) in &rows {
            dir_w = dir_w.max(d.len());
            prop_w = prop_w.max(p.len());
        }
        let mut out = format!(
            "{:<dir_w$}  {:<prop_w$}  {}\n",
            "DIRECTION", "PROPERTY", "ENTRIES"
        );
        for (d, p, n) in &rows {
            out.push_str(&format!("{d:<dir_w$}  {p:<prop_w$}  {n}\n"));
        }
        out
    }
}

/// What a read records for a property the source filesystem has no field for.
///
/// A FAT or exFAT directory entry has no owner, no group, and no permission bits, so
/// extracting one into host files means inventing all three. Every filesystem driver that
/// mounts such a format has `uid=`, `gid=`, `fmask=`, and `dmask=` options for exactly
/// this, and for exactly this reason: the values are a policy the caller owns, not a
/// constant the tool hides.
///
/// The defaults are the conservative ones — owned by root, `0644` for a file and `0755` for
/// a directory — and never the permissive ones. Every value actually applied is recorded in
/// the [`FidelityReport`], so an extraction says what it invented rather than leaving it to
/// be discovered.
///
/// A family that *does* record a property ignores the corresponding input: extracting an
/// ext4 image uses the ownership and modes the image holds, whatever is set here.
///
/// ```
/// # use ferrosys::Synthesis;
/// // A tree extracted for one user to own, with group and other read-only.
/// let synthesis = Synthesis::new().owner(1000, 1000).modes(0o644, 0o755);
/// # let _ = synthesis;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Synthesis {
    /// The owning user id to record where the source filesystem has none. Defaults to 0.
    pub uid: u32,
    /// The owning group id to record where the source filesystem has none. Defaults to 0.
    pub gid: u32,
    /// The permission bits to give a regular file, a symbolic link, or a special node
    /// where the source filesystem has none. Defaults to `0o644`.
    pub file_mode: u16,
    /// The permission bits to give a directory where the source filesystem has none.
    /// Defaults to `0o755`, since a directory that is not searchable cannot be entered.
    pub dir_mode: u16,
}

impl Synthesis {
    /// The conservative defaults: owned by root, `0644` for a file and `0755` for a
    /// directory.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            uid: 0,
            gid: 0,
            file_mode: 0o644,
            dir_mode: 0o755,
        }
    }

    /// Record `uid` and `gid` as the owner where the source filesystem has none.
    #[must_use]
    pub const fn owner(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// Record `file_mode` on a file and `dir_mode` on a directory where the source
    /// filesystem has no permission bits.
    #[must_use]
    pub const fn modes(mut self, file_mode: u16, dir_mode: u16) -> Self {
        self.file_mode = file_mode;
        self.dir_mode = dir_mode;
        self
    }
}

impl Default for Synthesis {
    /// The defaults in [`Synthesis::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Permission bits that make an entry writable. A mode with none of them set is what a
/// read-only attribute means, and is the one bit of a mode the formats below carry.
///
/// Crate-visible because both directions ask it: this module decides what a mode *loses* on
/// its way into such a format, and `tree.rs` decides what a read of one hands back. Two
/// constants would agree today and would be one edit apart from disagreeing.
#[cfg(any(feature = "fat", feature = "exfat"))]
pub(crate) const WRITE_BITS: u16 = 0o222;

/// The set-user-id, set-group-id, and sticky bits.
#[cfg(any(feature = "fat", feature = "exfat"))]
const SPECIAL_BITS: u16 = 0o7000;

/// The permission bits proper.
#[cfg(any(feature = "fat", feature = "exfat"))]
const PERMISSION_BITS: u16 = 0o777;

/// What a caller accepts losing, and what a read of the image would invent.
///
/// The two travel together everywhere, because neither answers anything on its own: whether a
/// property was *lost* is a comparison against what a read hands back, and whether a loss may
/// be taken is a comparison against what was accepted.
#[cfg(any(feature = "fat", feature = "exfat"))]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LossPolicy {
    /// Which losses the caller has accepted.
    pub accepted: AcceptedLoss,
    /// What a read of this image would fill a missing owner and mode with.
    pub synthesis: Synthesis,
}

#[cfg(any(feature = "fat", feature = "exfat"))]
impl LossPolicy {
    /// Record every property of `meta` and `xattrs` that a format storing no POSIX metadata
    /// beyond a read-only bit cannot carry, and report the first one the caller has not
    /// accepted losing.
    ///
    /// One accounting rather than one per family, because it is one question. FAT and exFAT
    /// share no bytes and no structures, and they lose exactly the same six things for exactly
    /// the same reason: each stores a name, one permission bit, and times, and has nowhere to
    /// put anything else. A second copy of this would agree today and drift the moment either
    /// gained a clause, and the drift would be silent — a tree one family refuses and the other
    /// writes, or worse, a property one of them stops naming.
    ///
    /// A property counts as lost when the value a read gets back is not the value stated, which
    /// is narrower than "the format has no field for it": measured against
    /// [`synthesis`](Self::synthesis), a root-owned `0644`/`0755` tree loses nothing.
    ///
    /// # Errors
    ///
    /// The first [`Property`] the format cannot carry that
    /// [`accepted`](Self::accepted) does not name. The caller wraps it in its own refusal, so
    /// the path and the family's own wording stay where a message is built.
    pub(crate) fn record_losses(
        &self,
        report: &mut FidelityReport,
        meta: &crate::source::Metadata,
        xattrs: &[crate::xattr::Xattr],
        is_dir: bool,
        path: &[u8],
    ) -> Result<(), Property> {
        let mut lose = |property: Property| -> Result<(), Property> {
            if !self.accepted.contains(property) {
                return Err(property);
            }
            report.record(Direction::Dropped, path, property);
            Ok(())
        };

        if meta.uid != self.synthesis.uid || meta.gid != self.synthesis.gid {
            lose(Property::Ownership)?;
        }
        if meta.mode & SPECIAL_BITS != 0 {
            lose(Property::SpecialBits)?;
        }
        // The default a read fills in, less the write bits where the entry is read-only —
        // which is exactly what a driver meeting the attribute hands back.
        let mut recovered = if is_dir {
            self.synthesis.dir_mode
        } else {
            self.synthesis.file_mode
        };
        if meta.mode & WRITE_BITS == 0 {
            recovered &= !WRITE_BITS;
        }
        if meta.mode & PERMISSION_BITS != recovered & PERMISSION_BITS {
            lose(Property::Permissions)?;
        }
        // These formats have one time per entry to spare and the modification time has it, so a
        // change time equal to it survives and one that is not is gone.
        if meta.ctime != meta.mtime {
            lose(Property::ChangeTime)?;
        }
        if !xattrs.is_empty() {
            lose(Property::ExtendedAttributes)?;
        }
        Ok(())
    }

    /// Whether the caller has accepted losing `property`.
    ///
    /// The families reach this for the one loss that is not a property of an entry's metadata:
    /// a kind the format has no representation for, which is decided before an entry exists.
    pub(crate) const fn accepts(&self, property: Property) -> bool {
        self.accepted.contains(property)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_report_is_faithful() {
        let report = FidelityReport::new();
        assert!(report.is_faithful());
        assert!(!report.is_truncated());
        assert!(report.records().is_empty());
        assert_eq!(report.to_table(), "nothing dropped or synthesized\n");
        assert_eq!(FidelityReport::default(), report);
    }

    #[test]
    fn a_record_names_the_entry_and_counts_the_property() {
        let mut report = FidelityReport::new();
        report.record(Direction::Dropped, b"/bin/ping", Property::SpecialBits);
        report.record(Direction::Dropped, b"/bin/ping", Property::Ownership);
        report.record(Direction::Dropped, b"/etc/passwd", Property::Ownership);
        report.record(Direction::Synthesized, b"/", Property::Permissions);

        assert!(!report.is_faithful());
        assert_eq!(report.records().len(), 4);
        assert_eq!(report.records()[0].path, b"/bin/ping");
        assert_eq!(report.records()[0].property, Property::SpecialBits);

        // The counts are per (direction, property) pair, so two entries losing ownership
        // read as two rather than as two separate facts.
        assert_eq!(report.count(Direction::Dropped, Property::Ownership), 2);
        assert_eq!(report.count(Direction::Dropped, Property::SpecialBits), 1);
        assert_eq!(
            report.count(Direction::Synthesized, Property::Permissions),
            1
        );
        // A pair that never happened is zero, not absent.
        assert_eq!(report.count(Direction::Dropped, Property::Kind), 0);

        // The summary is in first-seen order, so a table reads the way the run went.
        assert_eq!(
            report.summary(),
            vec![
                (Direction::Dropped, Property::SpecialBits, 1),
                (Direction::Dropped, Property::Ownership, 2),
                (Direction::Synthesized, Property::Permissions, 1),
            ]
        );
    }

    #[test]
    fn the_counts_survive_truncation() {
        // A truncated report stops storing records and keeps counting, which is what makes
        // it a floor on the entries and an exact answer on the total. A tree that loses a
        // property loses it on nearly every entry, so the total is the number that matters.
        let mut report = FidelityReport::new();
        for i in 0..FidelityReport::MAX_RECORDS + 5 {
            report.record(
                Direction::Dropped,
                format!("/f{i}").as_bytes(),
                Property::Ownership,
            );
        }
        assert!(report.is_truncated());
        assert_eq!(report.records().len(), FidelityReport::MAX_RECORDS);
        assert_eq!(
            report.count(Direction::Dropped, Property::Ownership),
            FidelityReport::MAX_RECORDS as u64 + 5
        );
    }

    #[test]
    fn an_accepted_loss_set_names_properties_rather_than_switching_everything() {
        // The whole reason the acknowledgement is a set: accepting mode loss must not also
        // accept every symbolic link in the tree disappearing.
        let precise = AcceptedLoss::NONE
            .and(Property::Ownership)
            .and(Property::Permissions);
        assert!(precise.contains(Property::Ownership));
        assert!(precise.contains(Property::Permissions));
        assert!(!precise.contains(Property::Kind));
        assert!(!precise.is_empty());

        assert!(AcceptedLoss::NONE.is_empty());
        assert!(!AcceptedLoss::NONE.contains(Property::Ownership));
        assert_eq!(AcceptedLoss::default(), AcceptedLoss::NONE);

        // Subtracting from the whole class is the other useful direction.
        let all_but_kind = AcceptedLoss::ALL.without(Property::Kind);
        assert!(all_but_kind.contains(Property::Ownership));
        assert!(!all_but_kind.contains(Property::Kind));
        // And adding a property twice is the same set, so a builder is not order-sensitive.
        assert_eq!(precise.and(Property::Ownership), precise);
    }

    #[test]
    fn every_property_has_a_bit_of_its_own_and_all_holds_every_one() {
        // Two properties sharing a bit would make accepting one accept the other, which is
        // the exact failure the set exists to prevent — and it is not a compile error.
        const EVERY: [Property; 10] = [
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
        ];
        for (i, one) in EVERY.iter().enumerate() {
            let only = AcceptedLoss::NONE.and(*one);
            for (j, other) in EVERY.iter().enumerate() {
                assert_eq!(
                    only.contains(*other),
                    i == j,
                    "{} and {} share a bit",
                    one.as_str(),
                    other.as_str()
                );
            }
            // `ALL` is all bits rather than an enumeration, so a property named in a later
            // version is covered by an existing caller's `ALL` rather than escaping it.
            assert!(AcceptedLoss::ALL.contains(*one));
        }
    }

    #[test]
    fn the_synthesis_defaults_are_the_conservative_ones() {
        // A tree extracted with nothing named must not be world-writable, and a directory
        // that is not searchable cannot be entered.
        let s = Synthesis::new();
        assert_eq!((s.uid, s.gid), (0, 0));
        assert_eq!(s.file_mode, 0o644);
        assert_eq!(s.dir_mode, 0o755);
        assert_eq!(Synthesis::default(), s);

        let named = Synthesis::new().owner(1000, 100).modes(0o600, 0o700);
        assert_eq!((named.uid, named.gid), (1000, 100));
        assert_eq!((named.file_mode, named.dir_mode), (0o600, 0o700));
    }
}
