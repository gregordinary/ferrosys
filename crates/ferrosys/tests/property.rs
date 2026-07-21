//! The writer property gate: an arbitrary source tree, built at an arbitrary
//! geometry, either is refused with a typed error or produces an image that reads
//! back exactly and checks clean under `e2fsck`.
//!
//! Two things are generated together, because a defect usually needs both to show:
//! the tree (what the source asks for) and the geometry (the block size, group
//! count, grow reservation, and feature profile it is written into).
//!
//! **The generator stays inside the feature envelope.** It builds a tree
//! constructively — a name is unique within its parent, a hard link names an entry
//! that exists, a directory exists before its contents — so every generated input is
//! one the crate can represent. That is what makes the property sharp: a
//! [`ModelError`] means the *generator* drifted out of the envelope, so it fails the
//! test rather than being swallowed as an expected rejection. The only rejections
//! accepted are the capacity ones a caller genuinely provokes: too few inodes, too
//! little space, a filesystem too small for a journal or for its own metadata.
//!
//! **Sizes are drawn from the geometry edges, not sampled uniformly.** Off-by-one
//! layout bugs live at the boundaries — the degenerate single-group filesystem, a
//! partial final group, the `flex_bg` boundary, the `sparse_super` backup groups, and
//! the group count where one more descriptor-table block is needed — so those counts
//! are what the generator mostly draws.
//!
//! [`ModelError`]: ferrosys::ext::ModelError

mod util;

use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU64;
use std::path::Path;

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use ferrosys::ext::acl::{Acl, AclEntry, AclQualifier, EXEC, READ, WRITE};
use ferrosys::ext::ondisk::{Inode, Timestamp};
use ferrosys::ext::{
    AllocError, Compat, FeatureSet, FormatError, FormatOptions, GeometryError, GrowReservation,
    HashSignedness, HashVersion, Incompat, InodeCount, ReadError, Reader, ReservedRatio, RoCompat,
    TreeBuilder, format_to,
};

const MIB: u64 = 1024 * 1024;

/// The fixed instant everything not exercising the timestamp dimension is stamped
/// with, and the filesystem's own creation time.
const BASE_TIME: i64 = 1_700_000_000;

/// The largest image a case may generate. Every edge the generator aims at fits well
/// inside this at some block size, and the cap is what keeps a run of cases routine
/// rather than an overnight job.
const MAX_IMAGE_BYTES: u64 = 2048 * MIB;

/// Groups per descriptor-table block, with the 64-byte descriptors `64bit` selects.
/// The group count where one more descriptor block is needed is a multiple of this.
fn groups_per_gdt_block(block_size: u32) -> u32 {
    block_size / 64
}

/// Blocks per group: eight bits of block bitmap per byte of a one-block bitmap.
fn blocks_per_group(block_size: u32) -> u32 {
    8 * block_size
}

/// The group counts an off-by-one is most likely to hide at, for a given block size:
/// the degenerate single group, the `sparse_super` backup groups (1 and the powers of
/// 3, 5, and 7), the `flex_bg` boundary at 16, and the counts either side of needing
/// one more descriptor-table block.
///
/// Counts whose image would exceed [`MAX_IMAGE_BYTES`] are dropped, so which edges a
/// block size actually reaches depends on how large its groups are. A 4 KiB block
/// puts 128 MiB in a group, so its descriptor-block edge sits at 8 GiB and is out of
/// reach here; at 1 KiB and 2 KiB the same edge is a few hundred MiB and is drawn
/// every run. The pure geometry tests pin the reserved-GDT arithmetic at every size
/// without building an image.
fn edge_group_counts(block_size: u32) -> Vec<u32> {
    let gpb = groups_per_gdt_block(block_size);
    let mut counts = vec![1, 2, 3, 5, 7, 9, 15, 16, 17, 25, 27, 49, 81];
    for k in 1..=2 {
        counts.push(k * gpb);
        counts.push(k * gpb + 1);
    }
    counts.sort_unstable();
    counts.dedup();
    counts.retain(|&g| image_bytes(block_size, g, 0) <= MAX_IMAGE_BYTES);
    counts
}

/// The image size a geometry selection realizes.
fn image_bytes(block_size: u32, groups: u32, tail_blocks: u32) -> u64 {
    let blocks =
        u64::from(groups) * u64::from(blocks_per_group(block_size)) + u64::from(tail_blocks);
    blocks * u64::from(block_size)
}

/// How much online-grow headroom to reserve.
#[derive(Clone, Copy, Debug)]
enum GrowSel {
    /// Reserve nothing past the initial size.
    None,
    /// Reserve for a target this many times the initial size.
    UpTo(u64),
    /// Reserve as much as the format allows.
    Max,
}

/// A feature profile inside the envelope. The extent family is the default with at most
/// one capability removed, together with whatever that capability's dependants require;
/// the block-mapped family is the ext2/ext3 baselines, which exercise the classic
/// direct/indirect map, per-group (non-flex) metadata placement, and — for ext3 — the
/// classic-mapped journal.
#[derive(Clone, Copy, Debug)]
enum Profile {
    /// The full default profile.
    Default,
    /// No journal — and so no orphan file, whose entries are journalled.
    NoJournal,
    /// No metadata checksums — and so no checksum seed, which exists to serve them.
    NoChecksums,
    /// Linear directories only: no hash index.
    NoDirIndex,
    /// The ext2 baseline: the block-mapped family, no journal and no extents.
    Ext2,
    /// The ext3 baseline: ext2 plus the classic-mapped journal.
    Ext3,
}

impl Profile {
    fn feature(self, block_size: u32) -> FeatureSet {
        let mut f = match self {
            Profile::Ext2 => FeatureSet::EXT2,
            Profile::Ext3 => FeatureSet::EXT3,
            _ => FeatureSet::DEFAULT,
        };
        f.block_size = block_size;
        match self {
            Profile::Default | Profile::Ext2 | Profile::Ext3 => {}
            Profile::NoJournal => {
                f.compat = Compat::from_bits(
                    f.compat.bits() & !(Compat::HAS_JOURNAL.bits() | Compat::ORPHAN_FILE.bits()),
                );
            }
            Profile::NoChecksums => {
                f.ro_compat =
                    RoCompat::from_bits(f.ro_compat.bits() & !RoCompat::METADATA_CSUM.bits());
                f.incompat = Incompat::from_bits(f.incompat.bits() & !Incompat::CSUM_SEED.bits());
            }
            Profile::NoDirIndex => {
                f.compat = Compat::from_bits(f.compat.bits() & !Compat::DIR_INDEX.bits());
            }
        }
        f
    }
}

/// How many inodes the format is asked for.
#[derive(Clone, Copy, Debug)]
enum InodeSel {
    /// The size-driven default.
    Auto,
    /// One inode per this many bytes (`-i`).
    BytesPerInode(u64),
    /// A target count (`-N`), spread across the groups.
    Count(u32),
}

/// The formatter inputs beyond the geometry: the tunables a caller can set and the
/// hash profile an indexed directory is ordered by. Generating them alongside the
/// geometry means every tunable meets every geometry edge eventually, rather than
/// only the four fixed values the unit tests pin.
#[derive(Clone, Copy, Debug)]
struct Tunables {
    /// The volume label, already NUL-padded to the on-disk width; all zero means
    /// unlabelled.
    label: [u8; 16],
    inodes: InodeSel,
    /// Reserved-block ratio in hundredths of one percent, `0..=5000`.
    reserved_hundredths: u16,
    hash_version: HashVersion,
    hash_signedness: HashSignedness,
    /// The directory-hash seed; zero is the unseeded default, anything else salts
    /// every indexed directory's ordering.
    hash_seed: [u8; 16],
}

/// The geometry a tree is written into, and the options it is written with.
#[derive(Clone, Copy, Debug)]
struct Geo {
    block_size: u32,
    groups: u32,
    /// Blocks past the last whole group, making a partial final group when non-zero.
    tail_blocks: u32,
    grow: GrowSel,
    profile: Profile,
    tun: Tunables,
}

impl Geo {
    fn size_bytes(&self) -> u64 {
        image_bytes(self.block_size, self.groups, self.tail_blocks)
    }

    fn options(&self) -> FormatOptions {
        let mut o = FormatOptions::new(
            [
                0xf0, 0xe1, 0x70, 0x55, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
            ],
            Timestamp::from_secs(BASE_TIME),
            self.tun.hash_seed,
        );
        o.feature = self.profile.feature(self.block_size);
        o.grow = match self.grow {
            GrowSel::None => GrowReservation::None,
            GrowSel::Max => GrowReservation::Max,
            GrowSel::UpTo(multiple) => {
                GrowReservation::UpTo(self.size_bytes().saturating_mul(multiple))
            }
        };
        o.volume_name = self.tun.label;
        o.inodes = match self.tun.inodes {
            InodeSel::Auto => InodeCount::Auto,
            InodeSel::BytesPerInode(b) => {
                InodeCount::BytesPerInode(NonZeroU64::new(b).expect("a nonzero ratio"))
            }
            InodeSel::Count(n) => InodeCount::Count(n),
        };
        o.reserved = ReservedRatio::from_hundredths_of_percent(self.tun.reserved_hundredths)
            .expect("the strategy stays at or below the 50% ceiling");
        o.hash_version = self.tun.hash_version;
        o.hash_signedness = self.tun.hash_signedness;
        o
    }
}

/// How large a generated file is. Content sizes are expressed against the block size
/// rather than as flat byte counts, so the boundary cases — empty, one byte short of a
/// block, exactly a block, one byte over — land wherever the block size lands.
#[derive(Clone, Copy, Debug)]
enum SizeSel {
    /// `blocks * block_size + delta`, with `delta` in `-1..=1`.
    Blocks(u16, i8),
    /// A flat byte count, for the sizes between the boundaries.
    Bytes(u32),
}

impl SizeSel {
    fn resolve(self, block_size: u32) -> u64 {
        match self {
            SizeSel::Blocks(blocks, delta) => (u64::from(blocks) * u64::from(block_size))
                .saturating_add_signed(i64::from(delta))
                .min(u64::from(u32::MAX)),
            SizeSel::Bytes(n) => u64::from(n),
        }
    }
}

/// When an entry is stamped. The interesting instants are the encoding boundaries:
/// zero, the signed-32-bit window's ends (where the epoch bits engage), a pre-1970
/// second, the extremes of the on-disk range, and a nanosecond fraction — each a
/// different shape for the split `(field, extra)` encoding.
#[derive(Clone, Copy, Debug)]
struct TimeSel {
    secs: i64,
    nanos: u32,
}

impl TimeSel {
    fn resolve(self) -> Timestamp {
        Timestamp {
            secs: self.secs,
            nanos: self.nanos,
        }
    }
}

/// An extended attribute to attach. The value length is what matters: a short value
/// lives in the spare room of the 256-byte inode, and a long one spills into an
/// external attribute block, which is a different encoding and a different checksum.
/// A set holding both is stored split across the two regions.
#[derive(Clone, Copy, Debug)]
struct XattrSel {
    name: u8,
    value_len: u16,
}

impl XattrSel {
    /// The value length, held to what the block size can actually store.
    ///
    /// An attribute's value must fit in a single block, so the envelope shrinks with
    /// the block size: a value a 4 KiB block holds easily has nowhere to go in a 1 KiB
    /// one. The margin covers the attribute block's header and this attribute's own
    /// entry. Asking past this is a typed refusal by the crate, not a defect, so the
    /// generator stays inside it and the property keeps its right to treat every
    /// non-capacity error as a failure.
    fn len(self, block_size: u32) -> usize {
        usize::from(self.value_len).min(block_size as usize - 128)
    }
}

/// What a generated entry is. Selectors (a parent, a hard-link target) are resolved
/// against what the tree has actually created by that point, so a raw item is always
/// realizable.
#[derive(Clone, Debug)]
enum RawKind {
    Dir,
    File(SizeSel),
    /// Target length. 60 bytes is where a symlink stops fitting in the inode and moves
    /// into a block, so the generator leans on that boundary.
    Symlink(u16),
    /// Selector among the non-directory entries created so far.
    HardLink(u16),
    CharDev(u32, u32),
    BlockDev(u32, u32),
    Fifo,
    Socket,
}

/// One generated entry, before its selectors are resolved against the tree.
#[derive(Clone, Debug)]
struct RawItem {
    /// Selector among the directories created so far.
    parent: u16,
    /// Total name length. 255 bytes is the longest a directory entry can name.
    name_len: u8,
    kind: RawKind,
    mode: u16,
    uid: u32,
    gid: u32,
    /// Access, change, and modification times, drawn independently so the three
    /// fields cannot pass by all holding one value.
    atime: TimeSel,
    ctime: TimeSel,
    mtime: TimeSel,
    /// Extended attributes; duplicates by name are dropped at realization (the model
    /// rejects a duplicate), and the set is trimmed to what the block size can store.
    xattrs: Vec<XattrSel>,
    /// Whether to attach a POSIX access ACL (and, on a directory, a default ACL).
    acl: bool,
}

/// A whole generated case.
#[derive(Clone, Debug)]
struct Spec {
    geo: Geo,
    items: Vec<RawItem>,
    /// A directory holding this many same-shaped files, with names this long. It is
    /// what reliably pushes a directory past one block and into a hash index: a
    /// handful of 255-byte names fills a block, and a few hundred fills enough blocks
    /// to need an interior node.
    wide: (u16, u8),
}

// --- strategies ---

fn size_sel() -> impl Strategy<Value = SizeSel> {
    prop_oneof![
        // The block boundaries, where the extent and tail handling can be off by one.
        6 => (0u16..=5, -1i8..=1).prop_map(|(b, d)| SizeSel::Blocks(b, d)),
        // A larger file, spanning enough blocks to need more than one extent leaf.
        1 => (12u16..=140, -1i8..=1).prop_map(|(b, d)| SizeSel::Blocks(b, d)),
        3 => (0u32..=70_000).prop_map(SizeSel::Bytes),
    ]
}

fn raw_kind() -> impl Strategy<Value = RawKind> {
    prop_oneof![
        4 => Just(RawKind::Dir),
        8 => size_sel().prop_map(RawKind::File),
        3 => prop_oneof![
            // Either side of the 60-byte fast/slow symlink boundary.
            3 => 57u16..=63,
            1 => 1u16..=255,
        ].prop_map(RawKind::Symlink),
        2 => any::<u16>().prop_map(RawKind::HardLink),
        1 => (0u32..=4095, 0u32..=255).prop_map(|(a, b)| RawKind::CharDev(a, b)),
        1 => (0u32..=4095, 0u32..=255).prop_map(|(a, b)| RawKind::BlockDev(a, b)),
        1 => Just(RawKind::Fifo),
        1 => Just(RawKind::Socket),
    ]
}

fn xattr_sel() -> impl Strategy<Value = XattrSel> {
    (
        any::<u8>(),
        prop_oneof![
            // Small enough to live in the inode.
            2 => 0u16..=40,
            // Around where the inode's spare room runs out.
            2 => 80u16..=200,
            // Large enough to force an external attribute block.
            2 => 300u16..=1200,
        ],
    )
        .prop_map(|(name, value_len)| XattrSel { name, value_len })
}

fn time_sel() -> impl Strategy<Value = TimeSel> {
    let secs = prop_oneof![
        // The common case, and what everything else in the image is stamped with.
        6 => Just(BASE_TIME),
        1 => Just(0i64),
        // Pre-1970: the signed field goes negative with the epoch bits still zero.
        // The range floor is the on-disk minimum, which is inside 1901.
        2 => Timestamp::EPOCH_MIN..0,
        1 => Just(Timestamp::EPOCH_MIN),
        // Either side of 2038: the last second the bare field holds, then the
        // seconds that need a nonzero epoch.
        1 => Just(i64::from(i32::MAX)),
        2 => i64::from(i32::MAX) + 1..i64::from(i32::MAX) + (1i64 << 33),
        1 => Just(Timestamp::EPOCH_MAX),
    ];
    let nanos = prop_oneof![
        3 => Just(0u32),
        2 => 1u32..Timestamp::NANOS_PER_SEC,
        1 => Just(Timestamp::NANOS_PER_SEC - 1),
    ];
    (secs, nanos).prop_map(|(secs, nanos)| TimeSel { secs, nanos })
}

fn raw_item() -> impl Strategy<Value = RawItem> {
    (
        (
            any::<u16>(),
            prop_oneof![
                4 => 1u8..=40,
                // The longest name a directory entry can hold.
                1 => Just(255u8),
                1 => 41u8..=255,
            ],
            raw_kind(),
            0u16..=0o7777,
            prop_oneof![3 => Just(0u32), 1 => any::<u32>()],
            prop_oneof![3 => Just(0u32), 1 => any::<u32>()],
        ),
        time_sel(),
        time_sel(),
        time_sel(),
        proptest::collection::vec(xattr_sel(), 0..=3),
        prop_oneof![4 => Just(false), 1 => Just(true)],
    )
        .prop_map(
            |((parent, name_len, kind, mode, uid, gid), atime, ctime, mtime, xattrs, acl)| {
                RawItem {
                    parent,
                    name_len,
                    kind,
                    mode,
                    uid,
                    gid,
                    atime,
                    ctime,
                    mtime,
                    xattrs,
                    acl,
                }
            },
        )
}

fn tunables() -> impl Strategy<Value = Tunables> {
    let label = prop_oneof![
        // Unlabelled, the default.
        3 => Just([0u8; 16]),
        // A short label and a full-width one with no NUL at all.
        1 => Just(*b"rootfs\0\0\0\0\0\0\0\0\0\0"),
        1 => Just(*b"sixteen-byte-lbl"),
    ];
    let inodes = prop_oneof![
        4 => Just(InodeSel::Auto),
        // The densities mke2fs's own buckets use, plus a sparse one.
        2 => proptest::sample::select(vec![4096u64, 16384, 65536]).prop_map(InodeSel::BytesPerInode),
        // A target count; too dense for a small filesystem is a typed refusal the
        // capacity filter accepts, so the low end stays in.
        2 => (64u32..=4096).prop_map(InodeSel::Count),
    ];
    let reserved = prop_oneof![
        3 => Just(500u16),
        1 => Just(0u16),
        1 => Just(5000u16),
        // A fractional percentage, which only exact hundredths arithmetic honors.
        1 => 1u16..5000,
    ];
    let hash_version = prop_oneof![
        4 => Just(HashVersion::HalfMd4),
        1 => Just(HashVersion::Tea),
        1 => Just(HashVersion::Legacy),
    ];
    let hash_signedness = prop_oneof![
        3 => Just(HashSignedness::Unsigned),
        1 => Just(HashSignedness::Signed),
    ];
    let hash_seed = prop_oneof![
        3 => Just([0u8; 16]),
        1 => Just([0xa5u8; 16]),
        1 => any::<[u8; 16]>(),
    ];
    (
        label,
        inodes,
        reserved,
        hash_version,
        hash_signedness,
        hash_seed,
    )
        .prop_map(
            |(label, inodes, reserved_hundredths, hash_version, hash_signedness, hash_seed)| {
                Tunables {
                    label,
                    inodes,
                    reserved_hundredths,
                    hash_version,
                    hash_signedness,
                    hash_seed,
                }
            },
        )
}

fn geo() -> impl Strategy<Value = Geo> {
    prop_oneof![Just(1024u32), Just(2048u32), Just(4096u32)]
        .prop_flat_map(|block_size| {
            let edges = edge_group_counts(block_size);
            let bpg = blocks_per_group(block_size);
            let max_groups = edges.iter().copied().max().unwrap_or(1);
            let groups = prop_oneof![
                // Mostly the edges: this is the whole point of the tier.
                8 => proptest::sample::select(edges),
                2 => 1u32..=max_groups,
            ];
            let tail = prop_oneof![
                // An exact multiple of the group size, and so no partial final group.
                4 => Just(0u32),
                // A partial final group, at its extremes and in between. The final
                // group has to hold its own metadata and still be described exactly.
                2 => Just(1u32),
                2 => Just(bpg - 1),
                3 => 1u32..bpg,
            ];
            (Just(block_size), groups, tail)
        })
        .prop_flat_map(|(block_size, groups, tail_blocks)| {
            let grow = prop_oneof![
                2 => Just(GrowSel::None),
                3 => Just(GrowSel::Max),
                3 => (1u64..=4096).prop_map(GrowSel::UpTo),
            ];
            let profile = prop_oneof![
                4 => Just(Profile::Default),
                2 => Just(Profile::NoJournal),
                2 => Just(Profile::NoChecksums),
                2 => Just(Profile::NoDirIndex),
                2 => Just(Profile::Ext2),
                2 => Just(Profile::Ext3),
            ];
            (
                Just(block_size),
                Just(groups),
                Just(tail_blocks),
                grow,
                profile,
                tunables(),
            )
        })
        .prop_map(
            |(block_size, groups, tail_blocks, grow, profile, tun)| Geo {
                block_size,
                groups,
                tail_blocks,
                grow,
                profile,
                tun,
            },
        )
        // A tail can push an edge count over the cap; drop those rather than build a
        // case whose only distinction is being expensive.
        .prop_filter("image within the size cap", |g| {
            g.size_bytes() <= MAX_IMAGE_BYTES
        })
}

fn spec() -> impl Strategy<Value = Spec> {
    (
        geo(),
        proptest::collection::vec(raw_item(), 0..48),
        prop_oneof![
            3 => Just((0u16, 1u8)),
            // Enough entries, at enough name lengths, to outgrow one directory block.
            4 => (1u16..=400, 1u8..=255),
        ],
    )
        .prop_map(|(geo, items, wide)| Spec { geo, items, wide })
}

// --- realizing a spec ---

/// What the image is expected to hold at one path.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Expected {
    Dir,
    File {
        content: Vec<u8>,
        mode: u16,
        uid: u32,
        gid: u32,
    },
    Symlink(Vec<u8>),
    /// The path this name shares an inode with.
    HardLink(Vec<u8>),
    Device {
        major: u32,
        minor: u32,
        /// Whether the node is character-special rather than block-special.
        char_special: bool,
    },
    Fifo,
    Socket,
}

/// Everything one path must hold: its kind, and the fields every kind carries.
#[derive(Clone, Debug)]
struct ExpectedEntry {
    kind: Expected,
    /// `(atime, ctime, mtime)` to assert, or `None` where the inode's times are not
    /// this entry's to name — a hard link shares its target's inode, and the
    /// formatter stamps `/lost+found` itself.
    times: Option<(Timestamp, Timestamp, Timestamp)>,
    /// The complete attribute set, ACLs included: the image must hold exactly these,
    /// no more.
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ExpectedEntry {
    /// An entry with formatter-stamped times and no attributes.
    fn bare(kind: Expected) -> Self {
        Self {
            kind,
            times: None,
            xattrs: BTreeMap::new(),
        }
    }

    /// An entry stamped with [`BASE_TIME`] and no attributes.
    fn at_base_time(kind: Expected) -> Self {
        let t = Timestamp::from_secs(BASE_TIME);
        Self {
            kind,
            times: Some((t, t, t)),
            xattrs: BTreeMap::new(),
        }
    }
}

/// The access ACL an item carries when its `acl` flag is set: a named user (the
/// item's uid) with read access — the named entry is what makes the mask mandatory,
/// so this is the shape `setfacl -m u:N:r` leaves behind.
fn access_acl(uid: u32) -> Vec<u8> {
    Acl::new(vec![
        AclEntry {
            who: AclQualifier::UserObj,
            perm: READ | WRITE,
        },
        AclEntry {
            who: AclQualifier::User(uid),
            perm: READ,
        },
        AclEntry {
            who: AclQualifier::GroupObj,
            perm: READ,
        },
        AclEntry {
            who: AclQualifier::Mask,
            perm: READ | EXEC,
        },
        AclEntry {
            who: AclQualifier::Other,
            perm: 0,
        },
    ])
    .expect("a valid access ACL")
    .encode()
}

/// The default ACL a directory carries alongside its access ACL.
fn default_acl() -> Vec<u8> {
    Acl::new(vec![
        AclEntry {
            who: AclQualifier::UserObj,
            perm: READ | WRITE | EXEC,
        },
        AclEntry {
            who: AclQualifier::GroupObj,
            perm: READ | EXEC,
        },
        AclEntry {
            who: AclQualifier::Other,
            perm: READ,
        },
    ])
    .expect("a valid default ACL")
    .encode()
}

/// Resolve an item's whole attribute set: the ACLs first, then the user attributes —
/// deduplicated by name, since the model refuses a duplicate — trimmed so the set
/// always fits the block size it is written into.
///
/// The trim uses the on-disk cost, `align4(16 + name) + align4(value)`, against one
/// block's capacity less a margin (the name here is the full prefixed name, which
/// only overstates the stored cost). Staying inside that bound is what keeps the
/// property sharp: a generated set can never legitimately be `XattrsTooLarge`, so
/// that refusal remains a failure rather than a discard.
fn resolve_xattrs(item: &RawItem, is_dir: bool, block_size: u32) -> BTreeMap<Vec<u8>, Vec<u8>> {
    fn cost(name_len: usize, value_len: usize) -> usize {
        (16 + name_len).next_multiple_of(4) + value_len.next_multiple_of(4)
    }
    let mut budget = block_size as usize - 64;
    let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    if item.acl {
        let acl = access_acl(item.uid);
        budget = budget.saturating_sub(cost(Acl::ACCESS_NAME.len(), acl.len()));
        out.insert(Acl::ACCESS_NAME.to_vec(), acl);
        if is_dir {
            let dacl = default_acl();
            budget = budget.saturating_sub(cost(Acl::DEFAULT_NAME.len(), dacl.len()));
            out.insert(Acl::DEFAULT_NAME.to_vec(), dacl);
        }
    }
    for x in &item.xattrs {
        let name = format!("user.a{}", x.name).into_bytes();
        if out.contains_key(&name) {
            continue;
        }
        // A fill byte derived from the name, so two attributes can never pass with
        // their values swapped.
        let value = vec![0xa0 ^ x.name; x.len(block_size)];
        let c = cost(name.len(), value.len());
        if c > budget {
            continue;
        }
        budget -= c;
        out.insert(name, value);
    }
    out
}

/// Turn a spec into the source to build and the tree that image must then hold.
///
/// Every selector is resolved against what exists at that point — a parent from the
/// directories created so far, a hard-link target from the non-directory entries — so
/// the source this returns is always inside the feature envelope. Content is held to a
/// budget so the common case is a filesystem that fits its tree, leaving the
/// out-of-space path as something a case may provoke rather than the norm.
fn realize(spec: &Spec) -> (TreeBuilder, BTreeMap<Vec<u8>, ExpectedEntry>) {
    let block_size = spec.geo.block_size;
    let base = Timestamp::from_secs(BASE_TIME);
    let base_meta = |mode: u16, uid: u32, gid: u32| {
        ferrosys::ext::source::Metadata::new(mode, base).owned_by(uid, gid)
    };

    let mut builder = TreeBuilder::new();
    let mut expected: BTreeMap<Vec<u8>, ExpectedEntry> = BTreeMap::new();
    // `/lost+found` is created — and stamped — by the formatter itself, not by the
    // source.
    expected.insert(b"/lost+found".to_vec(), ExpectedEntry::bare(Expected::Dir));

    // The root, and every directory as it is created; a parent selector indexes here.
    let mut dirs: Vec<Vec<u8>> = vec![Vec::new()];
    // Non-directory paths a hard link may name.
    let mut linkable: Vec<Vec<u8>> = Vec::new();
    // Bound the bytes the tree asks for, so most cases exercise a filesystem that can
    // hold its tree rather than one that refuses it.
    let mut budget = spec.geo.size_bytes() / 4;

    for (i, item) in spec.items.iter().enumerate() {
        let parent = &dirs[usize::from(item.parent) % dirs.len()];
        // A globally unique stem makes the name unique within its parent whatever the
        // padding, so a duplicate path — which the model rejects — is never generated.
        let stem = format!("n{i}").into_bytes();
        let mut name = stem.clone();
        name.resize(usize::from(item.name_len).max(stem.len()), b'x');
        let mut path = parent.clone();
        path.push(b'/');
        path.extend_from_slice(&name);

        let (atime, ctime, mtime) = (
            item.atime.resolve(),
            item.ctime.resolve(),
            item.mtime.resolve(),
        );
        let m = ferrosys::ext::source::Metadata::new(item.mode, mtime)
            .owned_by(item.uid, item.gid)
            .with_times(atime, ctime, mtime);
        let times = Some((atime, ctime, mtime));
        // A hard link with nothing to point at becomes an ordinary small file, so the
        // generator never emits an unresolvable link.
        let kind = match &item.kind {
            RawKind::HardLink(_) if linkable.is_empty() => &RawKind::File(SizeSel::Bytes(16)),
            other => other,
        };

        // The attribute set rides on the kinds that carry one here: directories,
        // files, and symlinks.
        let attach = |mut builder: TreeBuilder, xattrs: &BTreeMap<Vec<u8>, Vec<u8>>| {
            for (name, value) in xattrs {
                builder = builder.xattr(name.clone(), value.clone());
            }
            builder
        };

        match kind {
            RawKind::Dir => {
                let xattrs = resolve_xattrs(item, true, block_size);
                builder = attach(builder.directory(path.clone(), m), &xattrs);
                expected.insert(
                    path.clone(),
                    ExpectedEntry {
                        kind: Expected::Dir,
                        times,
                        xattrs,
                    },
                );
                dirs.push(path);
            }
            RawKind::File(sel) => {
                let want = sel.resolve(block_size).min(budget);
                budget -= want;
                let content = vec![b'c'; want as usize];
                let xattrs = resolve_xattrs(item, false, block_size);
                builder = attach(builder.file(path.clone(), content.clone(), m), &xattrs);
                expected.insert(
                    path.clone(),
                    ExpectedEntry {
                        kind: Expected::File {
                            content,
                            mode: item.mode,
                            uid: item.uid,
                            gid: item.gid,
                        },
                        times,
                        xattrs,
                    },
                );
                linkable.push(path);
            }
            RawKind::Symlink(len) => {
                let target = vec![b't'; usize::from(*len).max(1)];
                let xattrs = resolve_xattrs(item, false, block_size);
                builder = attach(builder.symlink(path.clone(), target.clone(), m), &xattrs);
                expected.insert(
                    path.clone(),
                    ExpectedEntry {
                        kind: Expected::Symlink(target),
                        times,
                        xattrs,
                    },
                );
                linkable.push(path);
            }
            RawKind::HardLink(sel) => {
                let target = linkable[usize::from(*sel) % linkable.len()].clone();
                builder = builder.hardlink(path.clone(), target.clone(), m);
                // The link shares its target's inode, so the times and attributes
                // that inode holds are the target entry's to assert.
                expected.insert(path, ExpectedEntry::bare(Expected::HardLink(target)));
            }
            RawKind::CharDev(major, minor) => {
                builder = builder.char_device(path.clone(), *major, *minor, m);
                expected.insert(
                    path.clone(),
                    ExpectedEntry {
                        kind: Expected::Device {
                            major: *major,
                            minor: *minor,
                            char_special: true,
                        },
                        times,
                        xattrs: BTreeMap::new(),
                    },
                );
                linkable.push(path);
            }
            RawKind::BlockDev(major, minor) => {
                builder = builder.block_device(path.clone(), *major, *minor, m);
                expected.insert(
                    path.clone(),
                    ExpectedEntry {
                        kind: Expected::Device {
                            major: *major,
                            minor: *minor,
                            char_special: false,
                        },
                        times,
                        xattrs: BTreeMap::new(),
                    },
                );
                linkable.push(path);
            }
            RawKind::Fifo => {
                builder = builder.fifo(path.clone(), m);
                expected.insert(
                    path.clone(),
                    ExpectedEntry {
                        kind: Expected::Fifo,
                        times,
                        xattrs: BTreeMap::new(),
                    },
                );
                linkable.push(path);
            }
            RawKind::Socket => {
                builder = builder.socket(path.clone(), m);
                expected.insert(
                    path.clone(),
                    ExpectedEntry {
                        kind: Expected::Socket,
                        times,
                        xattrs: BTreeMap::new(),
                    },
                );
                linkable.push(path);
            }
        }
    }

    // The wide directory: what pushes a directory past a single block.
    let (count, name_len) = spec.wide;
    if count > 0 {
        let dir = b"/wide".to_vec();
        builder = builder.directory(dir.clone(), base_meta(0o755, 0, 0));
        expected.insert(dir.clone(), ExpectedEntry::at_base_time(Expected::Dir));
        for i in 0..count {
            let stem = format!("w{i}").into_bytes();
            let mut name = stem.clone();
            name.resize(usize::from(name_len).max(stem.len()), b'w');
            let mut path = dir.clone();
            path.push(b'/');
            path.extend_from_slice(&name);
            builder = builder.file(path.clone(), Vec::new(), base_meta(0o644, 0, 0));
            expected.insert(
                path,
                ExpectedEntry::at_base_time(Expected::File {
                    content: Vec::new(),
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                }),
            );
        }
    }

    (builder, expected)
}

/// Whether a build failure is one a caller genuinely provoked, rather than a defect.
///
/// These are the capacity and configuration limits: a tree needing more inodes or
/// blocks than the filesystem has, and a filesystem too small to hold its own
/// metadata, its journal, or the reserved descriptors a grow target asks for. Every
/// other error — a model, directory, extent, or I/O failure — means either the crate
/// mishandled input it should represent or the generator left the envelope, and both
/// are failures worth hearing about.
fn is_capacity_refusal(e: &FormatError) -> bool {
    matches!(
        e,
        FormatError::TooManyInodes { .. }
            | FormatError::JournalTooSmall { .. }
            | FormatError::Alloc(AllocError::OutOfSpace { .. })
            | FormatError::Geometry(
                GeometryError::TooSmall { .. }
                    | GeometryError::GrowTargetTooLarge { .. }
                    // An inode-count override too dense for the block size, which the
                    // generator's low counts and small filesystems can legitimately
                    // provoke.
                    | GeometryError::InodesTooDense { .. }
            )
    )
}

/// The outcome of building one case: either a typed refusal, or an image on disk.
enum Built {
    Refused,
    Image(tempfile::NamedTempFile),
}

fn build(spec: &Spec) -> Result<Built, TestCaseError> {
    let (source, _) = realize(spec);
    let file = tempfile::NamedTempFile::new().expect("temp file");
    match format_to(
        source,
        spec.geo.size_bytes(),
        spec.geo.options(),
        file.as_file(),
    ) {
        Ok(_) => Ok(Built::Image(file)),
        Err(e) if is_capacity_refusal(&e) => Ok(Built::Refused),
        Err(e) => Err(TestCaseError::fail(format!(
            "format refused an in-envelope tree with a non-capacity error: {e}"
        ))),
    }
}

/// Map every path in the image to the inode number its directory entry names.
///
/// An [`Inode`] does not carry its own number, so proving that two names are one file
/// means reading the numbers out of the directory entries that point at them.
fn inode_numbers(
    r: &mut Reader<std::fs::File>,
) -> Result<BTreeMap<Vec<u8>, u32>, Box<dyn std::error::Error>> {
    let mut out = BTreeMap::new();
    let mut stack: Vec<(Vec<u8>, u32)> = vec![(Vec::new(), 2)];
    let mut descended: HashSet<u32> = HashSet::from([2]);
    while let Some((prefix, number)) = stack.pop() {
        let dir = r.inode(number).map_err(Box::new)?;
        for entry in r.read_dir(&dir).map_err(Box::new)? {
            if entry.name == b"." || entry.name == b".." {
                continue;
            }
            let mut path = prefix.clone();
            path.push(b'/');
            path.extend_from_slice(&entry.name);
            let child: Result<Inode, ReadError> = r.inode(entry.inode);
            let child = child.map_err(Box::new)?;
            out.insert(path.clone(), entry.inode);
            if child.mode & 0o170000 == 0o040000 && descended.insert(entry.inode) {
                stack.push((path, entry.inode));
            }
        }
    }
    Ok(out)
}

/// Read the image back and check it holds exactly the tree that was asked for, under
/// exactly the options that were given.
fn check_round_trip(
    path: &Path,
    spec: &Spec,
    expected: &BTreeMap<Vec<u8>, ExpectedEntry>,
) -> Result<(), TestCaseError> {
    let f = std::fs::File::open(path).expect("open image");
    let mut r = Reader::open(f).map_err(|e| TestCaseError::fail(format!("open image: {e}")))?;

    // Every checksum the profile carries verifies, and a strict scan of the whole
    // image finds nothing to report: an image ferrosys wrote is one ferrosys considers
    // conformant.
    r.verify_checksums()
        .map_err(|e| TestCaseError::fail(format!("checksums: {e}")))?;
    let report = r.scan();
    if !report.is_clean() {
        return Err(TestCaseError::fail(format!(
            "a strict scan of a freshly written image found anomalies: {}",
            report.to_table()
        )));
    }

    // The tunables land in the superblock exactly as given.
    let tun = &spec.geo.tun;
    let sb = r.superblock().clone();
    prop_assert_eq!(sb.volume_name, tun.label, "volume label");
    let reserved = ReservedRatio::from_hundredths_of_percent(tun.reserved_hundredths)
        .expect("the strategy stays at or below the ceiling");
    prop_assert_eq!(
        sb.r_blocks_count,
        reserved.blocks(sb.blocks_count),
        "reserved blocks at {} hundredths of a percent of {}",
        tun.reserved_hundredths,
        sb.blocks_count
    );
    prop_assert_eq!(sb.hash_seed, tun.hash_seed, "hash seed");
    prop_assert_eq!(
        sb.def_hash_version,
        tun.hash_version.to_u8(),
        "hash version"
    );
    prop_assert_eq!(
        sb.flags & 0x3,
        tun.hash_signedness.to_flag(),
        "hash signedness flag"
    );
    prop_assert_eq!(
        sb.inodes_count % sb.inodes_per_group,
        0,
        "the inode count fills whole groups"
    );
    if let InodeSel::Count(n) = tun.inodes {
        // The realized count meets the request, except the documented shortfall
        // where an inode-table block holds fewer than eight inodes and each group's
        // share rounds down to a multiple of eight.
        let groups = u64::from(sb.inodes_count / sb.inodes_per_group);
        let shortfall = if spec.geo.block_size < 4096 {
            8 * groups
        } else {
            0
        };
        prop_assert!(
            u64::from(sb.inodes_count) + shortfall >= u64::from(n),
            "asked for {} inodes, got {}",
            n,
            sb.inodes_count
        );
    }

    let tree: BTreeMap<Vec<u8>, Inode> = r
        .walk()
        .map_err(|e| TestCaseError::fail(format!("walk: {e}")))?
        .into_iter()
        .map(|e| (e.path, e.inode))
        .collect();
    let numbers =
        inode_numbers(&mut r).map_err(|e| TestCaseError::fail(format!("inode numbers: {e}")))?;

    let found: Vec<&Vec<u8>> = tree.keys().collect();
    let want: Vec<&Vec<u8>> = expected.keys().collect();
    if found != want {
        return Err(TestCaseError::fail(format!(
            "the image holds a different set of paths than the source asked for: \
             {} written, {} read back",
            want.len(),
            found.len()
        )));
    }

    for (path, want) in expected {
        let inode = tree[path].clone();

        // The fields every kind carries — except through a hard link, whose inode's
        // times and attributes belong to the target entry's own assertion.
        if !matches!(want.kind, Expected::HardLink(_)) {
            if let Some((atime, ctime, mtime)) = want.times {
                prop_assert_eq!(inode.atime, atime, "atime of {:?}", path);
                prop_assert_eq!(inode.ctime, ctime, "ctime of {:?}", path);
                prop_assert_eq!(inode.mtime, mtime, "mtime of {:?}", path);
                // The creation time is derived from the modification time.
                prop_assert_eq!(inode.crtime, mtime, "crtime of {:?}", path);
            }
            let got: BTreeMap<Vec<u8>, Vec<u8>> = r
                .xattrs(&inode)
                .map_err(|e| TestCaseError::fail(format!("xattrs of {path:?}: {e}")))?
                .into_iter()
                .map(|x| (x.name, x.value))
                .collect();
            prop_assert_eq!(
                &got,
                &want.xattrs,
                "the attribute set of {:?} is not the one attached",
                path
            );
        }

        match &want.kind {
            Expected::Dir => prop_assert_eq!(inode.mode & 0o170000, 0o040000, "{:?}", path),
            Expected::File {
                content,
                mode,
                uid,
                gid,
            } => {
                prop_assert_eq!(inode.mode & 0o170000, 0o100000, "{:?}", path);
                prop_assert_eq!(inode.mode & 0o7777, *mode, "{:?}", path);
                prop_assert_eq!(inode.uid, *uid, "{:?}", path);
                prop_assert_eq!(inode.gid, *gid, "{:?}", path);
                let data = r
                    .read_data(&inode)
                    .map_err(|e| TestCaseError::fail(format!("read {path:?}: {e}")))?;
                prop_assert_eq!(&data, content, "contents of {:?}", path);
            }
            Expected::Symlink(target) => {
                prop_assert_eq!(inode.mode & 0o170000, 0o120000, "{:?}", path);
                let got = r
                    .read_symlink(&inode)
                    .map_err(|e| TestCaseError::fail(format!("symlink {path:?}: {e}")))?;
                prop_assert_eq!(&got, target, "target of {:?}", path);
            }
            Expected::HardLink(target) => {
                // The two names are one file: they resolve to the same inode number,
                // and its link count counts every name that reaches it. Both numbers
                // must exist — two `None`s compare equal, and would wave through a
                // directory walk that lost both entries.
                let ours = numbers.get(path);
                let theirs = numbers.get(target);
                prop_assert!(
                    ours.is_some() && theirs.is_some(),
                    "{:?} or its target {:?} has no directory entry",
                    path,
                    target
                );
                prop_assert_eq!(
                    ours,
                    theirs,
                    "{:?} and its target {:?} are not the same inode",
                    path,
                    target
                );
                prop_assert!(inode.links_count >= 2, "{:?}", path);
            }
            Expected::Device {
                major,
                minor,
                char_special,
            } => {
                let want_type = if *char_special { 0o020000 } else { 0o060000 };
                prop_assert_eq!(inode.mode & 0o170000, want_type, "{:?}", path);
                prop_assert_eq!(r.device(&inode), (*major, *minor), "{:?}", path);
            }
            Expected::Fifo => prop_assert_eq!(inode.mode & 0o170000, 0o010000, "{:?}", path),
            Expected::Socket => prop_assert_eq!(inode.mode & 0o170000, 0o140000, "{:?}", path),
        }
    }
    Ok(())
}

// --- the properties ---

/// The case count to run, defaulting to `cases` and overridable by `PROPTEST_CASES`
/// for a longer campaign.
///
/// The override has to be read here rather than left to `ProptestConfig::default()`:
/// a `cases:` field set in the struct literal *replaces* the value the environment
/// supplied, so hard-coding one silently pins the campaign to that size however large
/// a run is asked for.
///
/// The failure-persistence path is named explicitly for the same reason. The default
/// looks for the source file's crate root and, from an integration test, does not find
/// one — it then warns and persists nothing, so the shrunk case that took a long
/// campaign to find would be printed once and lost. Named here, a failing case is
/// written to the file below and replayed on every subsequent run, which is what makes
/// a rare case a permanent regression test rather than an anecdote.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        max_shrink_iters: 4096,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/property.proptest-regressions",
        ))),
        ..ProptestConfig::default()
    }
}

proptest! {
    // The reader is in-process, so this tier is cheap enough to run a real number of
    // cases on every `cargo test`.
    #![proptest_config(config(64))]

    /// Whatever the tree and whatever the geometry, the image an accepted build
    /// produces holds exactly the tree it was given: every path, every content byte,
    /// every mode, owner, target, device number, timestamp, and attribute — under
    /// exactly the tunables asked for — and it trips no anomaly when its own reader
    /// scans it strictly.
    #[test]
    fn an_arbitrary_tree_reads_back_exactly_as_it_was_written(spec in spec()) {
        if let Built::Image(image) = build(&spec)? {
            let (_, expected) = realize(&spec);
            check_round_trip(image.path(), &spec, &expected)?;
        }
    }
}

/// A spec whose image is small enough to format twice and compare per case.
/// Reproducibility is a property of the writer's determinism, not of scale, so the
/// group count is halved until the image fits rather than discarding the case.
fn compact_spec() -> impl Strategy<Value = Spec> {
    const CAP: u64 = 256 * MIB;
    spec().prop_map(|mut s| {
        while s.geo.size_bytes() > CAP && s.geo.groups > 1 {
            s.geo.groups /= 2;
        }
        if s.geo.size_bytes() > CAP {
            s.geo.tail_blocks = 0;
        }
        s
    })
}

/// Compare two files byte for byte in fixed-size chunks, reporting the first
/// difference's offset — without ever holding either image in memory whole.
fn first_difference(a: &Path, b: &Path) -> std::io::Result<Option<u64>> {
    let (mut fa, mut fb) = (std::fs::File::open(a)?, std::fs::File::open(b)?);
    let (mut ba, mut bb) = (vec![0u8; MIB as usize], vec![0u8; MIB as usize]);
    let mut offset = 0u64;
    loop {
        let na = read_full(&mut fa, &mut ba)?;
        let nb = read_full(&mut fb, &mut bb)?;
        if ba[..na] != bb[..nb] {
            let at = ba[..na.min(nb)]
                .iter()
                .zip(&bb[..na.min(nb)])
                .position(|(x, y)| x != y)
                .unwrap_or(na.min(nb));
            return Ok(Some(offset + at as u64));
        }
        if na == 0 {
            return Ok(None);
        }
        offset += na as u64;
    }
}

/// Read until the buffer is full or the file ends, so the two sides' chunks stay
/// aligned even when a read comes back short.
fn read_full(f: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::io::Read as _;
    let mut n = 0;
    while n < buf.len() {
        let got = f.read(&mut buf[n..])?;
        if got == 0 {
            break;
        }
        n += got;
    }
    Ok(n)
}

proptest! {
    #![proptest_config(config(24))]

    /// The reproducibility guarantee, generatively: one spec, formatted twice, is the
    /// same bytes both times. The fixed reproducibility tests pin four known cases;
    /// this holds the guarantee across the whole generated space — any geometry, any
    /// tree, any tunables — where a stray clock read, an iteration over an unordered
    /// map, or an uninitialized pad byte would break equality.
    #[test]
    fn an_accepted_spec_formats_to_identical_bytes_twice(spec in compact_spec()) {
        let first = build(&spec)?;
        let second = build(&spec)?;
        match (&first, &second) {
            (Built::Image(a), Built::Image(b)) => {
                if let Some(offset) = first_difference(a.path(), b.path())
                    .map_err(|e| TestCaseError::fail(format!("compare: {e}")))?
                {
                    return Err(TestCaseError::fail(format!(
                        "two formats of one spec differ at byte {offset}\ngeometry: {:?}",
                        spec.geo
                    )));
                }
            }
            (Built::Refused, Built::Refused) => {}
            _ => {
                return Err(TestCaseError::fail(
                    "one spec was accepted once and refused once — the verdict itself \
                     is nondeterministic".to_string(),
                ));
            }
        }
    }
}

proptest! {
    // Each case shells out to `e2fsck` over an image up to two gigabytes, so this tier
    // draws fewer cases by default. PROPTEST_CASES raises it for a longer campaign.
    #![proptest_config(config(16))]

    /// The invariant the crate exists to hold: whatever the generator asks for, an
    /// image ferrosys writes is one a foreign checker finds nothing wrong with.
    #[test]
    fn an_arbitrary_tree_builds_an_e2fsck_clean_image(spec in spec()) {
        if !util::available("e2fsck") {
            return Ok(());
        }
        if let Built::Image(image) = build(&spec)?
            && let Err(why) = util::e2fsck_clean(image.path())
        {
            return Err(TestCaseError::fail(format!(
                "a generated image did not check clean: {why}\ngeometry: {:?}",
                spec.geo
            )));
        }
    }
}

/// The properties above are only worth anything if the generator mostly produces
/// filesystems that actually get built: a property whose every case is refused passes
/// while proving nothing, and it would do so silently.
///
/// So this pins the generator's yield. Most cases must reach an image; the refusals
/// that remain are the capacity and grow-target guards, which are themselves worth
/// exercising. If a change to the crate or to the strategies pushes the yield down,
/// this fails and says so rather than letting the tier hollow out unnoticed.
#[test]
fn the_generator_mostly_produces_filesystems_that_build() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    const SAMPLES: u32 = 120;
    let mut runner = TestRunner::deterministic();
    let strategy = spec();
    let mut built = 0;
    let mut refusals: BTreeMap<&'static str, u32> = BTreeMap::new();

    for _ in 0..SAMPLES {
        let spec = strategy
            .new_tree(&mut runner)
            .expect("generate a spec")
            .current();
        match build(&spec) {
            Ok(Built::Image(_)) => built += 1,
            Ok(Built::Refused) => *refusals.entry("capacity or grow target").or_default() += 1,
            Err(e) => panic!("the generator left the feature envelope: {e:?}"),
        }
    }

    for (why, count) in &refusals {
        eprintln!("refused {count:3} of {SAMPLES}: {why}");
    }
    assert!(
        built * 2 > SAMPLES,
        "only {built} of {SAMPLES} generated cases built an image: the writer \
         properties are close to vacuous"
    );
}
