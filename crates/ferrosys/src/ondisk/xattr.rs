//! Extended attributes (`struct ext4_xattr_*`), in both the in-inode and the
//! external-block forms.
//!
//! An extended attribute is a name/value pair attached to an inode. ext4 stores a
//! small set of them inline in the inode's extra area and spills the rest to a
//! dedicated block pointed at by `i_file_acl`. Both forms share the same
//! `ext4_xattr_entry` record and the same value packing: fixed-size entry headers
//! grow up from a header while values grow down from the end of the region, meeting
//! in the middle.
//!
//! This module is pure: it turns a set of [`Xattr`] pairs into the bytes of an
//! inline region or a block and parses them back, computing the name/value hash the
//! block form carries. It allocates nothing and performs no I/O.
//!
//! One attribute value has an encoding of its own here. A POSIX ACL travels in the
//! version-2 `posix_acl_xattr` form every boundary outside a filesystem speaks, and ext4
//! stores it more tightly: a `a_version = 1` header, and an id field only on the two tags
//! that name somebody. [`encode_acl`] and [`decode_acl`] are that narrowing, and they are
//! here rather than with [`Acl`] because the compaction is this format's, not the value's.
//!
//! Two layout details are load-bearing and differ between the forms. The value
//! offset (`e_value_offs`) is measured from the first entry for the inline form and
//! from the start of the block for the block form. And the per-entry hash
//! (`e_hash`) is zero for inline entries but is computed for block entries, where
//! `e2fsck` validates it regardless of whether metadata checksums are enabled. The
//! block hash (`h_hash`) folds the entry hashes together; the kernel uses it only
//! as a cache key when deciding whether identical blocks can be shared, so it is
//! written to the same recipe `e2fsprogs` uses but no checker verifies it.

use super::{ParseError, get_u8, get_u16, get_u32, put_u16, put_u32};
use crate::acl::{Acl, AclEntry, AclError, AclQualifier, TAG_GROUP, TAG_USER};
use crate::xattr::Xattr;

/// The magic identifying an xattr region, in both the inline header and the block
/// header (`h_magic`).
pub(crate) const XATTR_MAGIC: u32 = 0xEA02_0000;

/// The version ext4 writes in a stored ACL's header (`a_version`), distinct from the
/// version-2 form the value carries at every boundary outside the filesystem.
const ACL_VERSION: u32 = 0x0001;

/// Encode an ACL as ext4 stores it: the version header, then each entry as a tag and a
/// permission field, with an id after them only for a named user or group.
#[must_use]
pub fn encode_acl(acl: &Acl) -> Vec<u8> {
    let entries = acl.entries();
    let mut out = Vec::with_capacity(4 + entries.len() * 8);
    out.extend_from_slice(&ACL_VERSION.to_le_bytes());
    for e in entries {
        let (tag, id) = e.who.tag_and_id();
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&e.perm.to_le_bytes());
        if let Some(id) = id {
            out.extend_from_slice(&id.to_le_bytes());
        }
    }
    out
}

/// Parse a stored ACL back, revalidating the result.
///
/// The entries are re-sorted into canonical POSIX order, so an ACL stored out of order
/// decodes into a canonical [`Acl`] rather than being reported as malformed. The returned
/// value reflects the ACL's meaning, not the exact byte order it was stored in.
///
/// # Errors
///
/// [`AclError::Malformed`] if the version is not 1 or the bytes are truncated, or a
/// validity error from [`Acl::new`].
pub fn decode_acl(bytes: &[u8]) -> Result<Acl, AclError> {
    if bytes.len() < 4 {
        return Err(AclError::Malformed {
            reason: "shorter than the version header",
        });
    }
    let (header, mut rest) = bytes.split_at(4);
    let version = u32::from_le_bytes(header.try_into().expect("split at four bytes"));
    if version != ACL_VERSION {
        return Err(AclError::Malformed {
            reason: "unexpected version",
        });
    }
    let mut entries = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(AclError::Malformed {
                reason: "truncated entry",
            });
        }
        let tag = get_u16(rest, 0);
        let perm = get_u16(rest, 2);
        rest = &rest[4..];
        // Only the two tags that name somebody store an id, so how far this entry reaches
        // depends on the tag it opened with.
        let id = if matches!(tag, TAG_USER | TAG_GROUP) {
            if rest.len() < 4 {
                return Err(AclError::Malformed {
                    reason: "truncated entry id",
                });
            }
            let id = get_u32(rest, 0);
            rest = &rest[4..];
            id
        } else {
            0
        };
        let who = AclQualifier::from_tag(tag, id).ok_or(AclError::Malformed {
            reason: "unknown tag",
        })?;
        entries.push(AclEntry { who, perm });
    }
    Acl::new(entries)
}

/// The inline (in-inode) header: just the 4-byte magic.
const IBODY_HEADER_LEN: usize = 4;
/// The external block header (`struct ext4_xattr_header`): magic, refcount, block
/// count, hash, checksum, and three reserved words.
const BLOCK_HEADER_LEN: usize = 32;

/// Byte offset of `h_checksum` within an attribute block's header. The field participates in
/// its own checksum as four zero bytes, which is how [`encode_block`] leaves it.
pub(crate) const CHECKSUM_OFFSET: usize = 16;
/// The fixed part of one entry (`struct ext4_xattr_entry`) before its name.
const ENTRY_HEADER_LEN: usize = 16;

/// Round `n` up to the 4-byte boundary entries and values are aligned to (the ext4
/// documentation's Extended Attributes page).
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// The namespace prefixes ext4 encodes as an `e_name_index`, longest first so
/// `system.posix_acl_access` matches before the bare `system.` prefix.
///
/// Indices 2 and 3 are whole names, not prefixes: they stand for
/// `system.posix_acl_access` and `system.posix_acl_default` with an empty stored
/// name.
///
/// The rarely used indices (5 Lustre, 10 Hurd) are not listed. A name this crate writes
/// always maps to a listed prefix or to index 0 with its whole self stored; a foreign
/// attribute carrying an unlisted index reads back by its stored name without the namespace
/// prefix expanded. Index 9 is not listed either: its one entry, an encrypted inode's
/// context, is not read back as an attribute at all (`Stored::is_the_formats`).
const PREFIXES: &[(u8, &[u8])] = &[
    (2, b"system.posix_acl_access"),
    (3, b"system.posix_acl_default"),
    (8, b"system.richacl"),
    (1, b"user."),
    (7, b"system."),
    (4, b"trusted."),
    (6, b"security."),
];

/// Split a full name into its `e_name_index` and the remainder stored on disk.
///
/// A name matching no known prefix uses index 0 and stores its whole self.
fn split_name(name: &[u8]) -> (u8, &[u8]) {
    for &(index, prefix) in PREFIXES {
        // Indices 2, 3, and 8 are exact whole names (no per-attribute suffix);
        // the others are true prefixes.
        if matches!(index, 2 | 3 | 8) {
            if name == prefix {
                return (index, b"");
            }
        } else if let Some(rest) = name.strip_prefix(prefix) {
            return (index, rest);
        }
    }
    (0, name)
}

/// Whether an attribute's on-disk name would be empty — a zero-length `e_name_len`.
///
/// For the whole-name indices (2, 3, 8: an ACL or richacl attribute *is* its namespace,
/// with nothing stored after it) an empty stored name is correct. For every other name
/// it is an attribute with no name at all: under index 0 the entry's header is all
/// zeros, which is exactly the end-of-list terminator that stops the parse and hides
/// every attribute after it; under any other index it is an entry no kernel handler can
/// address, since the syscall boundary needs a name past the namespace prefix.
pub(crate) fn has_empty_name(name: &[u8]) -> bool {
    let (index, stored) = split_name(name);
    stored.is_empty() && !matches!(index, 2 | 3 | 8)
}

/// Rejoin an `e_name_index` and stored name into the full name.
fn join_name(index: u8, stored: &[u8]) -> Vec<u8> {
    for &(i, prefix) in PREFIXES {
        if i == index {
            let mut out = prefix.to_vec();
            out.extend_from_slice(stored);
            return out;
        }
    }
    stored.to_vec()
}

/// The hash an attribute block's entry records in `e_hash`, over its stored name and value.
///
/// The rule is the one FreeBSD's ext2fs implements in its extended-attribute code
/// (BSD-2-Clause): from zero, each byte of the stored name (the part after the namespace
/// prefix) is folded in by rotating the hash left five bits and XOR-ing the byte, then each
/// little-endian 32-bit word of the value, over its length rounded up to whole words, by
/// rotating left sixteen bits and XOR-ing the word.
///
/// A name byte at or above `0x80` is folded as its unsigned value. That is the value the
/// pinned `mke2fs` writes, on a filesystem flagged for signed directory hashes as well, and
/// the pinned `e2fsck` checks every entry's hash in a block and accepts it (observed). The
/// entries of every block `mke2fs -d` and a Linux kernel wrote in this crate's gates carry
/// exactly this hash.
fn hash_entry(name: &[u8], value: &[u8]) -> u32 {
    let named = name
        .iter()
        .fold(0u32, |hash, &byte| hash.rotate_left(5) ^ u32::from(byte));
    value.chunks(4).fold(named, |hash, chunk| {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        hash.rotate_left(16) ^ u32::from_le_bytes(word)
    })
}

/// The hash an attribute block's header records in `h_hash`: the entries' hashes in entry
/// order, folded by rotating left sixteen bits and XOR-ing each, or zero where any of them is
/// zero (FreeBSD's ext2fs, as for [`hash_entry`]).
///
/// A Linux kernel writes this value (observed). The pinned `mke2fs -d` writes zero, and the
/// pinned `e2fsck` accepts both; no checker compares the field.
fn block_hash(entry_hashes: &[u32]) -> u32 {
    if entry_hashes.contains(&0) {
        return 0;
    }
    entry_hashes
        .iter()
        .fold(0, |hash, &entry| hash.rotate_left(16) ^ entry)
}

/// Storage an attribute set occupies past its header: the entry records (each
/// header-plus-name padded to 4 bytes), the 4-byte end-of-list marker, and the
/// padded values.
fn packed_len(attrs: &[Xattr]) -> usize {
    // Four bytes for the zero entry that terminates the list.
    let mut total = 4;
    for x in attrs {
        let (_, stored) = split_name(&x.name);
        total += align4(ENTRY_HEADER_LEN + stored.len());
        total += align4(x.value.len());
    }
    total
}

/// The number of bytes an external xattr block needs to hold `attrs`: the 32-byte
/// header plus the packed entries and values. Used to reject a set too large to
/// store in one block.
pub(crate) fn block_len(attrs: &[Xattr]) -> usize {
    BLOCK_HEADER_LEN + packed_len(attrs)
}

/// The storage one attribute occupies in either region: its entry record
/// (header plus stored name, padded) and its padded value.
fn attr_len(x: &Xattr) -> usize {
    let (_, stored) = split_name(&x.name);
    align4(ENTRY_HEADER_LEN + stored.len()) + align4(x.value.len())
}

/// Partition `attrs` between the inode's inline region of `region_len` bytes and an
/// external block, returning `(inline, spilled)`.
///
/// Placement is deterministic in the set: the attributes are taken in the canonical
/// on-disk order ([`sorted`]) and each is placed inline when it still fits the
/// region's remaining space — the region less its 4-byte magic and the 4-byte
/// terminating entry — and spilled to the block otherwise. A later, smaller
/// attribute may therefore go inline after a larger one has spilled. The split is
/// exhaustive: every attribute lands in one of the two vectors, and whether the
/// spilled side fits a block is the caller's check, via [`block_len`].
pub(crate) fn split_for_storage(attrs: &[Xattr], region_len: usize) -> (Vec<Xattr>, Vec<Xattr>) {
    let mut inline_free = region_len.saturating_sub(IBODY_HEADER_LEN + 4);
    let mut inline = Vec::new();
    let mut spilled = Vec::new();
    for x in sorted(attrs) {
        let need = attr_len(&x);
        if need <= inline_free {
            inline_free -= need;
            inline.push(x);
        } else {
            spilled.push(x);
        }
    }
    (inline, spilled)
}

/// The longest stored name (the remainder after the namespace prefix) across
/// `attrs`, which must fit the single-byte `e_name_len`.
pub(crate) fn longest_stored_name(attrs: &[Xattr]) -> usize {
    attrs
        .iter()
        .map(|x| split_name(&x.name).1.len())
        .max()
        .unwrap_or(0)
}

/// Sort attributes by `(name_index, stored-name length, stored name)`, the order
/// the block form requires and a deterministic order for the inline form.
fn sorted(attrs: &[Xattr]) -> Vec<Xattr> {
    let mut v = attrs.to_vec();
    v.sort_by(|a, b| {
        let (ia, na) = split_name(&a.name);
        let (ib, nb) = split_name(&b.name);
        ia.cmp(&ib).then(na.len().cmp(&nb.len())).then(na.cmp(nb))
    });
    v
}

/// Encode `attrs` into the inline region of `region_len` bytes that follows the
/// inode's extra fields, or `None` if they do not fit and must spill to a block.
///
/// The returned buffer is exactly `region_len` bytes: the 4-byte magic, the entry
/// records growing up from offset 4, and the values growing down from the end.
/// Inline entries carry a zero `e_hash` and their `e_value_offs` is measured from
/// the first entry (offset 4).
pub(crate) fn encode_inline(attrs: &[Xattr], region_len: usize) -> Option<Vec<u8>> {
    if attrs.is_empty() {
        return Some(vec![0u8; region_len]);
    }
    let attrs = sorted(attrs);
    if IBODY_HEADER_LEN + packed_len(&attrs) > region_len {
        return None;
    }
    let mut buf = vec![0u8; region_len];
    put_u32(&mut buf, 0, XATTR_MAGIC);
    // Values grow down from the region end; e_value_offs is relative to the first
    // entry, which begins right after the 4-byte header.
    let base = IBODY_HEADER_LEN;
    let mut entry_off = base;
    let mut value_off = region_len;
    for x in &attrs {
        let (index, stored) = split_name(&x.name);
        value_off -= align4(x.value.len());
        buf[value_off..value_off + x.value.len()].copy_from_slice(&x.value);
        // An empty value occupies no bytes, so it records offset 0 rather than the
        // cursor's position, matching how `mke2fs` writes `e_value_offs` for one.
        let value_offs = if x.value.is_empty() {
            0
        } else {
            value_off - base
        };
        write_entry(
            &mut buf,
            entry_off,
            index,
            stored,
            x.value.len(),
            value_offs,
            0,
        );
        entry_off += align4(ENTRY_HEADER_LEN + stored.len());
    }
    // Bytes [entry_off, value_off) are already zero, terminating the entry list.
    Some(buf)
}

/// Encode `attrs` into a full external xattr block of `block_size` bytes.
///
/// The block carries the 32-byte header (refcount 1, one block, the folded block
/// hash, a zero checksum written through the checksum seam elsewhere), sorted entry
/// records with their computed `e_hash`, and the values packed from the block end.
/// `e_value_offs` is measured from the start of the block.
///
/// The entry records grow up from the header while the values grow down from the end,
/// so the caller must ensure the attributes fit: [`block_len`] gives the bytes a set needs,
/// and the model refuses a larger one before a block is ever encoded. That the check here
/// is unreachable through the crate's own surface is why it is stated rather than assumed —
/// a guard on the bytes this writes is worth nothing if it is compiled out of the build a
/// consumer installs, and what it prevents is a silently wrong attribute block.
pub(crate) fn encode_block(attrs: &[Xattr], block_size: usize) -> Vec<u8> {
    let attrs = sorted(attrs);
    // The same bound `encode_inline` applies to its region, in the same terms, before a
    // cursor moves. Reaching the loop with a set too large walks the value cursor below the
    // start of the buffer, which is an index panic rather than an account of what was wrong.
    assert!(
        block_len(&attrs) <= block_size,
        "xattr entries and values overflow the block"
    );
    let mut buf = vec![0u8; block_size];
    let mut entry_off = BLOCK_HEADER_LEN;
    let mut value_off = block_size;
    let mut hashes = Vec::with_capacity(attrs.len());
    for x in &attrs {
        let (index, stored) = split_name(&x.name);
        value_off -= align4(x.value.len());
        buf[value_off..value_off + x.value.len()].copy_from_slice(&x.value);
        let e_hash = hash_entry(stored, &x.value);
        hashes.push(e_hash);
        // Block value offsets are absolute from the block start; an empty value records
        // offset 0 rather than the cursor's position, as `mke2fs` writes it.
        let value_offs = if x.value.is_empty() { 0 } else { value_off };
        write_entry(
            &mut buf,
            entry_off,
            index,
            stored,
            x.value.len(),
            value_offs,
            e_hash,
        );
        entry_off += align4(ENTRY_HEADER_LEN + stored.len());
    }
    // The entry records and the values did not cross, and the terminating zero entry has
    // its four bytes. The bound above makes this arithmetic rather than a hope, and it is
    // kept as the statement of what that bound buys.
    assert!(
        entry_off + 4 <= value_off,
        "xattr entries and values overflow the block"
    );
    put_u32(&mut buf, 0, XATTR_MAGIC);
    put_u32(&mut buf, 4, 1); // h_refcount: this inode alone
    put_u32(&mut buf, 8, 1); // h_blocks: one block
    put_u32(&mut buf, 12, block_hash(&hashes));
    // h_checksum stays zero here: it is written through the checksum seam only
    // when metadata checksums are on.
    buf
}

/// Write one `ext4_xattr_entry` record: the header at `off` and the stored name
/// after it.
fn write_entry(
    buf: &mut [u8],
    off: usize,
    name_index: u8,
    stored: &[u8],
    value_size: usize,
    value_offs: usize,
    e_hash: u32,
) {
    // The stored name length is one byte on disk; the model rejects names past 255, so a
    // longer one here is a contract violation rather than a value to truncate. Stated
    // unconditionally, because the alternative in a build with the check compiled out is
    // `as u8` wrapping a 256-byte name to a recorded length of zero — a smaller wrong value
    // written into an image, which is the one outcome this layer never chooses (see
    // `dirent::min_rec_len`, which saturates for the same reason).
    assert!(
        stored.len() <= 255,
        "an xattr stored name is at most 255 bytes"
    );
    buf[off] = stored.len() as u8;
    buf[off + 1] = name_index;
    put_u16(buf, off + 2, value_offs as u16);
    put_u32(buf, off + 4, 0); // e_value_inum: value is in this region
    put_u32(buf, off + 8, value_size as u32);
    put_u32(buf, off + 12, e_hash);
    buf[off + ENTRY_HEADER_LEN..off + ENTRY_HEADER_LEN + stored.len()].copy_from_slice(stored);
}

/// Parse the inline xattr region (the bytes after the inode's extra fields) back
/// into attributes. An absent magic means the inode carries no inline attributes.
///
/// # Errors
///
/// [`ParseError`] if an entry or value reference runs outside the region.
#[cfg(test)]
pub(crate) fn parse_inline(region: &[u8]) -> Result<Vec<Xattr>, ParseError> {
    Ok(attributes(parse_inline_stored(region)?))
}

/// Parse the inline xattr region into every entry it stores, the format's own among them.
///
/// # Errors
///
/// [`ParseError`] if an entry or value reference runs outside the region.
pub(crate) fn parse_inline_stored(region: &[u8]) -> Result<Vec<Stored>, ParseError> {
    if region.len() < IBODY_HEADER_LEN || get_u32(region, 0) != XATTR_MAGIC {
        return Ok(Vec::new());
    }
    parse_entries(region, IBODY_HEADER_LEN, IBODY_HEADER_LEN)
}

/// Parse an external xattr block back into attributes. An absent magic yields no
/// attributes.
///
/// # Errors
///
/// [`ParseError`] if an entry or value reference runs outside the block.
#[cfg(test)]
pub(crate) fn parse_block(block: &[u8]) -> Result<Vec<Xattr>, ParseError> {
    Ok(attributes(parse_block_stored(block)?))
}

/// Parse an external xattr block into every entry it stores.
///
/// # Errors
///
/// [`ParseError`] if an entry or value reference runs outside the block.
pub(crate) fn parse_block_stored(block: &[u8]) -> Result<Vec<Stored>, ParseError> {
    if block.len() < BLOCK_HEADER_LEN || get_u32(block, 0) != XATTR_MAGIC {
        return Ok(Vec::new());
    }
    parse_entries(block, BLOCK_HEADER_LEN, 0)
}

/// The attributes of `stored`, as a test reads them: the format's own entries left out, and a
/// value kept in an inode read back empty.
#[cfg(test)]
fn attributes(stored: Vec<Stored>) -> Vec<Xattr> {
    stored
        .into_iter()
        .filter(|entry| !entry.is_the_formats())
        .map(|entry| Xattr {
            name: entry.name,
            value: match entry.value {
                Value::Here(value) => value,
                Value::InInode { .. } => Vec::new(),
            },
        })
        .collect()
}

/// One entry of an attribute region, as it is stored.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Stored {
    /// The name, its namespace expanded.
    pub(crate) name: Vec<u8>,
    /// The `e_name_index` it was stored under.
    pub(crate) index: u8,
    /// The value, or where it is kept.
    pub(crate) value: Value,
}

/// Where an attribute's value is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Value {
    /// In the region, beside the entry.
    Here(Vec<u8>),
    /// In the data of an inode of its own (`ea_inode`), `size` bytes of it.
    InInode {
        /// The inode, `e_value_inum`.
        inode: u32,
        /// The value's length, `e_value_size`.
        size: u32,
    },
}

impl Stored {
    /// Whether the entry is one the format keeps for itself rather than an attribute of the
    /// file: an encrypted inode's encryption context — name index 9, name `c`, observed on
    /// every encrypted inode a Linux 7.1 driver wrote — and an inline inode's `system.data`,
    /// which holds what its block area has no room for. The attribute calls expose neither:
    /// the first describes the encryption, and the second is the file's own content.
    pub(crate) fn is_the_formats(&self) -> bool {
        (self.index == 9 && self.name == b"c") || (self.index == 7 && self.name == b"system.data")
    }
}

/// Walk the entry list starting at `first_entry`, resolving each value at
/// `value_base + e_value_offs`. The list ends at an all-zero entry header — its
/// name length, name index, and value offset all zero. A zero name length alone is
/// *not* the end: an attribute whose whole name is its namespace prefix (an ACL,
/// stored under name index 2 or 3) has an empty stored name and so a zero name
/// length, while its non-zero name index keeps its header word non-zero.
fn parse_entries(
    buf: &[u8],
    first_entry: usize,
    value_base: usize,
) -> Result<Vec<Stored>, ParseError> {
    let mut out = Vec::new();
    let mut off = first_entry;
    // The values one region yields, summed. Each entry's own bounds are exact — a value is
    // confined to the region — but nothing bounded their *sum*, and an entry costs sixteen
    // bytes on disk while claiming the whole region as its value. A region of `B` bytes
    // therefore held `(B - 32) / 16` entries each copying `B`, which is `B² / 16`: about a
    // megabyte from a 4 KiB block, and 268 from a 64 KiB one — and a scan re-parses the
    // region for every in-use inode that names it, so an image whose inodes all point at one
    // crafted block turns 64 KiB into terabytes of copying. A hang, not a spike.
    //
    // The values a region really holds cannot exceed the region, so that is the bound. It
    // cannot refuse a well-formed set: every value is stored in the region once.
    let mut value_bytes = 0usize;
    loop {
        // The list ends at a zero word, which takes four bytes and not a whole header: entries
        // whose values are kept in inodes of their own leave no values in the region, and can
        // fill an inode's to within a header of its end. Observed: a Linux 7.1 driver's four
        // such entries in a 96-byte region, ending at 84 with twelve zero bytes after.
        if off + 4 <= buf.len() && get_u32(buf, off) == 0 {
            break;
        }
        if off + ENTRY_HEADER_LEN > buf.len() {
            return Err(ParseError::TooShort {
                structure: "XattrEntry",
                need: off + ENTRY_HEADER_LEN,
                got: buf.len(),
            });
        }
        let name_len = get_u8(buf, off) as usize;
        let name_index = get_u8(buf, off + 1);
        let value_offs = get_u16(buf, off + 2) as usize;
        let value_inum = get_u32(buf, off + 4);
        let value_size = get_u32(buf, off + 8) as usize;
        let name_end = off + ENTRY_HEADER_LEN + name_len;
        let stored = buf
            .get(off + ENTRY_HEADER_LEN..name_end)
            .ok_or(ParseError::TooShort {
                structure: "XattrName",
                need: name_end,
                got: buf.len(),
            })?;
        // An attribute whose value lives in an inode of its own (`e_value_inum != 0`, the
        // `ea_inode` form) keeps no value in this region, so where it is kept is what comes
        // back, for the reader to resolve — never the unrelated bytes at
        // `value_base + e_value_offs`, which a large `e_value_size` could also carry past the
        // region.
        let value = if value_inum != 0 {
            Value::InInode {
                inode: value_inum,
                size: u32::try_from(value_size).unwrap_or(u32::MAX),
            }
        } else {
            // `value_size` is the image's own claim and spans the whole `u32` range, so
            // the end of the value is computed under a checked width: on a target whose
            // `usize` is 32 bits the sum wraps, and a wrapped end names a range inside the
            // buffer that `get` would hand back as the attribute's bytes.
            let vstart = value_base + value_offs;
            let vend = vstart
                .checked_add(value_size)
                .ok_or(ParseError::InvalidField {
                    structure: "XattrEntry",
                    field: "e_value_size",
                    value: value_size as u64,
                })?;
            value_bytes = value_bytes.saturating_add(value_size);
            if value_bytes > buf.len() {
                return Err(ParseError::InvalidField {
                    structure: "XattrEntry",
                    field: "e_value_size",
                    value: value_bytes as u64,
                });
            }
            Value::Here(
                buf.get(vstart..vend)
                    .ok_or(ParseError::InvalidField {
                        structure: "XattrEntry",
                        field: "e_value_offs",
                        value: value_offs as u64,
                    })?
                    .to_vec(),
            )
        };
        out.push(Stored {
            name: join_name(name_index, stored),
            index: name_index,
            value,
        });
        off = name_end.next_multiple_of(4);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_ending_within_a_header_of_its_region_ends_at_its_zero_word() {
        // The shape a kernel leaves in an inode body whose entries keep their values in inodes:
        // the magic, four entries naming value inodes and storing no value, and a zero word
        // with eight bytes after it — fewer than a header, more than the word.
        let mut region = vec![0u8; 96];
        put_u32(&mut region, 0, XATTR_MAGIC);
        for k in 0..4u8 {
            let at = 4 + usize::from(k) * 20;
            region[at] = 2; // e_name_len
            region[at + 1] = 1; // e_name_index: user
            put_u32(&mut region, at + 4, 24 + u32::from(k)); // e_value_inum
            put_u32(&mut region, at + 8, 2000); // e_value_size
            region[at + 16..at + 18].copy_from_slice(&[b'm', b'1' + k]);
        }
        let stored = parse_inline_stored(&region).expect("the list ends at its zero word");
        assert_eq!(stored.len(), 4);
        assert_eq!(
            stored[3].value,
            Value::InInode {
                inode: 27,
                size: 2000
            }
        );
    }

    /// Deliberately out of order, to prove the encoding canonicalizes.
    fn sample_acl() -> Acl {
        Acl::new(vec![
            AclEntry {
                who: AclQualifier::Other,
                perm: Acl::READ,
            },
            AclEntry {
                who: AclQualifier::User(1000),
                perm: Acl::READ | Acl::WRITE,
            },
            AclEntry {
                who: AclQualifier::UserObj,
                perm: Acl::READ | Acl::WRITE | Acl::EXEC,
            },
            AclEntry {
                who: AclQualifier::Mask,
                perm: Acl::READ | Acl::WRITE | Acl::EXEC,
            },
            AclEntry {
                who: AclQualifier::GroupObj,
                perm: Acl::READ | Acl::EXEC,
            },
        ])
        .expect("valid ACL")
    }

    #[test]
    fn an_acl_encodes_to_the_exact_ext4_byte_form() {
        // Hand-computed from the ext4 on-disk format: version 1, then entries in
        // canonical order with named users carrying their id.
        let expected: Vec<u8> = vec![
            0x01, 0x00, 0x00, 0x00, // a_version = 1
            0x01, 0x00, 0x07, 0x00, // USER_OBJ rwx (short)
            0x02, 0x00, 0x06, 0x00, 0xe8, 0x03, 0x00, 0x00, // USER 1000 rw- (long)
            0x04, 0x00, 0x05, 0x00, // GROUP_OBJ r-x (short)
            0x10, 0x00, 0x07, 0x00, // MASK rwx (short)
            0x20, 0x00, 0x04, 0x00, // OTHER r-- (short)
        ];
        assert_eq!(encode_acl(&sample_acl()), expected);
    }

    #[test]
    fn an_acl_round_trips_through_the_stored_form() {
        let acl = sample_acl();
        assert_eq!(decode_acl(&encode_acl(&acl)).unwrap(), acl);
    }

    #[test]
    fn the_stored_form_rejects_a_bad_version_and_truncation() {
        assert!(matches!(
            decode_acl(&[0x02, 0, 0, 0]),
            Err(AclError::Malformed { .. })
        ));
        assert!(matches!(
            decode_acl(&[0x01]),
            Err(AclError::Malformed { .. })
        ));
    }

    #[test]
    fn the_stored_form_and_the_boundary_form_do_not_cross_silently() {
        // Each parser reads the other's version number and refuses, so a value that took
        // the wrong path is a malformed ACL rather than an ACL granting the wrong access.
        let acl = sample_acl();
        assert!(matches!(
            decode_acl(&acl.encode()),
            Err(AclError::Malformed { .. })
        ));
        assert!(matches!(
            Acl::decode(&encode_acl(&acl)),
            Err(AclError::Malformed { .. })
        ));
    }

    fn attrs() -> Vec<Xattr> {
        vec![
            Xattr {
                name: b"security.capability".to_vec(),
                value: vec![0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00],
            },
            Xattr {
                name: b"user.comment".to_vec(),
                value: b"hello".to_vec(),
            },
        ]
    }

    #[test]
    fn name_index_split_and_join_round_trip() {
        for name in [
            &b"security.capability"[..],
            b"user.comment",
            b"system.posix_acl_access",
            b"system.posix_acl_default",
            b"trusted.overlay.opaque",
            b"btrfs.something", // no known prefix -> index 0
        ] {
            let (index, stored) = split_name(name);
            assert_eq!(
                join_name(index, stored),
                name,
                "{name:?} did not round-trip"
            );
        }
        assert_eq!(split_name(b"security.capability").0, 6);
        assert_eq!(split_name(b"system.posix_acl_access"), (2, &b""[..]));
        assert_eq!(split_name(b"nope").0, 0);
    }

    #[test]
    fn inline_round_trips() {
        let region_len = 96; // a 256-byte inode with i_extra_isize = 32
        let region = encode_inline(&attrs(), region_len).expect("fits inline");
        assert_eq!(region.len(), region_len);
        assert_eq!(get_u32(&region, 0), XATTR_MAGIC);
        let back = parse_inline(&region).unwrap();
        // Order is normalized on encode; compare as sets.
        assert_eq!(back.len(), 2);
        for a in attrs() {
            assert!(back.contains(&a), "missing {a:?}");
        }
    }

    #[test]
    fn inline_returns_none_when_it_does_not_fit() {
        let big = vec![Xattr {
            name: b"user.big".to_vec(),
            value: vec![0x55; 200],
        }];
        assert!(encode_inline(&big, 96).is_none());
        // An empty set always fits and yields a zeroed region.
        assert_eq!(encode_inline(&[], 96), Some(vec![0u8; 96]));
    }

    #[test]
    fn an_empty_value_records_offset_zero() {
        // `mke2fs` writes `e_value_offs = 0` for a zero-length value, not the value
        // cursor's position. `e_value_offs` sits two bytes into the entry header, and the
        // sole entry begins right after the region header.
        let attrs = vec![Xattr {
            name: b"user.empty".to_vec(),
            value: Vec::new(),
        }];

        let block = encode_block(&attrs, 4096);
        assert_eq!(
            get_u16(&block, BLOCK_HEADER_LEN + 2),
            0,
            "block: an empty value records offset 0"
        );
        assert_eq!(parse_block(&block).unwrap(), attrs, "block round-trips");

        let region = encode_inline(&attrs, 96).expect("fits inline");
        assert_eq!(
            get_u16(&region, IBODY_HEADER_LEN + 2),
            0,
            "inline: an empty value records offset 0"
        );
        assert_eq!(parse_inline(&region).unwrap(), attrs, "inline round-trips");
    }

    #[test]
    fn block_round_trips_with_a_stable_nonzero_hash() {
        let block = encode_block(&attrs(), 4096);
        assert_eq!(get_u32(&block, 0), XATTR_MAGIC);
        assert_eq!(get_u32(&block, 4), 1, "refcount");
        assert_eq!(get_u32(&block, 8), 1, "blocks");
        let h = get_u32(&block, 12);
        assert_ne!(h, 0, "block hash is set");
        // Deterministic: the same input hashes the same.
        assert_eq!(get_u32(&encode_block(&attrs(), 4096), 12), h);
        let back = parse_block(&block).unwrap();
        assert_eq!(back.len(), 2);
        for a in attrs() {
            assert!(back.contains(&a), "missing {a:?}");
        }
    }

    #[test]
    fn empty_value_and_empty_name_hash_to_defined_values() {
        // An empty name and value fold to zero (no bytes, no words).
        assert_eq!(hash_entry(b"", b""), 0);
        // A value shorter than a word is zero-padded, not skipped.
        assert_ne!(hash_entry(b"x", b"a"), hash_entry(b"x", b""));
    }

    #[test]
    fn an_entry_hash_is_the_one_mke2fs_and_a_kernel_record() {
        // `e_hash` read out of attribute blocks the pinned `mke2fs -d` wrote (the user
        // namespace, so the stored name is what follows `user.`), on x86_64 and on a
        // filesystem flagged for signed directory hashes, and out of one a Linux 7.1 kernel
        // wrote (`trusted.big`).
        let pattern: Vec<u8> = (0..3000u32).map(|i| ((i * 131 + 7) % 251) as u8).collect();
        let observed: [(&[u8], Vec<u8>, u32); 7] = [
            (b"alpha", vec![b'A'; 500], 0x8c20_4766),
            (b"beta", (0..512u32).map(|i| i as u8).collect(), 0x0030_9ae1),
            (b"d", vec![b'q'; 301], 0x7171_7164),
            (b"plain", vec![b'P'; 200], 0x0737_894e),
            (b"gam\xe9", vec![b'Z'; 400], 0x0032_0949),
            (b"\xff\x80x", vec![b'W'; 300], 0xbb2f_5754),
            (b"big", pattern, 0x937c_311d),
        ];
        for (name, value, hash) in observed {
            assert_eq!(hash_entry(name, &value), hash, "{name:?}");
        }
    }

    #[test]
    fn a_block_hash_folds_its_entries_and_is_zero_beside_a_zero() {
        // One entry: the kernel's block records its entry's hash (observed).
        assert_eq!(block_hash(&[0x937c_311d]), 0x937c_311d);
        assert_eq!(
            block_hash(&[1, 2]),
            0x0001_0002,
            "the first rotates past the second"
        );
        assert_eq!(block_hash(&[1, 0, 2]), 0);
        assert_eq!(block_hash(&[]), 0);
    }

    #[test]
    fn the_split_places_first_fit_in_canonical_order() {
        // Region 96 leaves 88 free bytes past the magic and the terminator. The big
        // value cannot fit them, but the smaller attribute after it still can: the
        // split is first-fit, not a prefix cut at the first spill.
        let attrs = vec![
            Xattr {
                name: b"user.big".to_vec(),
                value: vec![0x55; 200],
            },
            Xattr {
                name: b"user.tiny".to_vec(),
                value: vec![0x66; 4],
            },
        ];
        let (inline, spilled) = split_for_storage(&attrs, 96);
        assert_eq!(inline.len(), 1);
        assert_eq!(inline[0].name, b"user.tiny");
        assert_eq!(spilled.len(), 1);
        assert_eq!(spilled[0].name, b"user.big");
        // An empty set splits into two empty sides.
        let (inline, spilled) = split_for_storage(&[], 96);
        assert!(inline.is_empty() && spilled.is_empty());
    }

    #[test]
    fn the_split_capacity_counts_the_magic_and_the_terminator() {
        // A 96-byte region holds 88 bytes of entries and values: 4 for the magic, 4
        // for the terminating zero entry. `user.x` stores a one-byte name, so its
        // entry record pads to 20 bytes, leaving exactly 68 for a value.
        let attr = |len| {
            vec![Xattr {
                name: b"user.x".to_vec(),
                value: vec![0x77; len],
            }]
        };
        let exact = split_for_storage(&attr(68), 96);
        assert!(exact.1.is_empty(), "an exact fill stays inline");
        // The split and the encoder must agree on the arithmetic.
        assert!(encode_inline(&exact.0, 96).is_some());
        let over = split_for_storage(&attr(69), 96);
        assert!(over.0.is_empty(), "one value byte more spills");
        assert_eq!(over.1.len(), 1);
    }

    #[test]
    fn parse_ignores_a_region_without_magic() {
        assert!(parse_inline(&[0u8; 96]).unwrap().is_empty());
        assert!(parse_block(&[0u8; 4096]).unwrap().is_empty());
    }

    #[test]
    fn an_external_value_inode_entry_is_where_its_value_is_kept_not_garbage() {
        // An `ea_inode` attribute keeps its value in an inode of its own: e_value_inum is
        // non-zero and e_value_size can be large. The parse hands back that inode and size,
        // with the name preserved — never the unrelated bytes at e_value_offs, and never a
        // parse failure from a declared size larger than the region.
        let mut block = vec![0u8; 4096];
        put_u32(&mut block, 0, XATTR_MAGIC);
        let off = BLOCK_HEADER_LEN;
        block[off] = 4; // e_name_len: "test"
        block[off + 1] = 1; // e_name_index: user
        put_u16(&mut block, off + 2, 0); // e_value_offs
        put_u32(&mut block, off + 4, 42); // e_value_inum: value lives in inode 42
        put_u32(&mut block, off + 8, 1_000_000); // e_value_size: larger than the block
        block[off + ENTRY_HEADER_LEN..off + ENTRY_HEADER_LEN + 4].copy_from_slice(b"test");

        let stored = parse_block_stored(&block).expect("an ea_inode entry does not fail the parse");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].name, b"user.test");
        assert_eq!(
            stored[0].value,
            Value::InInode {
                inode: 42,
                size: 1_000_000
            },
            "the external value is where it is kept, not inline bytes"
        );
    }

    #[test]
    fn a_value_size_that_spans_the_address_space_is_refused() {
        // `e_value_size` is the image's own claim and spans the whole `u32` range, so the
        // end of a value is computed under a checked width. The value it names is refused
        // either way; which field is at fault depends on how wide `usize` is, and the
        // refusal does not.
        let mut block = vec![0u8; 4096];
        put_u32(&mut block, 0, XATTR_MAGIC);
        let off = BLOCK_HEADER_LEN;
        block[off] = 4; // e_name_len: "test"
        block[off + 1] = 1; // e_name_index: user
        put_u16(&mut block, off + 2, 64); // e_value_offs: inside the block
        put_u32(&mut block, off + 4, 0); // e_value_inum: the value is meant to be here
        put_u32(&mut block, off + 8, u32::MAX); // e_value_size
        block[off + ENTRY_HEADER_LEN..off + ENTRY_HEADER_LEN + 4].copy_from_slice(b"test");

        // The size alone is what is impossible: it is larger than the region that holds it,
        // whatever offset it starts at, and the running total refuses it before a byte is
        // copied. On a 32-bit `usize` the checked sum refuses it one step earlier, where a
        // wrapping add would otherwise name a range the block does contain — the same field
        // either way, so the refusal does not depend on how wide a pointer is.
        let err = parse_block(&block).expect_err("a value larger than the block is refused");
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    structure: "XattrEntry",
                    field: "e_value_size",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn the_values_one_region_yields_cannot_outweigh_the_region() {
        // Each entry's bounds are exact in isolation, and nothing bounded their sum. An
        // entry costs sixteen bytes on disk and may claim the whole region as its value, so
        // a 4 KiB block held 254 entries each copying 4 KiB, and a 64 KiB one — a legal
        // `s_log_block_size` — copied 268 megabytes. A scan re-parses the region once per
        // in-use inode that names it, which turns that into a hang rather than a spike.
        //
        // The values a region really holds fit in the region, so that is the bound, and no
        // well-formed set can reach it.
        let mut block = vec![0u8; 4096];
        put_u32(&mut block, 0, XATTR_MAGIC);
        // Nameless entries, sixteen bytes each, every one claiming the whole block.
        let mut off = BLOCK_HEADER_LEN;
        for _ in 0..8 {
            block[off] = 0; // e_name_len
            block[off + 1] = 1; // e_name_index, so the header is not the end marker
            put_u16(&mut block, off + 2, 0); // e_value_offs
            put_u32(&mut block, off + 4, 0); // e_value_inum: the value is here
            put_u32(&mut block, off + 8, 4096); // e_value_size: the whole block
            off += ENTRY_HEADER_LEN;
        }
        let err = parse_block(&block).expect_err("the sum outgrows the region");
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    structure: "XattrEntry",
                    field: "e_value_size",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn empty_stored_name_attributes_round_trip() {
        // system.posix_acl_access and _default map to name indices 2 and 3 with an
        // empty stored name, so their entry header has a zero name length. That must
        // not be mistaken for the end-of-list marker, which is an all-zero header.
        let attrs = vec![
            Xattr {
                name: b"system.posix_acl_access".to_vec(),
                value: vec![0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x00],
            },
            Xattr {
                name: b"security.selinux".to_vec(),
                value: b"unconfined_u:object_r:etc_t:s0\0".to_vec(),
            },
        ];
        let region = encode_inline(&attrs, 96).expect("fits inline");
        let back = parse_inline(&region).unwrap();
        assert_eq!(
            back.len(),
            2,
            "the empty-named ACL entry is not the terminator"
        );
        assert!(back.contains(&attrs[0]));
        assert!(back.contains(&attrs[1]));
        // Same through the block form.
        let block = encode_block(&attrs, 4096);
        let back = parse_block(&block).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.contains(&attrs[0]));
    }
}
