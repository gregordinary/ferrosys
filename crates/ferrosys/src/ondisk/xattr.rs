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

/// Round `n` up to the 4-byte boundary entries and values are aligned to
/// (`EXT4_XATTR_PAD`).
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
/// The rarely used indices (5 Lustre, 9 encryption, 10 Hurd) are not listed. A name
/// this crate writes always maps to a listed prefix or to index 0 with its whole self
/// stored; a foreign attribute carrying an unlisted index reads back by its stored
/// name without the namespace prefix expanded.
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

/// Hash one attribute's name and value (`ext4_xattr_hash_entry`).
///
/// The name bytes (the stored remainder, not the namespace prefix) are folded one
/// byte at a time, then the value is folded as little-endian 32-bit words over its
/// 4-byte-padded length. This is the hash `e2fsck` recomputes for every block
/// entry, so the shifts and word count match `e2fsprogs` exactly.
///
/// `signed` selects how a name byte at or above `0x80` is folded: sign-extended, as the
/// host `char` `ext2fs_ext_attr_hash_entry` reads (signed on x86, unsigned on arm64), or
/// zero-extended. It follows the same choice the directory-name hashes take, so one
/// signedness governs every name hash in the image. The two agree for an ASCII name.
fn hash_entry(name: &[u8], value: &[u8], signed: bool) -> u32 {
    const NAME_HASH_SHIFT: u32 = 5;
    const VALUE_HASH_SHIFT: u32 = 16;
    let mut hash: u32 = 0;
    for &b in name {
        let nb = if signed { b as i8 as u32 } else { u32::from(b) };
        hash = (hash << NAME_HASH_SHIFT) ^ (hash >> (32 - NAME_HASH_SHIFT)) ^ nb;
    }
    // The value is hashed over its padded length: whole 4-byte little-endian words,
    // the final word zero-filled past the value's end.
    let words = value.len().div_ceil(4);
    for i in 0..words {
        let start = i * 4;
        let mut word = [0u8; 4];
        let end = (start + 4).min(value.len());
        word[..end - start].copy_from_slice(&value[start..end]);
        let v = u32::from_le_bytes(word);
        hash = (hash << VALUE_HASH_SHIFT) ^ (hash >> (32 - VALUE_HASH_SHIFT)) ^ v;
    }
    hash
}

/// Fold the per-entry hashes into the block hash (`ext4_xattr_rehash`). A zero
/// entry hash forces the block hash to zero, marking the block unshareable, exactly
/// as `e2fsprogs` does.
fn block_hash(entry_hashes: &[u32]) -> u32 {
    const BLOCK_HASH_SHIFT: u32 = 16;
    let mut hash: u32 = 0;
    for &e in entry_hashes {
        if e == 0 {
            return 0;
        }
        hash = (hash << BLOCK_HASH_SHIFT) ^ (hash >> (32 - BLOCK_HASH_SHIFT)) ^ e;
    }
    hash
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
///
/// `signed` selects the name-byte signedness the per-entry `e_hash` folds with, matching
/// the image's directory-name-hash choice; see [`hash_entry`].
pub(crate) fn encode_block(attrs: &[Xattr], block_size: usize, signed: bool) -> Vec<u8> {
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
        let e_hash = hash_entry(stored, &x.value, signed);
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
pub(crate) fn parse_inline(region: &[u8]) -> Result<Vec<Xattr>, ParseError> {
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
pub(crate) fn parse_block(block: &[u8]) -> Result<Vec<Xattr>, ParseError> {
    if block.len() < BLOCK_HEADER_LEN || get_u32(block, 0) != XATTR_MAGIC {
        return Ok(Vec::new());
    }
    parse_entries(block, BLOCK_HEADER_LEN, 0)
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
) -> Result<Vec<Xattr>, ParseError> {
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
        if off + ENTRY_HEADER_LEN > buf.len() {
            return Err(ParseError::TooShort {
                structure: "XattrEntry",
                need: off + ENTRY_HEADER_LEN,
                got: buf.len(),
            });
        }
        if get_u32(buf, off) == 0 {
            break; // the all-zero entry header ends the list
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
        // An attribute whose value lives in a separate inode (`e_value_inum != 0`, the
        // `ea_inode` form) keeps no value in this region. This crate never writes that
        // form and cannot resolve the external inode from these bytes, so its value reads
        // back empty rather than as the unrelated bytes at `value_base + e_value_offs`
        // (which a large `e_value_size` could also carry past the region). The name is
        // preserved either way.
        let value = if value_inum != 0 {
            Vec::new()
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
            buf.get(vstart..vend)
                .ok_or(ParseError::InvalidField {
                    structure: "XattrEntry",
                    field: "e_value_offs",
                    value: value_offs as u64,
                })?
                .to_vec()
        };
        out.push(Xattr {
            name: join_name(name_index, stored),
            value,
        });
        off = name_end.next_multiple_of(4);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let block = encode_block(&attrs, 4096, false);
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
        let block = encode_block(&attrs(), 4096, false);
        assert_eq!(get_u32(&block, 0), XATTR_MAGIC);
        assert_eq!(get_u32(&block, 4), 1, "refcount");
        assert_eq!(get_u32(&block, 8), 1, "blocks");
        let h = get_u32(&block, 12);
        assert_ne!(h, 0, "block hash is set");
        // Deterministic: the same input hashes the same.
        assert_eq!(get_u32(&encode_block(&attrs(), 4096, false), 12), h);
        let back = parse_block(&block).unwrap();
        assert_eq!(back.len(), 2);
        for a in attrs() {
            assert!(back.contains(&a), "missing {a:?}");
        }
    }

    #[test]
    fn empty_value_and_empty_name_hash_to_defined_values() {
        // An empty name and value fold to zero (no bytes, no words).
        assert_eq!(hash_entry(b"", b"", false), 0);
        // A value shorter than a word is zero-padded, not skipped.
        assert_ne!(hash_entry(b"x", b"a", false), hash_entry(b"x", b"", false));
    }

    #[test]
    fn a_name_hash_follows_the_signedness_only_for_high_bytes() {
        // The name-hash signedness follows the image's directory-hash choice. An ASCII
        // name folds the same either way; a byte at or above 0x80 sign-extends under
        // Signed, so the two diverge there, matching how `mke2fs` folds a host `char`.
        assert_eq!(
            hash_entry(b"user", b"v", true),
            hash_entry(b"user", b"v", false),
            "an ASCII name is identical under either signedness"
        );
        assert_ne!(
            hash_entry(b"\xff", b"v", true),
            hash_entry(b"\xff", b"v", false),
            "a high name byte sign-extends under Signed and diverges"
        );
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
    fn an_external_value_inode_entry_reads_an_empty_value_not_garbage() {
        // A foreign `ea_inode` attribute keeps its value in a separate inode: e_value_inum
        // is non-zero and e_value_size can be large. Its value must read back empty with
        // the name preserved — never the unrelated bytes at e_value_offs, and never a
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

        let attrs = parse_block(&block).expect("an ea_inode entry does not fail the parse");
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].name, b"user.test");
        assert!(
            attrs[0].value.is_empty(),
            "the external value is not read as inline bytes"
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
        let block = encode_block(&attrs, 4096, false);
        let back = parse_block(&block).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.contains(&attrs[0]));
    }
}
