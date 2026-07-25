//! The inode (`struct ext4_inode`), at any of the sizes ext4 stores it in.
//!
//! An inode records one file's type and permission bits, ownership, size, link
//! count, timestamps, and the 60-byte `i_block` area that either roots an extent
//! tree or holds the classic block map.
//!
//! # The extended area, and why every field past 128 bytes is conditional
//!
//! The first [`GOOD_OLD_SIZE`] bytes are the classic inode, present on every ext2,
//! ext3, and ext4 filesystem. A filesystem whose `s_inode_size` is larger carries an
//! extended area after it, and `i_extra_isize` at offset `0x80` declares how much of
//! that area is *in use*. A field in the extended area therefore exists only when the
//! inode is both large enough to hold it and declares an extra area that reaches past
//! its end — the kernel's `EXT4_FITS_IN_INODE`, spelled here as [`Inode::fits`].
//!
//! This is not a corner case. `mke2fs` leaves the reserved inodes at
//! `i_extra_isize = 0`, so on a filesystem another tool formatted those inodes carry
//! no creation time, no sub-second timestamps, and no `i_checksum_hi` — and a reader
//! that takes those fields unconditionally recovers bytes that mean something else.
//! Whole filesystems are like this: a 128-byte inode has no extended area at all.
//!
//! Sizes, block counts, ownership, and the ACL block are held as full logical
//! values and split into the low/high halves ext4 stores. The `i_block` area is
//! kept as opaque bytes: what fills it — an inline extent tree or a classic
//! indirect map — is the mapping layer's concern, not this struct's.

use super::xattr::XATTR_MAGIC;
use super::{ParseError, get_u16, get_u32, join64, put_u16, put_u32};

/// `S_IFDIR | 0755`, the mode of the root directory.
pub const ROOT_INODE_MODE: u16 = 0o40755;

/// `EXT2_GOOD_OLD_INODE_SIZE`: the 128-byte classic inode that every ext2, ext3, and
/// ext4 filesystem carries, and the smallest `s_inode_size` any of them declares.
/// Everything past it is the extended area, and conditional — see [`Inode::fits`].
pub const GOOD_OLD_SIZE: usize = 128;

/// `EXT2_GOOD_OLD_FIRST_INO`: the first inode a file may use on a revision-0
/// filesystem, where the superblock carries no `s_first_ino` field and the count of
/// reserved inodes is fixed by the revision.
pub const GOOD_OLD_FIRST_INODE: u32 = 11;

/// The `i_extra_isize` an inode of `inode_size` carries.
///
/// A 128-byte inode ends where the extended area would begin and so declares none.
/// Every larger inode declares the 32-byte area that holds the sub-second timestamps,
/// the creation time, and `i_checksum_hi` — the value `mke2fs` writes at every inode
/// size it supports, and the one `s_want_extra_isize` advertises.
#[must_use]
pub const fn extra_isize_for(inode_size: u16) -> u16 {
    if inode_size as usize > GOOD_OLD_SIZE {
        32
    } else {
        0
    }
}

/// Inode flags (`i_flags`).
///
/// Only the flags this crate sets are named; the field is otherwise zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct InodeFlags(pub u32);

impl InodeFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// `EXT4_EXTENTS_FL` (`0x80000`): the `i_block` area roots an extent tree
    /// rather than a classic block map.
    pub const EXTENTS: Self = Self(0x0008_0000);
    /// `EXT4_HUGE_FILE_FL` (`0x40000`): `i_blocks` counts filesystem blocks rather
    /// than 512-byte sectors, for files past the sector-count limit.
    pub const HUGE_FILE: Self = Self(0x0004_0000);
    /// `EXT4_INDEX_FL` (`0x1000`): the directory is hash-indexed (htree).
    pub const INDEX: Self = Self(0x0000_1000);

    /// The raw flag word.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True when every flag in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for InodeFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// An ext4 timestamp: seconds since the Unix epoch plus a nanosecond fraction.
///
/// ext4 splits this across a 32-bit seconds field and a 32-bit "extra" field. The
/// seconds field is a *signed* 32-bit value; the extra field's low two bits are an
/// unsigned epoch that adds a multiple of `2^32` seconds on top of it, and its upper
/// 30 bits hold nanoseconds. So the on-disk seconds are
/// `(i32)field + (epoch << 32)`, spanning [`EPOCH_MIN`](Self::EPOCH_MIN) to
/// [`EPOCH_MAX`](Self::EPOCH_MAX) — from 1901 to 2446.
/// [`encode`](Timestamp::encode) and [`decode`](Timestamp::decode) perform that
/// split; it matches the kernel's `ext4_decode_extra_time` exactly, so a pre-1970 or
/// post-2038 time round-trips through the same bytes the kernel would write.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Timestamp {
    /// Seconds since the Unix epoch. Values outside
    /// [`EPOCH_MIN`](Self::EPOCH_MIN)`..=`[`EPOCH_MAX`](Self::EPOCH_MAX) cannot be
    /// represented on disk; [`is_representable`](Self::is_representable) reports which.
    pub secs: i64,
    /// Nanoseconds within the second, `0..1_000_000_000`.
    ///
    /// A timestamp built for writing holds a valid fraction, and
    /// [`is_representable`](Self::is_representable) is what confirms it before one
    /// reaches an inode. A timestamp [`decode`](Self::decode)d from an image need not:
    /// the on-disk field is thirty bits wide, so an inode this crate did not write can
    /// name a fraction larger than a second and this field carries what the inode says.
    pub nanos: u32,
}

impl Timestamp {
    /// The earliest representable time: `(i32)field` at its most negative with a zero
    /// epoch, i.e. `-2^31` seconds (1901-12-13).
    pub const EPOCH_MIN: i64 = i32::MIN as i64;

    /// The latest representable time: `(i32)field` at its most positive with the epoch
    /// at 3, i.e. `(2^31 - 1) + 3 * 2^32` seconds (2446-05-10).
    pub const EPOCH_MAX: i64 = i32::MAX as i64 + (3 << 32);

    /// One past the largest valid nanosecond fraction.
    pub const NANOS_PER_SEC: u32 = 1_000_000_000;

    /// A timestamp at `secs` seconds past the epoch with no sub-second part.
    #[must_use]
    pub const fn from_secs(secs: i64) -> Self {
        Self { secs, nanos: 0 }
    }

    /// Whether this timestamp encodes to disk without loss: its seconds lie within
    /// the on-disk range and its nanoseconds are a valid fraction. A timestamp that is
    /// not representable would have its epoch bits or nanoseconds silently truncated by
    /// [`encode`](Self::encode), so callers reject it with a typed error instead.
    #[must_use]
    pub const fn is_representable(self) -> bool {
        self.secs >= Self::EPOCH_MIN
            && self.secs <= Self::EPOCH_MAX
            && self.nanos < Self::NANOS_PER_SEC
    }

    /// Encode to the `(field, extra)` pair ext4 stores: the low 32 bits of the seconds
    /// as a signed field, and the extra word combining the epoch offset with the
    /// nanoseconds.
    ///
    /// The epoch is the number of `2^32`-second steps between the signed 32-bit field
    /// and the true seconds; for a [representable](Self::is_representable) timestamp it
    /// is 0 to 3 and encodes exactly. Outside that range the epoch and the nanoseconds
    /// are masked to their on-disk widths, so callers validate first.
    #[must_use]
    pub const fn encode(self) -> (u32, u32) {
        let field = self.secs as u32;
        // The signed 32-bit field sign-extended back to i64; the epoch carries the
        // remaining high seconds as a count of 2^32-second steps.
        let low = field as i32 as i64;
        let epoch = ((self.secs - low) >> 32) as u32;
        let extra = (epoch & 0x3) | (self.nanos << 2);
        (field, extra)
    }

    /// Decode from the stored `(field, extra)` pair: the signed seconds field plus the
    /// epoch offset, and the nanoseconds from the extra word's upper bits.
    ///
    /// This is the kernel's `ext4_decode_extra_time`, and like it, it reports what the
    /// inode holds rather than what a valid fraction would be: the extra word's upper
    /// thirty bits reach 1 073 741 823, past the 1 000 000 000 that makes a second, so a
    /// decoded [`nanos`](Self::nanos) is bounded by the field and not by the second it
    /// divides. A caller that goes on to render or re-encode a decoded timestamp checks
    /// it with [`is_representable`](Self::is_representable) first.
    #[must_use]
    pub const fn decode(field: u32, extra: u32) -> Self {
        let secs = (field as i32 as i64) + (((extra & 0x3) as i64) << 32);
        Self {
            secs,
            nanos: extra >> 2,
        }
    }
}

/// Encode a device number into the inode block words `(i_block[0], i_block[1])`.
///
/// A device whose major and minor numbers both fit in eight bits uses the compact
/// "old" form in `i_block[0]`; a wider device uses the "new" form in `i_block[1]`.
/// The unused word is left zero, which is how the kernel decides which form to read:
/// a non-zero `i_block[0]` is the old form, otherwise `i_block[1]` is the new form.
#[must_use]
pub(crate) fn encode_device(major: u32, minor: u32) -> (u32, u32) {
    if major < 256 && minor < 256 {
        ((major << 8) | minor, 0)
    } else {
        let new = (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
        (0, new)
    }
}

/// Decode a device number `(major, minor)` from the two inode block words, mirroring
/// [`encode_device`].
#[must_use]
pub(crate) fn decode_device(block0: u32, block1: u32) -> (u32, u32) {
    if block0 != 0 {
        ((block0 >> 8) & 0xff, block0 & 0xff)
    } else {
        let major = (block1 & 0x000f_ff00) >> 8;
        let minor = (block1 & 0xff) | ((block1 >> 12) & 0x000f_ff00);
        (major, minor)
    }
}

/// An inode: one file's metadata and the 60-byte area that maps its blocks.
///
/// # Constructing one
///
/// Start from [`Inode::empty`], which sizes the extra area, and assign the fields that
/// differ. A `#[non_exhaustive]` structure cannot be written as a literal from outside
/// this crate, and that is about the Rust type, not the format: the byte layout is
/// [`read_from`](Self::read_from), [`write_to`](Self::write_to), and the inode size the
/// superblock declares, and none of them changes. What the attribute buys is that this crate can widen its
/// coverage of the on-disk structure — the fields it does not yet model — without that
/// being a breaking change for everyone reading an image.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Inode {
    /// Type and permission bits (`i_mode`): the `S_IF*` type in the high nibble and
    /// the permission bits below.
    pub mode: u16,
    /// Owning user id (`i_uid` + `l_i_uid_high`).
    pub uid: u32,
    /// Owning group id (`i_gid` + `l_i_gid_high`).
    pub gid: u32,
    /// File size in bytes (`i_size_lo` + `i_size_high`). For a directory this is
    /// the number of bytes its directory blocks occupy.
    pub size: u64,
    /// Link count (`i_links_count`).
    pub links_count: u16,
    /// Blocks charged to the file (`i_blocks_lo` + `l_i_blocks_high`), in 512-byte
    /// sectors unless [`InodeFlags::HUGE_FILE`] is set.
    pub blocks: u64,
    /// Inode flags (`i_flags`).
    pub flags: InodeFlags,
    /// Access time (`i_atime` + `i_atime_extra`).
    pub atime: Timestamp,
    /// Change (status) time (`i_ctime` + `i_ctime_extra`).
    pub ctime: Timestamp,
    /// Modification time (`i_mtime` + `i_mtime_extra`).
    pub mtime: Timestamp,
    /// Creation time (`i_crtime` + `i_crtime_extra`), available in the 256-byte
    /// inode's extra area.
    pub crtime: Timestamp,
    /// Deletion time (`i_dtime`); zero for a live inode.
    pub dtime: u32,
    /// Generation number (`i_generation`); zero in the images this crate writes.
    pub generation: u32,
    /// Block holding this inode's out-of-line extended attributes (`i_file_acl` +
    /// `l_i_file_acl_high`); zero when there are none.
    pub file_acl: u64,
    /// Size of the used extra-inode area (`i_extra_isize`); 32 in the 256-byte
    /// inode.
    pub extra_isize: u16,
    /// The 60-byte block-mapping area (`i_block`): an inline extent tree when
    /// [`InodeFlags::EXTENTS`] is set, otherwise the classic direct/indirect map.
    pub block: [u8; Self::BLOCK_BYTES],
    /// crc32c of the inode (`l_i_checksum_lo` + `i_checksum_hi`), written through
    /// the checksum seam; zero while `metadata_csum` is off.
    pub checksum: u32,
    /// The inline extended-attribute region that follows the extra fields, from
    /// byte `128 + extra_isize` to the end of the inode. Empty when the inode
    /// carries no inline attributes; otherwise the full region including its magic
    /// header, as produced by the xattr encoder.
    pub inline_xattr: Vec<u8>,
}

impl Inode {
    /// Size of the `i_block` mapping area in bytes.
    pub const BLOCK_BYTES: usize = 60;
    /// Byte offset of the `i_block` area within the inode.
    pub const BLOCK_OFFSET: usize = 0x28;

    /// Byte offset of `i_extra_isize` (`__le16`), the first field past the classic inode
    /// and the declaration of how much of the extra area is in use. The field itself is
    /// present only when the inode is large enough to hold its two bytes, so an access to
    /// it is gated on `inode_size >= EXTRA_ISIZE_OFFSET + 2` rather than on
    /// [`fits`](Self::fits), whose extra-area bound would be circular for this field.
    pub const EXTRA_ISIZE_OFFSET: usize = 0x80;

    /// Byte offset of `l_i_checksum_lo`, the low half of the inode checksum. It sits
    /// inside the classic inode and so exists on every filesystem.
    pub const CHECKSUM_LO_OFFSET: usize = 0x7c;
    /// Byte offset of `i_checksum_hi`, the high half of the inode checksum. It sits in
    /// the extended area and exists only when [`fits`](Self::fits) says so.
    pub const CHECKSUM_HI_OFFSET: usize = 0x82;

    /// Whether the extended field at `off` spanning `width` bytes exists in an inode of
    /// `inode_size` whose extra area declares `extra_isize` — the kernel's
    /// `EXT4_FITS_IN_INODE`.
    ///
    /// The field must lie within the inode *and* within the extra area the inode
    /// declares in use. Both bounds matter: the first is what makes a 128-byte inode
    /// carry none of these fields, the second is what makes `mke2fs`'s reserved inodes
    /// (`i_extra_isize = 0`) carry none of them either despite living in a 256-byte
    /// table.
    #[must_use]
    pub const fn fits(inode_size: u16, extra_isize: u16, off: usize, width: usize) -> bool {
        let end = off + width;
        end <= inode_size as usize && end <= GOOD_OLD_SIZE + extra_isize as usize
    }

    /// Whether this inode carries `i_checksum_hi`, the high half of its checksum.
    ///
    /// When it does not, the stored checksum is the low sixteen bits alone, and a
    /// verifier must narrow its computed value to match — which is what
    /// `ext4_inode_csum_verify` does with `calculated &= 0xFFFF`. Comparing a full
    /// 32-bit value against a stored half rejects a healthy inode.
    #[must_use]
    pub const fn has_checksum_hi(inode_size: u16, extra_isize: u16) -> bool {
        Self::fits(inode_size, extra_isize, Self::CHECKSUM_HI_OFFSET, 2)
    }

    /// An empty inode with the extra area an inode of `inode_size` carries: all fields
    /// zero, the block area cleared. Reserved inodes that hold nothing (bad-blocks, the
    /// unused reserved range) serialize from this.
    ///
    /// The 128-byte inode ends where the extended area would begin, so it declares no
    /// extra area; every larger inode declares the 32-byte one that carries the
    /// creation time and the sub-second timestamps.
    #[must_use]
    pub fn empty(inode_size: u16) -> Self {
        Self {
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 0,
            blocks: 0,
            flags: InodeFlags::NONE,
            atime: Timestamp::default(),
            ctime: Timestamp::default(),
            mtime: Timestamp::default(),
            crtime: Timestamp::default(),
            dtime: 0,
            generation: 0,
            file_acl: 0,
            extra_isize: extra_isize_for(inode_size),
            block: [0u8; Self::BLOCK_BYTES],
            checksum: 0,
            inline_xattr: Vec::new(),
        }
    }

    /// The bytes of the inline extended-attribute region an inode of `inode_size` with
    /// this inode's extra area has room for: what is left after the classic inode and
    /// the extra area. Zero when the inode ends at or before the region would start,
    /// which is every 128-byte inode.
    #[must_use]
    pub fn inline_xattr_capacity(&self, inode_size: u16) -> usize {
        (inode_size as usize).saturating_sub(GOOD_OLD_SIZE + self.extra_isize as usize)
    }

    /// [`Self::inline_xattr_capacity`] for an inode this crate creates at
    /// `inode_size`, whose extra area is always [`extra_isize_for`] that size. Lets a
    /// caller reason about inline room before any inode exists.
    #[must_use]
    pub fn inline_xattr_capacity_for(inode_size: u16) -> usize {
        (inode_size as usize).saturating_sub(GOOD_OLD_SIZE + extra_isize_for(inode_size) as usize)
    }

    /// Serialize into the first `inode_size` bytes of `buf`, which are cleared first.
    ///
    /// Every field in the extended area is written only when this inode
    /// [carries](Self::fits) it, so a 128-byte inode receives the classic fields alone
    /// and an inode declaring no extra area receives no creation time, no sub-second
    /// timestamps, and no `i_checksum_hi`. Those are the same conditions the kernel
    /// writes under, so the bytes match what it would have produced.
    ///
    /// # Errors
    ///
    /// [`ParseError::InvalidField`] if `inode_size` is below [`GOOD_OLD_SIZE`];
    /// [`ParseError::TooShort`] if `buf` cannot hold `inode_size` bytes.
    pub fn write_to(&self, buf: &mut [u8], inode_size: u16) -> Result<(), ParseError> {
        let size = check_inode_size(inode_size, buf.len())?;
        let b = &mut buf[..size];
        b.fill(0);

        let (atime, atime_x) = self.atime.encode();
        let (ctime, ctime_x) = self.ctime.encode();
        let (mtime, mtime_x) = self.mtime.encode();
        let (crtime, crtime_x) = self.crtime.encode();
        let fits = |off, width| Self::fits(inode_size, self.extra_isize, off, width);

        // The classic inode: present at every inode size.
        put_u16(b, 0x00, self.mode);
        put_u16(b, 0x02, self.uid as u16);
        put_u32(b, 0x04, self.size as u32);
        put_u32(b, 0x08, atime);
        put_u32(b, 0x0c, ctime);
        put_u32(b, 0x10, mtime);
        put_u32(b, 0x14, self.dtime);
        put_u16(b, 0x18, self.gid as u16);
        put_u16(b, 0x1a, self.links_count);
        put_u32(b, 0x1c, self.blocks as u32);
        put_u32(b, 0x20, self.flags.bits());
        // 0x24 i_osd1 (l_i_version) — left zero.
        b[Self::BLOCK_OFFSET..Self::BLOCK_OFFSET + Self::BLOCK_BYTES].copy_from_slice(&self.block);
        put_u32(b, 0x64, self.generation);
        put_u32(b, 0x68, self.file_acl as u32);
        put_u32(b, 0x6c, (self.size >> 32) as u32);
        // 0x70 i_obso_faddr — left zero.
        put_u16(b, 0x74, (self.blocks >> 32) as u16);
        put_u16(b, 0x76, (self.file_acl >> 32) as u16);
        put_u16(b, 0x78, (self.uid >> 16) as u16);
        put_u16(b, 0x7a, (self.gid >> 16) as u16);
        put_u16(b, Self::CHECKSUM_LO_OFFSET, self.checksum as u16);
        // 0x7e l_i_reserved — left zero.

        // The extended area. `i_extra_isize` itself is the declaration of how much of
        // it is in use, so it exists whenever the inode is large enough to hold the
        // field's own two bytes; every field after it is conditional on that declaration.
        if size >= Self::EXTRA_ISIZE_OFFSET + 2 {
            put_u16(b, Self::EXTRA_ISIZE_OFFSET, self.extra_isize);
        }
        if fits(Self::CHECKSUM_HI_OFFSET, 2) {
            put_u16(b, Self::CHECKSUM_HI_OFFSET, (self.checksum >> 16) as u16);
        }
        if fits(0x84, 4) {
            put_u32(b, 0x84, ctime_x);
        }
        if fits(0x88, 4) {
            put_u32(b, 0x88, mtime_x);
        }
        if fits(0x8c, 4) {
            put_u32(b, 0x8c, atime_x);
        }
        if fits(0x90, 4) {
            put_u32(b, 0x90, crtime);
        }
        if fits(0x94, 4) {
            put_u32(b, 0x94, crtime_x);
        }
        // 0x98 i_version_hi, 0x9c i_projid — left zero.

        // The inline xattr region begins right after the extra area, at
        // 128 + extra_isize, and runs to the end of the inode. It is zero unless the
        // inode carries inline attributes. Clamp the length, so a hand-built inode with
        // an oversized region cannot run past the inode.
        let xoff = GOOD_OLD_SIZE + self.extra_isize as usize;
        if !self.inline_xattr.is_empty() && xoff < size {
            debug_assert!(
                xoff + self.inline_xattr.len() <= size,
                "inline xattr region overflows the inode"
            );
            let n = self.inline_xattr.len().min(size - xoff);
            b[xoff..xoff + n].copy_from_slice(&self.inline_xattr[..n]);
        }
        Ok(())
    }

    /// Serialize to a fresh `inode_size`-byte buffer.
    ///
    /// # Errors
    ///
    /// As [`write_to`](Self::write_to).
    pub fn to_bytes(&self, inode_size: u16) -> Result<Vec<u8>, ParseError> {
        let mut b = vec![0u8; inode_size as usize];
        self.write_to(&mut b, inode_size)?;
        Ok(b)
    }

    /// Parse an `inode_size`-byte inode from the front of `buf`.
    ///
    /// Fields in the extended area are recovered only when this inode
    /// [carries](Self::fits) them, and default to zero otherwise: a 128-byte inode
    /// yields second-granularity timestamps and no creation time, because that is all
    /// its bytes hold. `extra_isize` is taken as declared and is not trusted to be in
    /// range — a value that overruns the inode simply leaves every conditional field
    /// absent rather than reading past it.
    ///
    /// # Errors
    ///
    /// [`ParseError::InvalidField`] if `inode_size` is below [`GOOD_OLD_SIZE`];
    /// [`ParseError::TooShort`] if `buf` is shorter than `inode_size`.
    pub fn read_from(buf: &[u8], inode_size: u16) -> Result<Self, ParseError> {
        let size = check_inode_size(inode_size, buf.len())?;
        let mut block = [0u8; Self::BLOCK_BYTES];
        block.copy_from_slice(&buf[Self::BLOCK_OFFSET..Self::BLOCK_OFFSET + Self::BLOCK_BYTES]);

        // `i_extra_isize` exists whenever the inode is large enough to hold the field's
        // own two bytes; a 128-byte inode, or one too small to fit even this field,
        // declares no extra area, so nothing after this point exists. Gating on the
        // field's own span keeps the read within `buf` for any `inode_size` a caller
        // passes, not only the power-of-two sizes a real filesystem uses.
        let extra_isize = if size >= Self::EXTRA_ISIZE_OFFSET + 2 {
            get_u16(buf, Self::EXTRA_ISIZE_OFFSET)
        } else {
            0
        };
        let fits = |off, width| Self::fits(inode_size, extra_isize, off, width);
        let extra = |off| if fits(off, 4) { get_u32(buf, off) } else { 0 };

        // The inline xattr region runs from 128 + extra_isize to the inode's end.
        // Retain it only when it carries the xattr magic; an all-zero tail is no
        // attributes, and keeping it empty makes the round trip exact. A declared
        // `extra_isize` past the inode's end yields no region at all rather than a
        // panic.
        let xoff = GOOD_OLD_SIZE + extra_isize as usize;
        let inline_xattr = match buf.get(xoff..size) {
            Some(region) if region.len() >= 4 && get_u32(region, 0) == XATTR_MAGIC => {
                region.to_vec()
            }
            _ => Vec::new(),
        };

        // The stored checksum is the low half alone unless the inode carries the high
        // one. Reconstructing a 32-bit value from an absent high half would fabricate a
        // zero and reject a healthy inode.
        let checksum = {
            let lo = u32::from(get_u16(buf, Self::CHECKSUM_LO_OFFSET));
            if Self::has_checksum_hi(inode_size, extra_isize) {
                lo | (u32::from(get_u16(buf, Self::CHECKSUM_HI_OFFSET)) << 16)
            } else {
                lo
            }
        };

        // The word at 0x6c holds the high half of a *regular file's* size. Under every
        // other file type it is `i_dir_acl` — a directory ACL pointer in ext2, reserved
        // since — so an inode type that is not a regular file takes its size from the
        // low word alone. Joining unconditionally would read a foreign directory's
        // leftover pointer as four gigabytes of size per unit, and a walk would then try
        // to map it.
        let mode = get_u16(buf, 0x00);
        let size_hi = if mode & 0o170000 == 0o100000 {
            get_u32(buf, 0x6c)
        } else {
            0
        };

        Ok(Self {
            mode,
            uid: u32::from(get_u16(buf, 0x02)) | (u32::from(get_u16(buf, 0x78)) << 16),
            gid: u32::from(get_u16(buf, 0x18)) | (u32::from(get_u16(buf, 0x7a)) << 16),
            size: join64(get_u32(buf, 0x04), size_hi),
            links_count: get_u16(buf, 0x1a),
            blocks: join64(get_u32(buf, 0x1c), u32::from(get_u16(buf, 0x74))),
            flags: InodeFlags(get_u32(buf, 0x20)),
            atime: Timestamp::decode(get_u32(buf, 0x08), extra(0x8c)),
            ctime: Timestamp::decode(get_u32(buf, 0x0c), extra(0x84)),
            mtime: Timestamp::decode(get_u32(buf, 0x10), extra(0x88)),
            crtime: Timestamp::decode(extra(0x90), extra(0x94)),
            dtime: get_u32(buf, 0x14),
            generation: get_u32(buf, 0x64),
            file_acl: join64(get_u32(buf, 0x68), u32::from(get_u16(buf, 0x76))),
            extra_isize,
            block,
            checksum,
            inline_xattr,
        })
    }
}

/// Validate an inode size and the buffer offered for it, returning the size as a
/// `usize`. Every accessor below indexes within the classic inode, so a buffer holding
/// at least `GOOD_OLD_SIZE` bytes bounds them all.
fn check_inode_size(inode_size: u16, available: usize) -> Result<usize, ParseError> {
    let size = inode_size as usize;
    if size < GOOD_OLD_SIZE {
        return Err(ParseError::InvalidField {
            structure: "Inode",
            field: "s_inode_size",
            value: u64::from(inode_size),
        });
    }
    if available < size {
        return Err(ParseError::TooShort {
            structure: "Inode",
            need: size,
            got: available,
        });
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inode size this crate writes by default, and the one the fixed vectors
    /// below are expressed at.
    const S: u16 = 256;

    fn root_like() -> Inode {
        let t = Timestamp::from_secs(1_700_000_000);
        let mut ino = Inode::empty(S);
        ino.mode = ROOT_INODE_MODE;
        ino.size = 4096;
        ino.links_count = 3;
        ino.blocks = 8;
        ino.flags = InodeFlags::EXTENTS;
        ino.atime = t;
        ino.ctime = t;
        ino.mtime = t;
        ino.crtime = t;
        ino
    }

    fn bytes(ino: &Inode, size: u16) -> Vec<u8> {
        ino.to_bytes(size).expect("serializes")
    }

    #[test]
    fn round_trips() {
        let ino = root_like();
        assert_eq!(Inode::read_from(&bytes(&ino, S), S).unwrap(), ino);
    }

    #[test]
    fn matches_ground_truth_root_fields() {
        // Root inode of the 64 MiB baseline: mode 040755, extents flag, size 4096,
        // links 3, blockcount 8, extra isize 32, ctime 0x6553f100 extra 0.
        let ino = root_like();
        let b = bytes(&ino, S);
        assert_eq!(get_u16(&b, 0x00), 0o40755);
        assert_eq!(get_u32(&b, 0x20), InodeFlags::EXTENTS.bits());
        assert_eq!(get_u32(&b, 0x04), 4096);
        assert_eq!(get_u16(&b, 0x1a), 3);
        assert_eq!(get_u32(&b, 0x1c), 8);
        assert_eq!(get_u16(&b, 0x80), 32);
        assert_eq!(get_u32(&b, 0x0c), 0x6553_f100);
        assert_eq!(get_u32(&b, 0x84), 0, "ctime_extra: nanos 0, epoch bits 0");
    }

    #[test]
    fn large_size_and_blocks_split_across_halves() {
        // The resize inode has size 4299210752 (needs the high half) and lives on a
        // classic block map (no extents flag).
        let mut ino = Inode::empty(S);
        ino.mode = 0o100600;
        ino.size = 4_299_210_752;
        ino.blocks = 80;
        ino.links_count = 1;
        let b = bytes(&ino, S);
        assert_eq!(get_u32(&b, 0x04), 0x0040_c000, "size low");
        assert_eq!(get_u32(&b, 0x6c), 1, "size high");
        assert_eq!(Inode::read_from(&b, S).unwrap(), ino);
    }

    #[test]
    fn only_a_regular_file_takes_its_size_from_both_words() {
        // The word at 0x6c is the size's high half for a regular file and `i_dir_acl`
        // for every other type. A foreign directory carrying a leftover pointer there
        // must not read as four gigabytes of size per unit — a size a walk would then
        // try to map, one entry per logical block.
        let mut b = vec![0u8; S as usize];
        put_u16(&mut b, 0x00, ROOT_INODE_MODE);
        put_u32(&mut b, 0x04, 4096);
        put_u32(&mut b, 0x6c, 1);
        assert_eq!(
            Inode::read_from(&b, S).unwrap().size,
            4096,
            "a directory's size is the low word alone"
        );

        put_u16(&mut b, 0x00, 0o120777);
        assert_eq!(
            Inode::read_from(&b, S).unwrap().size,
            4096,
            "and so is a symlink's"
        );

        // The same bytes under a regular file's mode do join: that is the one type
        // whose size spans both words.
        put_u16(&mut b, 0x00, 0o100644);
        assert_eq!(Inode::read_from(&b, S).unwrap().size, 4096 + (1 << 32));
    }

    #[test]
    fn high_uid_gid_and_blocks_round_trip() {
        let mut ino = Inode::empty(S);
        ino.uid = 0x0012_3456;
        ino.gid = 0x0065_4321;
        ino.blocks = 0x1_0000_0000;
        ino.file_acl = 0x1_0000_2000;
        assert_eq!(Inode::read_from(&bytes(&ino, S), S).unwrap(), ino);
    }

    #[test]
    fn round_trips_at_every_inode_size() {
        // The extra area exists at 256 and above; the 128-byte inode ends before it, so
        // it carries no creation time and no sub-second fraction, and a round trip
        // through its bytes is exact only for what those bytes can hold.
        for size in [128u16, 256, 512, 1024] {
            let mut ino = Inode::empty(size);
            ino.mode = ROOT_INODE_MODE;
            ino.size = 4096;
            ino.links_count = 3;
            ino.mtime = Timestamp::from_secs(1_700_000_000);
            let b = bytes(&ino, size);
            assert_eq!(
                b.len(),
                size as usize,
                "serializes exactly s_inode_size bytes"
            );
            assert_eq!(
                Inode::read_from(&b, size).unwrap(),
                ino,
                "round trip at inode_size={size}"
            );
        }
    }

    #[test]
    fn the_classic_inode_carries_no_extended_field() {
        // A 128-byte inode has no extra area: no i_extra_isize, no sub-second
        // timestamps, no creation time, no i_checksum_hi. Asking it for one is not an
        // error — the field simply is not there.
        assert_eq!(extra_isize_for(128), 0);
        assert!(!Inode::has_checksum_hi(128, 0));
        assert!(!Inode::fits(128, 0, 0x84, 4), "no ctime_extra");
        assert!(!Inode::fits(128, 0, 0x90, 4), "no crtime");

        let mut ino = Inode::empty(128);
        ino.mtime = Timestamp {
            secs: 1_700_000_000,
            nanos: 123_456_789,
        };
        ino.crtime = Timestamp::from_secs(1_700_000_000);
        let back = Inode::read_from(&bytes(&ino, 128), 128).unwrap();
        assert_eq!(back.mtime.secs, 1_700_000_000, "seconds survive");
        assert_eq!(back.mtime.nanos, 0, "the fraction has nowhere to live");
        assert_eq!(back.crtime, Timestamp::default(), "no creation time exists");
    }

    #[test]
    fn the_checksum_high_half_exists_only_when_the_extra_area_reaches_it() {
        // The kernel's EXT4_FITS_IN_INODE(raw, ei, i_checksum_hi): 0x82 + 2 <= 128 +
        // i_extra_isize, i.e. i_extra_isize >= 4. mke2fs leaves the reserved inodes at
        // zero, so on a foreign filesystem they store the low half alone.
        assert!(!Inode::has_checksum_hi(256, 0), "mke2fs's reserved inodes");
        assert!(!Inode::has_checksum_hi(256, 3));
        assert!(Inode::has_checksum_hi(256, 4), "the exact threshold");
        assert!(Inode::has_checksum_hi(256, 32), "the usual extra area");
        assert!(!Inode::has_checksum_hi(128, 32), "no extra area at all");

        // An inode declaring no extra area stores the low half, and parsing must not
        // fabricate a zero high half from the bytes that follow it.
        let mut ino = Inode::empty(256);
        ino.extra_isize = 0;
        ino.checksum = 0xdead_beef;
        let b = bytes(&ino, 256);
        assert_eq!(get_u16(&b, 0x7c), 0xbeef, "the low half is written");
        assert_eq!(get_u16(&b, 0x82), 0, "the high half is not");
        assert_eq!(
            Inode::read_from(&b, 256).unwrap().checksum,
            0x0000_beef,
            "and reads back as the low half alone"
        );
    }

    #[test]
    fn a_declared_extra_area_past_the_inode_reads_no_fields_and_does_not_panic() {
        // A hostile i_extra_isize must leave the conditional fields absent rather than
        // index past the inode.
        let mut b = vec![0u8; 256];
        put_u16(&mut b, 0x80, 0xffff);
        let ino = Inode::read_from(&b, 256).expect("parses");
        assert_eq!(ino.extra_isize, 0xffff);
        assert!(ino.inline_xattr.is_empty());
        assert_eq!(ino.crtime, Timestamp::default());
    }

    #[test]
    fn an_inode_size_below_the_classic_one_is_refused() {
        let b = vec![0u8; 256];
        assert!(matches!(
            Inode::read_from(&b, 64),
            Err(ParseError::InvalidField { field, .. }) if field == "s_inode_size"
        ));
    }

    #[test]
    fn an_odd_inode_size_short_of_the_extra_field_reads_and_writes_without_panic() {
        // `read_from`/`write_to` accept any `inode_size >= 128`, not only the power-of-two
        // sizes a real filesystem uses. A 129-byte inode reaches one byte past the classic
        // inode yet cannot hold the two-byte `i_extra_isize` at 0x80, so both directions
        // must treat it as carrying no extra area rather than indexing byte 129 of a
        // 129-byte buffer.
        for size in [129u16, 130] {
            let buf = vec![0u8; size as usize];
            let ino = Inode::read_from(&buf, size).expect("parses without panic");
            assert_eq!(ino.extra_isize, 0);
            assert!(ino.inline_xattr.is_empty());

            // Serializing into a buffer of exactly `inode_size` must not index past it.
            let mut out = vec![0u8; size as usize];
            let mut written = Inode::empty(size);
            written.extra_isize = 0;
            written
                .write_to(&mut out, size)
                .expect("serializes without panic");
            assert_eq!(out.len(), size as usize);
        }

        // At 130 bytes the field just fits (0x80..0x82), so a declaration survives the
        // round trip; the two bytes it occupies are the inode's last two.
        let mut ino = Inode::empty(130);
        ino.extra_isize = 2;
        let mut out = vec![0u8; 130];
        ino.write_to(&mut out, 130).expect("serializes");
        assert_eq!(
            get_u16(&out, 0x80),
            2,
            "i_extra_isize occupies the last two bytes"
        );
        assert_eq!(Inode::read_from(&out, 130).unwrap().extra_isize, 2);
    }

    #[test]
    fn timestamp_encodes_seconds_and_nanoseconds() {
        let t = Timestamp {
            secs: 1_700_000_000,
            nanos: 123_456_789,
        };
        let (field, extra) = t.encode();
        assert_eq!(field, 1_700_000_000);
        assert_eq!(extra & 0x3, 0, "epoch high bits");
        assert_eq!(extra >> 2, 123_456_789, "nanoseconds");
        assert_eq!(Timestamp::decode(field, extra), t);
    }

    #[test]
    fn timestamp_matches_kernel_epoch_scheme() {
        // The on-disk seconds are (i32)field + (epoch << 32), not a sign-extended
        // 34-bit integer. These vectors are the exact bytes e2fsprogs/debugfs write —
        // a self-round-trip test passes under either scheme, so it cannot catch a wrong
        // one. Confirmed against `debugfs stat`: 2038-01-19 stores as 0x80000000:1.
        for (secs, field, epoch) in [
            (-86_400i64, 0xfffe_ae80u32, 0u32), // 1969-12-31, pre-epoch, epoch 0
            (-1, 0xffff_ffff, 0),               // one second before 1970
            (2_147_483_648, 0x8000_0000, 1),    // 2038-01-19, first post-2038 second
            (4_294_967_296, 0x0000_0000, 1),    // 2106, exactly 2^32
            (1_700_000_000, 0x6553_f100, 0),    // an in-range recent time
        ] {
            let (f, e) = Timestamp::from_secs(secs).encode();
            assert_eq!(f, field, "field for secs={secs}");
            assert_eq!(e & 0x3, epoch, "epoch for secs={secs}");
            assert_eq!(
                Timestamp::decode(f, e),
                Timestamp::from_secs(secs),
                "round-trip for secs={secs}"
            );
        }
    }

    #[test]
    fn timestamp_representable_range_tracks_the_on_disk_limits() {
        assert_eq!(Timestamp::EPOCH_MIN, -(1 << 31));
        assert_eq!(Timestamp::EPOCH_MAX, (1 << 31) - 1 + (3 << 32));
        assert!(Timestamp::from_secs(0).is_representable());
        assert!(Timestamp::from_secs(Timestamp::EPOCH_MIN).is_representable());
        assert!(Timestamp::from_secs(Timestamp::EPOCH_MAX).is_representable());
        assert!(!Timestamp::from_secs(Timestamp::EPOCH_MIN - 1).is_representable());
        assert!(!Timestamp::from_secs(Timestamp::EPOCH_MAX + 1).is_representable());
        // A nanosecond fraction at or past one second cannot be represented.
        assert!(
            !Timestamp {
                secs: 0,
                nanos: Timestamp::NANOS_PER_SEC
            }
            .is_representable()
        );
    }

    #[test]
    fn small_device_uses_the_old_form() {
        // /dev/null is char 1:3; both fit in a byte, so i_block[0] holds it.
        let (b0, b1) = encode_device(1, 3);
        assert_eq!(b0, (1 << 8) | 3);
        assert_eq!(b1, 0);
        assert_eq!(decode_device(b0, b1), (1, 3));
        // A block device 8:0 (/dev/sda) round-trips too.
        let (b0, b1) = encode_device(8, 0);
        assert_eq!(decode_device(b0, b1), (8, 0));
    }

    #[test]
    fn wide_device_uses_the_new_form() {
        // A minor past 255 forces the new form in i_block[1].
        let (b0, b1) = encode_device(1, 300);
        assert_eq!(b0, 0);
        assert_ne!(b1, 0);
        assert_eq!(decode_device(b0, b1), (1, 300));
        // A large major too.
        let (b0, b1) = encode_device(4095, 1_048_575);
        assert_eq!(decode_device(b0, b1), (4095, 1_048_575));
    }

    #[test]
    fn inline_xattr_region_round_trips() {
        let mut ino = root_like();
        // A minimal inline region: magic then a zero terminator, padded to 96 bytes.
        let mut region = vec![0u8; 96];
        region[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
        ino.inline_xattr = region.clone();
        let b = bytes(&ino, S);
        // The region lands at 0xa0 (128 + extra_isize of 32).
        assert_eq!(get_u32(&b, 0xa0), 0xEA02_0000);
        let back = Inode::read_from(&b, S).unwrap();
        assert_eq!(back.inline_xattr, region);
        assert_eq!(back, ino);
    }

    #[test]
    fn absent_inline_xattr_stays_empty() {
        let ino = root_like();
        let back = Inode::read_from(&bytes(&ino, S), S).unwrap();
        assert!(back.inline_xattr.is_empty());
        assert_eq!(back, ino);
    }

    #[test]
    fn the_inline_xattr_region_grows_with_the_inode() {
        // The region is what is left after the classic inode and the extra area, so it
        // scales with s_inode_size — and a 128-byte inode has none.
        let ino = root_like();
        assert_eq!(ino.inline_xattr_capacity(128), 0);
        assert_eq!(ino.inline_xattr_capacity(256), 96);
        assert_eq!(ino.inline_xattr_capacity(512), 352);
        assert_eq!(ino.inline_xattr_capacity(1024), 864);

        // A region sized for the larger inode round-trips through it.
        let mut big = Inode::empty(512);
        let mut region = vec![0u8; big.inline_xattr_capacity(512)];
        region[0..4].copy_from_slice(&XATTR_MAGIC.to_le_bytes());
        big.inline_xattr = region.clone();
        let back = Inode::read_from(&bytes(&big, 512), 512).unwrap();
        assert_eq!(back.inline_xattr, region);
    }
}
