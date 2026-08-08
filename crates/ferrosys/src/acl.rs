//! POSIX.1e access control lists, and the form they take at a boundary.
//!
//! An ACL is a set of permission entries beyond the owner/group/other mode bits. It
//! travels as the value of the `system.posix_acl_access` or `system.posix_acl_default`
//! extended attribute, and the bytes that value holds are the version-2
//! `posix_acl_xattr` structure the `getxattr`/`setxattr` boundary uses: a 4-byte version
//! header (`a_version = 2`) followed by fixed 8-byte entries, each carrying an id field
//! even for the tags that identify nobody. [`Acl::encode`] produces that byte form and
//! [`Acl::decode`] parses it back.
//!
//! That is the form an [`Acl`] takes everywhere outside a filesystem — in a host tree, in
//! an archive, in a [`SourceEntry`](crate::SourceEntry) going in, and in the
//! [`Attributes`](crate::Attributes) a read hands back. How a filesystem *stores* one is
//! that family's own business, and the conversion belongs to the family's edge.
//!
//! This module is pure: it converts between an [`Acl`] value and its bytes, with no I/O.
//! A caller attaches an ACL by encoding it and adding it as the corresponding extended
//! attribute (see [`Acl::ACCESS_NAME`] and [`Acl::DEFAULT_NAME`]).

/// The version of the `posix_acl_xattr` form used at the `getxattr`/`setxattr`
/// boundary, which is what an archive carries in a binary `system.posix_acl_*`
/// attribute.
const XATTR_ACL_VERSION: u32 = 0x0002;

/// The size of one version-2 `posix_acl_xattr_entry`: tag, permissions, and an id that
/// is present even for the tags that do not use one.
const XATTR_ENTRY_LEN: usize = 8;

/// The id a version-2 entry carries in place of a real one (`ACL_UNDEFINED_ID`), for
/// the tags that identify no particular user or group.
const ACL_UNDEFINED_ID: u32 = u32::MAX;

// The tag values POSIX gives the six qualifiers (`ACL_USER_OBJ` … `ACL_OTHER`). Every
// encoding of an ACL writes these same numbers; they are shared with the encodings a
// family stores rather than restated by each.
pub(crate) const TAG_USER_OBJ: u16 = 0x01;
pub(crate) const TAG_USER: u16 = 0x02;
pub(crate) const TAG_GROUP_OBJ: u16 = 0x04;
pub(crate) const TAG_GROUP: u16 = 0x08;
pub(crate) const TAG_MASK: u16 = 0x10;
pub(crate) const TAG_OTHER: u16 = 0x20;

/// A failure encoding or decoding an ACL.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AclError {
    /// The ACL is missing a required entry: exactly one owner, owning-group, and
    /// other entry must be present.
    #[error("ACL is missing its required {tag} entry")]
    #[non_exhaustive]
    MissingRequired {
        /// The entry tag that is absent: `owner`, `owning group`, or `other`.
        tag: &'static str,
    },
    /// A required entry appears more than once, or a named user/group id repeats.
    #[error("ACL has a duplicate {tag} entry")]
    #[non_exhaustive]
    Duplicate {
        /// The entry tag that repeats.
        tag: &'static str,
    },
    /// The ACL names specific users or groups but carries no mask entry, which POSIX
    /// requires in that case.
    #[error("ACL names users or groups but has no mask entry")]
    MaskRequired,
    /// A permission field set bits outside read/write/execute.
    #[error("ACL entry has invalid permission bits {perm:#x}")]
    #[non_exhaustive]
    InvalidPerm {
        /// The permission field as found, including the bits outside `rwx`.
        perm: u16,
    },
    /// The encoded ACL was truncated or its version was not 1.
    #[error("encoded ACL is malformed: {reason}")]
    #[non_exhaustive]
    Malformed {
        /// What about the encoding is wrong.
        reason: &'static str,
    },
}

/// Who an [`AclEntry`] grants permissions to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AclQualifier {
    /// The file owner (`ACL_USER_OBJ`); mirrors the owner mode bits.
    UserObj,
    /// A named user (`ACL_USER`) identified by uid.
    User(u32),
    /// The owning group (`ACL_GROUP_OBJ`).
    GroupObj,
    /// A named group (`ACL_GROUP`) identified by gid.
    Group(u32),
    /// The mask (`ACL_MASK`) bounding the permissions of named users and groups.
    Mask,
    /// Everyone else (`ACL_OTHER`); mirrors the other mode bits.
    Other,
}

impl AclQualifier {
    /// The tag value and, for a named user or group, the id that accompanies it.
    pub(crate) fn tag_and_id(self) -> (u16, Option<u32>) {
        match self {
            AclQualifier::UserObj => (TAG_USER_OBJ, None),
            AclQualifier::User(id) => (TAG_USER, Some(id)),
            AclQualifier::GroupObj => (TAG_GROUP_OBJ, None),
            AclQualifier::Group(id) => (TAG_GROUP, Some(id)),
            AclQualifier::Mask => (TAG_MASK, None),
            AclQualifier::Other => (TAG_OTHER, None),
        }
    }

    /// The qualifier a tag names, or `None` for a tag no encoding defines.
    ///
    /// The id is read for every tag and kept only by the two that identify somebody; the
    /// rest carry a placeholder in the encodings that reserve room for one, and nothing at
    /// all in the encodings that do not.
    pub(crate) fn from_tag(tag: u16, id: u32) -> Option<Self> {
        Some(match tag {
            TAG_USER_OBJ => AclQualifier::UserObj,
            TAG_USER => AclQualifier::User(id),
            TAG_GROUP_OBJ => AclQualifier::GroupObj,
            TAG_GROUP => AclQualifier::Group(id),
            TAG_MASK => AclQualifier::Mask,
            TAG_OTHER => AclQualifier::Other,
            _ => return None,
        })
    }

    /// The sort key that puts entries in canonical POSIX order: by tag, then by id
    /// within the named-user and named-group runs.
    fn sort_key(self) -> (u16, u32) {
        let (tag, id) = self.tag_and_id();
        (tag, id.unwrap_or(0))
    }
}

/// One ACL entry: a qualifier and the read/write/execute bits it grants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AclEntry {
    /// Who the entry applies to.
    pub who: AclQualifier,
    /// Permission bits, an OR of [`Acl::READ`], [`Acl::WRITE`], and [`Acl::EXEC`].
    pub perm: u16,
}

/// A POSIX access control list: a canonically ordered, validated set of entries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Acl {
    entries: Vec<AclEntry>,
}

impl Acl {
    /// Read permission bit (`ACL_READ`).
    pub const READ: u16 = 4;
    /// Write permission bit (`ACL_WRITE`).
    pub const WRITE: u16 = 2;
    /// Execute permission bit (`ACL_EXECUTE`).
    pub const EXEC: u16 = 1;

    /// The extended-attribute name an access ACL is stored under.
    pub const ACCESS_NAME: &'static [u8] = b"system.posix_acl_access";
    /// The extended-attribute name a default ACL (inherited by new files in a
    /// directory) is stored under.
    pub const DEFAULT_NAME: &'static [u8] = b"system.posix_acl_default";

    /// Build an ACL from its entries, sorting them into canonical order and checking
    /// POSIX validity.
    ///
    /// # Errors
    ///
    /// An [`AclError`] if a required entry is missing or duplicated, a named user or
    /// group appears without a mask, or a permission field has stray bits.
    pub fn new(mut entries: Vec<AclEntry>) -> Result<Self, AclError> {
        for e in &entries {
            if e.perm & !(Self::READ | Self::WRITE | Self::EXEC) != 0 {
                return Err(AclError::InvalidPerm { perm: e.perm });
            }
        }
        entries.sort_by_key(|e| e.who.sort_key());
        Self::validate(&entries)?;
        Ok(Self { entries })
    }

    /// The ACL's entries, in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[AclEntry] {
        &self.entries
    }

    /// Check the required-entry and mask rules the kernel enforces.
    fn validate(entries: &[AclEntry]) -> Result<(), AclError> {
        let count =
            |pred: fn(&AclQualifier) -> bool| entries.iter().filter(|e| pred(&e.who)).count();
        let user_obj = count(|w| matches!(w, AclQualifier::UserObj));
        let group_obj = count(|w| matches!(w, AclQualifier::GroupObj));
        let other = count(|w| matches!(w, AclQualifier::Other));
        let mask = count(|w| matches!(w, AclQualifier::Mask));
        if user_obj == 0 {
            return Err(AclError::MissingRequired { tag: "owner" });
        }
        if group_obj == 0 {
            return Err(AclError::MissingRequired {
                tag: "owning-group",
            });
        }
        if other == 0 {
            return Err(AclError::MissingRequired { tag: "other" });
        }
        if user_obj > 1 {
            return Err(AclError::Duplicate { tag: "owner" });
        }
        if group_obj > 1 {
            return Err(AclError::Duplicate {
                tag: "owning-group",
            });
        }
        if other > 1 {
            return Err(AclError::Duplicate { tag: "other" });
        }
        if mask > 1 {
            return Err(AclError::Duplicate { tag: "mask" });
        }
        // Named users and groups must have distinct ids, and their presence requires
        // a mask entry.
        let mut named = false;
        let mut users: Vec<u32> = Vec::new();
        let mut groups: Vec<u32> = Vec::new();
        for e in entries {
            match e.who {
                AclQualifier::User(id) => {
                    named = true;
                    if users.contains(&id) {
                        return Err(AclError::Duplicate { tag: "named-user" });
                    }
                    users.push(id);
                }
                AclQualifier::Group(id) => {
                    named = true;
                    if groups.contains(&id) {
                        return Err(AclError::Duplicate { tag: "named-group" });
                    }
                    groups.push(id);
                }
                _ => {}
            }
        }
        if named && mask == 0 {
            return Err(AclError::MaskRequired);
        }
        Ok(())
    }

    /// Encode to the version-2 `posix_acl_xattr` bytes: the version header then one
    /// fixed 8-byte entry per ACL entry, each carrying an id — a real one for a named
    /// user or group, `ACL_UNDEFINED_ID` for the four tags that identify nobody in
    /// particular.
    ///
    /// This is the form the `getxattr`/`setxattr` boundary uses, and so the form an ACL
    /// takes in every value this crate carries: a `system.posix_acl_*` attribute written
    /// into an archive, handed to a tool that will `setxattr` it, or named in a
    /// [`SourceEntry`](crate::SourceEntry). A filesystem that stores some narrower
    /// encoding converts at its own edge, and a consumer given that stored form in place
    /// of this one reads the wrong version number and rejects the attribute.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.entries.len() * XATTR_ENTRY_LEN);
        out.extend_from_slice(&XATTR_ACL_VERSION.to_le_bytes());
        for e in &self.entries {
            let (tag, id) = e.who.tag_and_id();
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&e.perm.to_le_bytes());
            out.extend_from_slice(&id.unwrap_or(ACL_UNDEFINED_ID).to_le_bytes());
        }
        out
    }

    /// Parse the version-2 `posix_acl_xattr` form into an ACL, revalidating the result.
    ///
    /// This is the form `getxattr` returns and an archive stores in a binary
    /// `system.posix_acl_access` or `system.posix_acl_default` attribute: a 4-byte
    /// version header followed by fixed 8-byte entries, each carrying an id field even
    /// for the tags that do not use one.
    ///
    /// The entries are re-sorted into canonical POSIX order, so an ACL whose entries
    /// arrive out of order parses into a canonical [`Acl`] rather than being reported as
    /// malformed. The returned value reflects the ACL's meaning, not the byte order it
    /// arrived in.
    ///
    /// # Errors
    ///
    /// [`AclError::Malformed`] if the version is not 2, the bytes are truncated or stop
    /// part-way through an entry, or a tag is unknown; or a validity error from
    /// [`new`](Self::new).
    pub fn decode(bytes: &[u8]) -> Result<Self, AclError> {
        if bytes.len() < 4 {
            return Err(AclError::Malformed {
                reason: "shorter than the version header",
            });
        }
        let (header, body) = bytes.split_at(4);
        let version = u32::from_le_bytes(header.try_into().expect("split at four bytes"));
        if version != XATTR_ACL_VERSION {
            return Err(AclError::Malformed {
                reason: "unexpected version",
            });
        }
        if body.len() % XATTR_ENTRY_LEN != 0 {
            return Err(AclError::Malformed {
                reason: "truncated entry",
            });
        }
        let mut entries = Vec::with_capacity(body.len() / XATTR_ENTRY_LEN);
        for e in body.chunks_exact(XATTR_ENTRY_LEN) {
            let tag = u16::from_le_bytes([e[0], e[1]]);
            let perm = u16::from_le_bytes([e[2], e[3]]);
            // The id is meaningful only for a named user or group; the other tags carry
            // `ACL_UNDEFINED_ID` here, which the qualifier does not hold.
            let id = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
            let who = AclQualifier::from_tag(tag, id).ok_or(AclError::Malformed {
                reason: "unknown tag",
            })?;
            entries.push(AclEntry { who, perm });
        }
        Self::new(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Acl {
        // Deliberately out of order to prove canonicalization.
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
    fn a_minimal_acl_needs_no_mask() {
        let acl = Acl::new(vec![
            AclEntry {
                who: AclQualifier::UserObj,
                perm: Acl::READ | Acl::WRITE,
            },
            AclEntry {
                who: AclQualifier::GroupObj,
                perm: Acl::READ,
            },
            AclEntry {
                who: AclQualifier::Other,
                perm: Acl::READ,
            },
        ])
        .expect("minimal ACL is valid without a mask");
        // Three entries, each with an id field: 4 + 3*8 = 28 bytes.
        assert_eq!(acl.encode().len(), 28);
    }

    #[test]
    fn named_user_without_mask_is_rejected() {
        let err = Acl::new(vec![
            AclEntry {
                who: AclQualifier::UserObj,
                perm: Acl::READ | Acl::WRITE,
            },
            AclEntry {
                who: AclQualifier::User(1000),
                perm: Acl::READ,
            },
            AclEntry {
                who: AclQualifier::GroupObj,
                perm: Acl::READ,
            },
            AclEntry {
                who: AclQualifier::Other,
                perm: Acl::READ,
            },
        ])
        .unwrap_err();
        assert_eq!(err, AclError::MaskRequired);
    }

    #[test]
    fn missing_required_and_duplicate_and_bad_perm_are_rejected() {
        assert_eq!(
            Acl::new(vec![AclEntry {
                who: AclQualifier::UserObj,
                perm: Acl::READ,
            }])
            .unwrap_err(),
            AclError::MissingRequired {
                tag: "owning-group"
            }
        );
        assert_eq!(
            Acl::new(vec![AclEntry {
                who: AclQualifier::UserObj,
                perm: 0x40,
            }])
            .unwrap_err(),
            AclError::InvalidPerm { perm: 0x40 }
        );
    }

    #[test]
    fn the_version_2_xattr_form_decodes_to_the_same_acl() {
        // The bytes `getxattr` returns for the sample ACL: version 2, then fixed 8-byte
        // entries whose id field is `ACL_UNDEFINED_ID` on every tag but the named user.
        let v2: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, // a_version = 2
            0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // USER_OBJ rwx
            0x02, 0x00, 0x06, 0x00, 0xe8, 0x03, 0x00, 0x00, // USER 1000 rw-
            0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // GROUP_OBJ r-x
            0x10, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // MASK rwx
            0x20, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff, // OTHER r--
        ];
        let acl = Acl::decode(&v2).expect("valid version-2 ACL");
        assert_eq!(acl, sample());
    }

    #[test]
    fn the_version_2_xattr_form_is_encoded_exactly_as_getxattr_returns_it() {
        // The same hand-written bytes the decode test consumes: every entry eight bytes
        // wide, the four tags that identify nobody carrying ACL_UNDEFINED_ID.
        let expected: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, // a_version = 2
            0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // USER_OBJ rwx
            0x02, 0x00, 0x06, 0x00, 0xe8, 0x03, 0x00, 0x00, // USER 1000 rw-
            0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // GROUP_OBJ r-x
            0x10, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // MASK rwx
            0x20, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff, // OTHER r--
        ];
        assert_eq!(sample().encode(), expected);
    }

    #[test]
    fn an_acl_round_trips_through_the_version_2_form() {
        // The two directions are inverses, so an ACL read from a filesystem and written
        // back out to a syscall-boundary consumer is the ACL that was stored.
        let acl = sample();
        assert_eq!(Acl::decode(&acl.encode()).unwrap(), acl);
    }

    #[test]
    fn the_version_2_xattr_form_rejects_a_bad_version_and_a_partial_entry() {
        assert!(matches!(
            Acl::decode(&[0x01, 0x00, 0x00, 0x00]),
            Err(AclError::Malformed { .. })
        ));
        let mut truncated = vec![0x02, 0x00, 0x00, 0x00];
        truncated.extend_from_slice(&[0x01, 0x00, 0x07, 0x00]); // half an entry
        assert!(matches!(
            Acl::decode(&truncated),
            Err(AclError::Malformed { .. })
        ));
    }
}
