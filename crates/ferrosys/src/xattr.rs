//! Extended attributes as a source states them and a read hands them back: a
//! fully-qualified name and its raw value.
//!
//! [`Xattr`] is the boundary form — what `getxattr` would have returned and what `setxattr`
//! would be given — not any family's storage form. A family that packs names into indices,
//! shares a value between inodes, or has nowhere to put an attribute at all does that
//! behind this type, and the family that cannot hold one is the one that says so.

/// One extended attribute: a fully-qualified name (namespace prefix included, e.g.
/// `b"security.capability"`) and its raw value bytes.
///
/// The name carries its namespace as text. A family whose on-disk form splits a known
/// prefix into a compact index, or encodes a value differently from the boundary form,
/// does that when it stores one and undoes it when it reads one back — so an attribute
/// that makes the round trip through an image is the attribute that went in.
///
/// One value has an encoding of its own and is worth naming. A `system.posix_acl_access`
/// or `system.posix_acl_default` attribute holds the version-2 `posix_acl_xattr` bytes
/// [`Acl::encode`](crate::Acl::encode) produces, whatever the family
/// storing it packs those into.
///
/// The type is exhaustive: an attribute is a name and a value, and there is no field it
/// could grow.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Xattr {
    /// The attribute's full name, namespace prefix included.
    pub name: Vec<u8>,
    /// The attribute's raw value.
    pub value: Vec<u8>,
}

/// Whether two attribute lists state the same attributes, in whatever order.
///
/// Order-insensitive because a source states attributes in the order its producer
/// happened to write them, and a set is what an inode holds. Every model that gives one
/// inode two names asks this question when the second name repeats the first's attributes,
/// which is the two families with attributes to repeat.
#[cfg(any(feature = "ext", feature = "btrfs"))]
pub(crate) fn same_xattrs(a: &[Xattr], b: &[Xattr]) -> bool {
    fn sorted(list: &[Xattr]) -> Vec<&Xattr> {
        let mut refs: Vec<&Xattr> = list.iter().collect();
        refs.sort_by(|x, y| x.name.cmp(&y.name));
        refs
    }
    a.len() == b.len()
        && sorted(a)
            .into_iter()
            .zip(sorted(b))
            .all(|(x, y)| x.name == y.name && x.value == y.value)
}
