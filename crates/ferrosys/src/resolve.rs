//! The path resolution every family's reader answers a lookup with.
//!
//! Resolving a path is the same algorithm whatever the format: start at the filesystem's own
//! root, take the components in order, find each in the directory reached so far, expand a
//! symbolic link into the components still to come, and ascend on `..`. What differs between
//! the families is how a name is found in a directory and whether the format has links at all
//! — and [`Resolve`] is exactly that.
//!
//! # `..` is an ascent, not a name
//!
//! A path component of `..` names the directory holding the one reached so far. Two things
//! that look like answers are not:
//!
//! - **Looking up an entry called `..`.** Only ext stores one, so a rule built on it answers
//!   for one family of the four and leaves the others resolving nothing. It also takes an
//!   image's word for where its parent is, and a backpointer is a field like any other: a
//!   crafted one would send a resolution somewhere the path never named.
//! - **Refusing it.** A `..` a caller writes is ordinary, and so is one stored in a symbolic
//!   link — a distribution's `/usr/lib64` is a relative link that ascends, and a reader that
//!   refuses one cannot follow it.
//!
//! What answers for every family is the descent itself: keep what has been descended through,
//! and pop it. That crosses a btrfs subvolume boundary correctly for free, because the stack
//! holds the directories reached rather than inode numbers that mean different things in
//! different trees.
//!
//! At the root there is nothing to pop, and `..` stays where it is. **A resolution can name
//! nothing outside the filesystem it is reading**: an absolute link target restarts at this
//! image's root and never the host's, and no run of `..` climbs past it.
//!
//! # What is bounded, and by what
//!
//! - **A cycle of links.** `/a` pointing at `/b` pointing at `/a` expands without end, so a
//!   resolution spends at most [`MAX_SYMLINK_HOPS`] of them and then refuses.
//! - **The components still to come.** A link's target is pushed onto the front of them, so
//!   the queue grows as a resolution runs. It is bounded because each hop contributes at most
//!   a path's worth of components and there are at most `MAX_SYMLINK_HOPS` hops.
//! - **The descent.** One entry per component actually descended through, so it is bounded by
//!   the same count — and it holds a locator rather than a directory, which is why a crafted
//!   image whose directories nest into each other without end costs a resolution the numbers
//!   and not the inodes.
//!
//! # What this does not ask about a component
//!
//! Nothing. A component that no directory could hold as an entry — one carrying a NUL — is
//! looked up like any other and found in no directory, so it is [`not_found`](Resolve::not_found)
//! and says so. Refusing it by name here would be the same rule stated twice, since the place
//! that has to hold the line is where a directory's entries are *read*: a name a volume
//! carries reaches a path, an archive member, and a host file, and each of those is a
//! consequence of having accepted it. A path a caller writes has no such reach.

use std::collections::VecDeque;

use crate::path::canonical_parts;
use crate::policy::MAX_SYMLINK_HOPS;

/// What a path resolution needs of a filesystem's reader.
pub(crate) trait Resolve {
    /// The least a family needs to return to a directory a resolution has left.
    ///
    /// An inode number, a cluster — not the directory itself, since the descent holds one of
    /// these per component and a resolution over a crafted image may descend a long way.
    type Ancestor: Copy;

    /// What a resolution reaches, and what a lookup hands back.
    type Node;

    /// The family's own failure.
    type Error;

    /// The filesystem's own root directory, which every resolution starts at and which an
    /// absolute symbolic link target restarts at.
    fn root_node(&mut self) -> Result<Self::Node, Self::Error>;

    /// What it takes to come back to `node`.
    fn ancestor_of(&self, node: &Self::Node) -> Self::Ancestor;

    /// The node an [`Ancestor`](Self::Ancestor) names, read again on the way back up.
    fn node_at(&mut self, ancestor: Self::Ancestor) -> Result<Self::Node, Self::Error>;

    /// Whether `node` is a directory, which is the only thing a name can be looked up in.
    fn is_directory(&self, node: &Self::Node) -> bool;

    /// The node `dir` holds under `name`, or [`None`] where it holds no such name.
    ///
    /// Which byte strings count as the same name is the family's: a FAT or exFAT volume finds
    /// a name whose case differs, because that is how every driver reading one finds it.
    fn find_name(
        &mut self,
        dir: &Self::Node,
        name: &[u8],
    ) -> Result<Option<Self::Node>, Self::Error>;

    /// The target of `node` if it is a symbolic link, or [`None`] if it is not one.
    ///
    /// `path` is the whole path under resolution, for a family whose refusals name it: a
    /// target the image describes as longer than a path can be is one this reader will not
    /// allocate for, and the failure it reports is its own.
    ///
    /// This and [`too_many_links`](Self::too_many_links) are the link half of the trait, and a
    /// format that has no links takes both defaults: no node ever yields a target, so no hop
    /// is ever spent and the refusal is never reached. Overriding one alone is what the
    /// pairing is written down to prevent.
    fn read_link(
        &mut self,
        node: &Self::Node,
        path: &[u8],
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        let (_, _) = (node, path);
        Ok(None)
    }

    /// The failure this family reports where a component names nothing.
    fn not_found(&self, path: &[u8]) -> Self::Error;

    /// The failure this family reports where a component has to be looked up in `node` and
    /// `node` is not a directory.
    fn not_a_directory(&self, node: &Self::Node, path: &[u8]) -> Self::Error;

    /// The failure this family reports for a resolution past [`MAX_SYMLINK_HOPS`] links.
    ///
    /// Defaulted with [`read_link`](Self::read_link), and unreachable for a family that takes
    /// that default.
    fn too_many_links(&self, path: &[u8]) -> Self::Error {
        self.not_found(path)
    }
}

/// Resolve `path` against the filesystem's own root, component by component.
///
/// `follow_final` decides whether a symbolic link in the last component is expanded; the ones
/// before it always are, because a path cannot continue through a link without going where it
/// points. A distribution's root filesystem is what makes that obligatory rather than a
/// nicety: `/bin`, `/lib`, and `/sbin` are links into `/usr` on every current one, so a
/// resolver that stopped at a link would find nothing under any of them.
///
/// # Errors
///
/// The family's own, through the four constructors [`Resolve`] declares and whatever reading a
/// directory or a link refuses.
pub(crate) fn drive<R>(reader: &mut R, path: &[u8], follow_final: bool) -> Result<R::Node, R::Error>
where
    R: Resolve,
{
    // Owned, because a link's target is a buffer read out of the image and gone by the next
    // iteration: the queue cannot borrow the bytes it was split from.
    let mut pending: VecDeque<Vec<u8>> = canonical_parts(path)
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
    let mut node = reader.root_node()?;
    // Empty exactly when `node` is the root, which is what makes `..` at the root a no-op
    // rather than a read.
    let mut descended: Vec<R::Ancestor> = Vec::new();
    let mut hops = 0u32;

    while let Some(part) = pending.pop_front() {
        if !reader.is_directory(&node) {
            return Err(reader.not_a_directory(&node, path));
        }
        if part == b".." {
            if let Some(ancestor) = descended.pop() {
                node = reader.node_at(ancestor)?;
            }
            continue;
        }
        let Some(next) = reader.find_name(&node, &part)? else {
            return Err(reader.not_found(path));
        };

        // A link is read only where it is about to be followed, so a lookup that stops at the
        // final component does not touch what it points at.
        if let Some(target) = (follow_final || !pending.is_empty())
            .then(|| reader.read_link(&next, path))
            .transpose()?
            .flatten()
        {
            hops += 1;
            if hops > MAX_SYMLINK_HOPS {
                return Err(reader.too_many_links(path));
            }
            if target.is_empty() {
                return Err(reader.not_found(path));
            }
            // An absolute target restarts at this filesystem's root; a relative one continues
            // from the directory holding the link, which `node` still is, because the
            // resolution did not descend into the link.
            if target.starts_with(b"/") {
                descended.clear();
                node = reader.root_node()?;
            }
            for component in canonical_parts(&target).into_iter().rev() {
                pending.push_front(component.to_vec());
            }
            continue;
        }

        descended.push(reader.ancestor_of(&node));
        node = next;
    }
    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tree of named directories, files, and links, resolved by the same driver every
    /// family's reader is. It stands in for a filesystem so the rules the driver owns — the
    /// ascent, the root clamp, the hop budget, the absolute restart — are checked once,
    /// against a tree whose shape the test states rather than against an image.
    struct Tiny {
        /// One node per index: its kind, and its entries where it is a directory.
        nodes: Vec<Kind>,
    }

    #[derive(Clone)]
    enum Kind {
        Dir(Vec<(&'static [u8], usize)>),
        File,
        Link(&'static [u8]),
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Refused {
        NotFound,
        NotADirectory,
        TooManyLinks,
    }

    impl Resolve for Tiny {
        type Ancestor = usize;
        type Node = usize;
        type Error = Refused;

        fn root_node(&mut self) -> Result<usize, Refused> {
            Ok(0)
        }
        fn ancestor_of(&self, node: &usize) -> usize {
            *node
        }
        fn node_at(&mut self, ancestor: usize) -> Result<usize, Refused> {
            Ok(ancestor)
        }
        fn is_directory(&self, node: &usize) -> bool {
            matches!(self.nodes[*node], Kind::Dir(_))
        }
        fn find_name(&mut self, dir: &usize, name: &[u8]) -> Result<Option<usize>, Refused> {
            let Kind::Dir(entries) = &self.nodes[*dir] else {
                return Ok(None);
            };
            Ok(entries
                .iter()
                .find(|(entry, _)| *entry == name)
                .map(|(_, at)| *at))
        }
        fn read_link(&mut self, node: &usize, _path: &[u8]) -> Result<Option<Vec<u8>>, Refused> {
            match self.nodes[*node] {
                Kind::Link(target) => Ok(Some(target.to_vec())),
                _ => Ok(None),
            }
        }
        fn not_found(&self, _path: &[u8]) -> Refused {
            Refused::NotFound
        }
        fn not_a_directory(&self, _node: &usize, _path: &[u8]) -> Refused {
            Refused::NotADirectory
        }
        fn too_many_links(&self, _path: &[u8]) -> Refused {
            Refused::TooManyLinks
        }
    }

    /// `/usr/{bin,lib}`, `/usr/bin/lib -> ../lib`, `/bin -> usr/bin`, `/etc/hostname`, and a
    /// pair of links that point at each other.
    fn tree() -> Tiny {
        Tiny {
            nodes: vec![
                // 0: the root
                Kind::Dir(vec![
                    (b"usr", 1),
                    (b"etc", 4),
                    (b"bin", 6),
                    (b"here", 7),
                    (b"there", 8),
                ]),
                // 1: /usr
                Kind::Dir(vec![(b"bin", 2), (b"lib", 3)]),
                // 2: /usr/bin
                Kind::Dir(vec![(b"sh", 10), (b"lib", 9)]),
                // 3: /usr/lib
                Kind::Dir(vec![(b"libc.so", 11)]),
                // 4: /etc
                Kind::Dir(vec![(b"hostname", 5)]),
                // 5: /etc/hostname
                Kind::File,
                // 6: /bin
                Kind::Link(b"usr/bin"),
                // 7, 8: a cycle
                Kind::Link(b"/there"),
                Kind::Link(b"/here"),
                // 9: /usr/bin/lib, which ascends to a sibling of the directory holding it
                Kind::Link(b"../lib"),
                // 10: /usr/bin/sh
                Kind::File,
                // 11: /usr/lib/libc.so
                Kind::File,
            ],
        }
    }

    fn at(path: &[u8]) -> Result<usize, Refused> {
        drive(&mut tree(), path, true)
    }

    #[test]
    fn a_parent_component_ascends_through_what_was_descended() {
        assert_eq!(at(b"/usr/bin/../lib/libc.so"), Ok(11));
        assert_eq!(at(b"/usr/bin/.."), Ok(1));
        // Interleaved with `.`, which carries no meaning and is dropped before the driver
        // ever sees it.
        assert_eq!(at(b"/usr/./bin/./../lib"), Ok(3));
    }

    #[test]
    fn a_relative_link_that_ascends_is_one_a_resolution_follows() {
        // The case a distribution's `/usr/lib64` is: the link is found in `/usr/bin`, its
        // target ascends out of it, and the resolution continues in `/usr`.
        assert_eq!(at(b"/usr/bin/lib"), Ok(3));
        assert_eq!(at(b"/usr/bin/lib/libc.so"), Ok(11));
        // The ascent is from the directory holding the link and not from the link, which is
        // what a resolution that had descended into it would get wrong: from the link, `..`
        // would land in `/usr` and `../lib` would be `/usr/lib` by luck rather than by rule.
        assert_eq!(drive(&mut tree(), b"/usr/bin/lib", false), Ok(9));
        // The same link reached through another one, so the ascent is over an expansion
        // rather than over what the caller wrote.
        assert_eq!(at(b"/bin/lib/libc.so"), Ok(11));
    }

    #[test]
    fn nothing_outside_the_filesystem_can_be_named() {
        // At the root there is nothing to ascend to, so a run of `..` stays there rather than
        // climbing out of the image.
        for path in [&b"/.."[..], b"/../..", b"..", b"../../.."] {
            assert_eq!(at(path), Ok(0), "{}", String::from_utf8_lossy(path));
        }
        // And what follows the run resolves from the root, so an ascent that ran out is a
        // path rooted at this image rather than a refusal.
        assert_eq!(at(b"/../etc/hostname"), Ok(5));
        assert_eq!(at(b"../../../../etc/hostname"), Ok(5));
        // A run of them from below climbs exactly as far as it descended and no further.
        assert_eq!(at(b"/usr/bin/../../etc/hostname"), Ok(5));
        assert_eq!(at(b"/usr/bin/../../../../etc/hostname"), Ok(5));
    }

    #[test]
    fn a_component_below_something_that_is_not_a_directory_is_refused() {
        assert_eq!(at(b"/etc/hostname/x"), Err(Refused::NotADirectory));
        // Including an ascent: `..` is a component like any other, and a file has no parent
        // to give.
        assert_eq!(at(b"/etc/hostname/.."), Err(Refused::NotADirectory));
    }

    #[test]
    fn a_name_no_directory_holds_is_not_found_rather_than_refused_by_name() {
        assert_eq!(at(b"/etc/nothing"), Err(Refused::NotFound));
        // A component no directory could hold as an entry is looked up like any other and
        // found nowhere, which is the answer that is true of it.
        assert_eq!(at(b"/etc/host\0name"), Err(Refused::NotFound));
    }

    #[test]
    fn a_cycle_of_links_is_spent_rather_than_followed() {
        assert_eq!(at(b"/here"), Err(Refused::TooManyLinks));
    }

    #[test]
    fn a_link_in_the_middle_is_expanded_whether_or_not_the_last_one_is() {
        // `/bin` is a link, and a path continuing through it goes where it points either way.
        assert_eq!(drive(&mut tree(), b"/bin/sh", true), Ok(10));
        assert_eq!(drive(&mut tree(), b"/bin/sh", false), Ok(10));
        // The last component is where the two differ.
        assert_eq!(drive(&mut tree(), b"/bin", true), Ok(2));
        assert_eq!(drive(&mut tree(), b"/bin", false), Ok(6));
    }

    #[test]
    fn the_root_is_what_an_empty_path_names() {
        for path in [&b""[..], b"/", b"//", b"/./"] {
            assert_eq!(at(path), Ok(0), "{}", String::from_utf8_lossy(path));
        }
    }
}
