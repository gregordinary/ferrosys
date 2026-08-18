//! The depth-first walk every family's reader is driven by.
//!
//! Walking a filesystem tree is the same algorithm whatever the format: seed a frontier from
//! the root's children, pop a name, descend into it the first time its directory is reached,
//! push its children in reverse order so they pop in order, and yield each name once. What
//! differs between the families is three things and no more — what sits on the frontier, what
//! identifies a directory for the cycle check, and how a name's children are read — and
//! [`Walk`] is exactly those three.
//!
//! # The bounds are the reason this is one function
//!
//! A walk reads a tree it has no reason to trust, and three separate properties of the input
//! could make it run without end or without bound:
//!
//! - **A cycle.** Nothing in a directory entry says it does not point back up the tree, and a
//!   crafted image can say a directory is its own ancestor. Descending into a directory only
//!   the first time its identity is reached terminates that.
//! - **The frontier.** Each iteration may push a whole directory's worth of children, and
//!   distinct directories may map the same storage — so bounding only the names *popped*
//!   would leave the stack bounded by the cap times a directory's fan-out rather than by the
//!   cap. Every name pushed is a name this walk must yield, so a frontier already past what
//!   is left of the cap is a walk past it, reported before the memory is spent.
//! - **Depth.** An explicit stack rather than recursion, so a tree nested arbitrarily deep is
//!   walked without a call-stack bound.
//!
//! Each of those is a bound a reader has to get exactly right, and none of them is visible in
//! what a walk *returns* — a walk missing one is a walk that works on every sound filesystem
//! and runs without end on a crafted one. So they are stated here, once, and a family
//! supplies only what it genuinely decides.

use std::collections::HashSet;
use std::hash::Hash;

use crate::policy::MAX_PATH;

/// What a depth-first walk needs of a filesystem's reader.
pub(crate) trait Walk {
    /// What sits on the frontier: the least a family needs to visit a name later.
    ///
    /// A family that can re-read a node cheaply keeps a locator here rather than the node
    /// itself, since the frontier holds every name reached and not yet visited.
    type Pending;

    /// What a visitor is handed: the resolved name.
    type Entry;

    /// What identifies a directory for the cycle check — an inode number, a first cluster.
    type Key: Eq + Hash;

    /// The family's own failure.
    type Error;

    /// The most names this walk may yield: the caller's bound and the filesystem's own
    /// storage ceiling, whichever is lower.
    fn cap(&mut self) -> usize;

    /// The frontier the root's children make, and the keys already occupied — the root's
    /// own, so a tree that points back at it does not descend twice.
    ///
    /// The root has no name, so a walk seeds from its children rather than from it.
    fn seed(&mut self) -> Result<Seed<Self>, Self::Error>;

    /// Resolve a frontier element into the entry a visitor receives.
    fn resolve(&mut self, pending: Self::Pending) -> Result<Self::Entry, Self::Error>;

    /// The key to descend under, or `None` for an entry that is not a directory with
    /// storage to descend into.
    fn descend_key(&self, entry: &Self::Entry) -> Option<Self::Key>;

    /// The names below `entry`, in reverse name order so a stack pops them in order.
    fn children(&mut self, entry: &Self::Entry) -> Result<Vec<Self::Pending>, Self::Error>;

    /// The failure this family reports for a walk past `limit` names.
    fn too_large(limit: usize) -> Self::Error;
}

/// What a walk starts from: the root's children, and the keys already occupied.
pub(crate) type Seed<W> = (Vec<<W as Walk>::Pending>, Vec<<W as Walk>::Key>);

/// Walk every name below the root, calling `visit` for each in depth-first order with a
/// parent before its children and siblings in name order.
///
/// The visitor is handed the reader back, so it can stat, read, and resolve while the walk is
/// in progress and nothing has to be gathered up front. Its error type is its own, and the
/// walk's failures convert into it — so a consumer's own failure and the filesystem's each
/// reach the caller as themselves.
///
/// # Errors
///
/// Whatever `visit` returns, and the family's own errors converted into it.
pub(crate) fn drive<W, E>(
    walk: &mut W,
    mut visit: impl FnMut(&mut W, W::Entry) -> Result<(), E>,
) -> Result<(), E>
where
    W: Walk,
    E: From<W::Error>,
{
    let cap = walk.cap();
    let mut seen = 0usize;

    // Track the directories descended into: a well-formed tree reaches each exactly once, so
    // declining to re-descend a repeat bounds the walk against a cycle or a hard-linked
    // directory rather than fanning out.
    let mut visited: HashSet<W::Key> = HashSet::new();
    let (mut stack, seeded) = walk.seed().map_err(E::from)?;
    visited.extend(seeded);

    // The root's own children are the first frontier, and answer to the bound below like
    // every later one.
    if stack.len() > cap {
        return Err(E::from(W::too_large(cap)));
    }

    while let Some(pending) = stack.pop() {
        if seen >= cap {
            return Err(E::from(W::too_large(cap)));
        }
        seen += 1;
        let entry = walk.resolve(pending).map_err(E::from)?;
        // Descend into a subdirectory only the first time its identity is reached; a repeat
        // is a cycle or a second name for one directory, so re-descending would not
        // terminate.
        if walk
            .descend_key(&entry)
            .is_some_and(|key| visited.insert(key))
        {
            let children = walk.children(&entry).map_err(E::from)?;
            // The cap bounds the names *pushed*, not only the names popped — see the module
            // documentation for why the difference matters.
            if seen
                .saturating_add(stack.len())
                .saturating_add(children.len())
                > cap
            {
                return Err(E::from(W::too_large(cap)));
            }
            stack.extend(children);
        }
        visit(walk, entry)?;
    }
    Ok(())
}

/// The absolute path `name` has below `prefix`, or `None` where it would exceed
/// [`MAX_PATH`].
///
/// Every path a walk builds goes through here, so the bound holds for every family and the
/// separator is placed one way. The refusal is `None` rather than an error because the error
/// is the family's; each maps it to its own.
pub(crate) fn child_path(prefix: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let mut path = Vec::with_capacity(prefix.len() + 1 + name.len());
    path.extend_from_slice(prefix);
    path.push(b'/');
    path.extend_from_slice(name);
    (path.len() <= MAX_PATH).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::child_path;
    use crate::policy::MAX_PATH;

    #[test]
    fn a_child_path_joins_with_one_separator_and_stops_at_the_bound() {
        assert_eq!(child_path(b"", b"etc").as_deref(), Some(&b"/etc"[..]));
        assert_eq!(
            child_path(b"/etc", b"hostname").as_deref(),
            Some(&b"/etc/hostname"[..])
        );
        // The bound is on the whole path, and it is inclusive: a path exactly at the limit is
        // one a walk yields.
        let deep = vec![b'a'; MAX_PATH - 1];
        assert_eq!(child_path(b"", &deep).map(|p| p.len()), Some(MAX_PATH));
        assert_eq!(child_path(b"", &vec![b'a'; MAX_PATH]), None);
    }
}
