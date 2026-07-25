//! The private supertrait that seals this crate's internal seams.
//!
//! A trait with [`Sealed`] as a supertrait can only be implemented here, because
//! `Sealed` itself is private and no outside crate can name it. That makes adding a
//! method to such a trait a compatible change rather than a breaking one — nobody
//! outside has an implementation to break.
//!
//! Sealing is applied to the seams that exist so this crate's own layers can be swapped:
//! the checksum implementation the feature set selects, and the directory layout it
//! selects. Their concrete implementations stay public, so a caller can name and inspect
//! them; what is closed is the ability to substitute another. A wrong-but-compiling
//! checksum implementation would produce an image this crate claims is checksummed and
//! no checker accepts, which is the one failure mode this project treats as worse than
//! any inconvenience.
//!
//! [`Source`](crate::source::Source) is deliberately **not** sealed: it is the crate's
//! extension point, and describing a tree to write is a thing a caller is meant to
//! implement.

/// The marker no outside crate can implement.
pub trait Sealed {}
