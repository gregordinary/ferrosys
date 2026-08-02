//! `ferrosys` — pure-Rust, userspace filesystem tooling.
//!
//! The crate creates and reads filesystem images entirely in userspace, over ordinary byte
//! streams, in self-contained, safe Rust. On-disk types serialize through explicit
//! little-endian byte accessors, so the byte layout is spelled out at every field.
//!
//! # Structure
//!
//! The crate root holds the family-agnostic substrate — the vocabulary a detector and a
//! scan speak, independent of which family answers them:
//!
//! - [`detect`] reads an image and reports the [`Filesystem`] family it holds, and
//!   [`detect_with`] does the same at an offset within the source, for a partition or a
//!   region a carver located; [`DetectError`] tells an unreadable source from an
//!   unrecognized one.
//! - [`crc32c`] is the reflected CRC-32C primitive filesystem metadata checksums are
//!   built from.
#![cfg_attr(
    feature = "ext",
    doc = "\n The [`ext`] module implements the ext2/ext3/ext4 family — the \
[`format`](ext::format) writer, the [`Reader`](ext::Reader) opened over any `Read + Seek` \
source, the [`TreeBuilder`](ext::TreeBuilder) source, and the byte-exact on-disk \
structures — and is on by default. Its images are byte-reproducible: the UUID, hash seed, \
and timestamps are inputs, never read from the clock or a random source."
)]
//!
//! # Features
//!
//! `ext` is on by default and is the whole filesystem surface. Three more are off by
//! default, so a build that wants none of them depends only on `thiserror`:
//!
//! - **`tar`** adds the tar/PAX archive source and sink: a filesystem built from an
//!   archive, and one written back out as one. It depends on `tar`.
//! - **`dir`** adds the host-directory source: a filesystem built by walking a tree on
//!   this machine, with its modes, ownership, times, hard links, special files, and
//!   extended attributes. It depends on `rustix` for the two extended-attribute calls the
//!   standard library has no equivalent of, and is present on Linux.
//! - **`serde`** adds `Serialize` to the scan taxonomy, the planned geometry, and the
//!   feature model, for embedding them in a document of your own. It depends on `serde`.
// The crate is safe by construction: on-disk types serialize through explicit
// little-endian byte accessors, never transmutes or `zerocopy`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The crate's README, compiled as a doctest so the example on its front page is the
/// example this crate's API actually accepts. The item exists only while rustdoc is
/// collecting doctests, so it is neither part of the crate nor part of its documentation.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;

// ── Generic substrate: the crate root ──
//
// Present regardless of which family backends are enabled. The root exposes only what a
// detector or a scan produces independent of the family that answers it.

// The reflected CRC-32C primitive. The module is pure and has no family dependencies.
mod crc32c;
pub use crc32c::crc32c;

// Image detection and the family selector it returns. `Filesystem` and `DetectError` are
// always present; `detect` dispatches across whichever families are compiled in.
mod detect;
pub use detect::{DetectError, DetectOptions, Filesystem, detect, detect_with};

// ── The ext family: the `ext` module, behind the default-on `ext` feature ──
//
// The family's modules live at the crate root as private modules — so their cross-module
// paths stay `crate::` — and are presented to callers only through [`ext`]. The feature
// model, the checksum seam, and the scan taxonomy are ext concepts: they are reached
// through `ext`, not the crate root.
#[cfg(feature = "ext")]
mod acl;
#[cfg(feature = "ext")]
mod alloc;
#[cfg(all(feature = "ext", feature = "tar"))]
mod archive;
#[cfg(feature = "ext")]
mod csum;
#[cfg(feature = "ext")]
mod dir;
#[cfg(feature = "ext")]
mod extent;
#[cfg(feature = "ext")]
mod feature;
#[cfg(feature = "ext")]
mod fit;
#[cfg(feature = "ext")]
mod geometry;
#[cfg(feature = "ext")]
mod hash;
#[cfg(all(feature = "dir", any(target_os = "linux", target_os = "android")))]
mod host;
#[cfg(feature = "ext")]
mod identity;
#[cfg(feature = "ext")]
mod journal;
#[cfg(feature = "ext")]
mod materialize;
#[cfg(feature = "ext")]
mod model;
#[cfg(feature = "ext")]
mod ondisk;
#[cfg(feature = "ext")]
mod read;
#[cfg(feature = "ext")]
mod sealed;
#[cfg(feature = "ext")]
mod source;

#[cfg(feature = "ext")]
pub mod ext;
