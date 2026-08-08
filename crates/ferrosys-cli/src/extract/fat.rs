//! Resolving and describing a path in a FAT volume.
//!
//! A FAT directory entry holds a name, one attribute byte, three coarse times, a first
//! cluster, and a length. There is no field for an owner, a group, permission bits, a
//! symbolic link, a second name for a file, a device number, or an extended attribute — so
//! everything a report says about ownership and modes was filled in from `--assume-owner` and
//! `--assume-modes`, and the library's own `stat` names every property that happened to.
//!
//! The three fields the shared description makes optional are all absent here. There are no
//! inode numbers, so no entry carries one; no node has a second name, so nothing counts them;
//! and the format records no block count for a file, only its length and where its chain
//! begins.

use std::fs::File;
use std::io::Write;

use ferrosys::fat::{Node, Reader};
use ferrosys::{FsTree, NodeKind, Synthesis};

use crate::extract::{Describe, Described};
use crate::{Error, from_fat_read};

/// The FAT family, as the extraction's per-family questions reach it.
pub struct Family;

impl Describe<Reader<File>> for Family {
    fn one(
        &self,
        reader: &mut Reader<File>,
        path: &[u8],
        synthesis: &Synthesis,
    ) -> Result<Described, Error> {
        // There is no `lookup_no_follow` here and none is wanted: the format has no symbolic
        // link, so a path resolves to exactly one node and there is nothing to follow.
        let node = reader.lookup(path).map_err(from_fat_read)?;
        describe(reader, path.to_vec(), node, synthesis)
    }

    fn all(
        &self,
        reader: &mut Reader<File>,
        synthesis: &Synthesis,
        _xattrs: bool,
    ) -> Result<Vec<Described>, Error> {
        // A FAT volume carries no extended attributes at all, so gathering them costs
        // nothing and the flag is ignored rather than branched on.
        let mut out = Vec::new();
        // The walk yields the root first under the empty path, which is what a sink needs and
        // what a listing does not: a listing lists names, and the root has none.
        reader.walk_tree::<Error, _>(|reader, entry| {
            if entry.path.is_empty() {
                return Ok(());
            }
            out.push(describe(reader, entry.path, entry.node, synthesis)?);
            Ok(())
        })?;
        Ok(out)
    }

    fn cat(
        &self,
        reader: &mut Reader<File>,
        path: &[u8],
        out: &mut dyn Write,
    ) -> Result<(), Error> {
        let node = reader.lookup(path).map_err(from_fat_read)?;
        if node.is_dir() || node.is_volume_label() {
            return Err(Error::NotAFile(path.to_vec()));
        }
        reader.read_data_to(&node, out).map_err(from_fat_read)?;
        Ok(())
    }
}

/// One node as the shared description carries it.
///
/// The metadata comes from the library's own `stat` rather than being assembled here, so what
/// a listing shows and what an extraction would write are the same values from the same
/// place — including which of them were invented.
fn describe(
    reader: &mut Reader<File>,
    path: Vec<u8>,
    node: Node,
    synthesis: &Synthesis,
) -> Result<Described, Error> {
    let attrs = FsTree::stat(reader, &node, synthesis)?;
    // The format records a creation time of its own, distinct from the modification time and
    // from the access date. The root has no entry on any type and so has none of the three,
    // which is what the library's `stat` reports as synthesized.
    let created = node.times.map(|t| t.create);
    Ok(Described {
        path,
        kind: Some(kind_of(&node)),
        size: size_of(&node),
        attrs,
        number: None,
        links: None,
        target: None,
        blocks: None,
        created,
    })
}

/// What a node is, as the shared vocabulary names it.
///
/// Only two of the seven kinds occur: the format has no symbolic link, no device node, no
/// named pipe, and no socket, so a FAT volume is directories and files and nothing else.
fn kind_of(node: &Node) -> NodeKind {
    if node.is_dir() {
        NodeKind::Directory
    } else {
        NodeKind::File {
            size: size_of(node),
        }
    }
}

/// The length the volume records for a node.
///
/// A directory entry's length field is zero on a directory, by the format's own rule — a
/// directory's extent is however many clusters its chain holds, and the field is not where it
/// is written down. That zero is reported as it stands rather than replaced by a chain walk,
/// because a report says what the volume records, and it is the same length the library's own
/// walk carries.
fn size_of(node: &Node) -> u64 {
    if node.is_dir() {
        0
    } else {
        u64::from(node.size)
    }
}
