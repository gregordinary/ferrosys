//! Resolving and describing a path in an exFAT volume.
//!
//! An exFAT directory entry set holds a name, five attribute bits, three times, and two
//! lengths. There is no field for an owner, a group, permission bits, a symbolic link, a
//! second name for a file, a device number, or an extended attribute — so everything a report
//! says about ownership and modes was filled in from `--assume-owner` and `--assume-modes`,
//! and the library's own `stat` names every property that happened to.
//!
//! The three fields the shared description makes optional are all absent here, for the same
//! reasons they are absent from the FAT body: there are no inode numbers, no node has a second
//! name, and the format records no block count for a file — only how much it is allocated and
//! how much of that was written.
//!
//! # What this family reports that its neighbour cannot
//!
//! A size here is the declared length, and the format records a second one beside it: how much
//! of the allocation was actually written. The two differ on a file a driver extended without
//! writing the extension, and a read yields zeros between them. The declared length is what a
//! listing shows, because it is what every driver reports and what a copy of the file produces.

use std::fs::File;
use std::io::Write;

use ferrosys::exfat::{Node, Reader};
use ferrosys::{FsTree, NodeKind, Synthesis};

use crate::extract::{Describe, Described};
use crate::{Error, from_exfat_read};

/// The exFAT family, as the extraction's per-family questions reach it.
pub struct Family;

impl Describe<Reader<File>> for Family {
    fn one(
        &self,
        reader: &mut Reader<File>,
        path: &[u8],
        synthesis: &Synthesis,
    ) -> Result<Described, Error> {
        // As on the FAT side, there is no `lookup_no_follow` and none is wanted: the format
        // has no symbolic link, so a path resolves to exactly one node and there is nothing to
        // follow. What a lookup *does* have here is a fold — the volume's own up-case table —
        // so a path in any case reaches the entry a driver reading the same volume would.
        let node = reader.lookup(path).map_err(from_exfat_read)?;
        describe(reader, path.to_vec(), node, synthesis)
    }

    fn all(
        &self,
        reader: &mut Reader<File>,
        synthesis: &Synthesis,
        _xattrs: bool,
    ) -> Result<Vec<Described>, Error> {
        // An exFAT volume carries no extended attributes at all, so gathering them costs
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
        let node = reader.lookup(path).map_err(from_exfat_read)?;
        if node.is_dir() {
            return Err(Error::NotAFile(path.to_vec()));
        }
        reader.read_data_to(&node, out).map_err(from_exfat_read)?;
        Ok(())
    }
}

/// One node as the shared description carries it.
///
/// The metadata comes from the library's own `stat` rather than being assembled here, so what
/// a listing shows and what an extraction would write are the same values from the same place
/// — including which of them were invented.
fn describe(
    reader: &mut Reader<File>,
    path: Vec<u8>,
    node: Node,
    synthesis: &Synthesis,
) -> Result<Described, Error> {
    let attrs = FsTree::stat(reader, &node, synthesis)?;
    // The format records a creation time of its own, distinct from the modification time and
    // from the access time, and to ten milliseconds where the other two families record two
    // seconds. The root is reached through the boot sector rather than through an entry set,
    // so it has none of the three — which is what the library's `stat` reports as synthesized.
    let created = node.times.map(|t| t.create);
    Ok(Described {
        path,
        kind: Some(kind_of(&node)),
        size: node.data_length,
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
/// named pipe, and no socket, so an exFAT volume is directories and files and nothing else.
fn kind_of(node: &Node) -> NodeKind {
    if node.is_dir() {
        NodeKind::Directory
    } else {
        NodeKind::File {
            size: node.data_length,
        }
    }
}
