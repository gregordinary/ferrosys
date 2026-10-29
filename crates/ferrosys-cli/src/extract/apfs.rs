//! Resolving and describing a path in an APFS volume.
//!
//! An APFS inode records every property a report names, birth time included, so nothing here is
//! invented and the synthesis inputs go unused: what is stored is what is reported. An inode
//! number and a link count are present; a block count is not, since what an inode's data stream
//! records is how many bytes are allocated to it rather than how many blocks.

use std::fs::File;
use std::io::Write;

use ferrosys::apfs::ondisk::split_device;
use ferrosys::apfs::{Node, Reader};
use ferrosys::{Attributes, FsTree, NodeKind, Synthesis};

use crate::extract::{Describe, Described};
use crate::{Error, from_apfs_read};

/// The APFS family, as the extraction's per-family questions reach it.
pub struct Family;

impl Describe<Reader<File>> for Family {
    fn one(
        &self,
        reader: &mut Reader<File>,
        path: &[u8],
        _synthesis: &Synthesis,
    ) -> Result<Described, Error> {
        // Not following a link in the last component, so a listing of a path naming a link
        // describes the link, which is what every other family answering this question answers.
        let node = reader.lookup_no_follow(path).map_err(from_apfs_read)?;
        describe(reader, path.to_vec(), node, true)
    }

    fn all(
        &self,
        reader: &mut Reader<File>,
        _synthesis: &Synthesis,
        xattrs: bool,
    ) -> Result<Vec<Described>, Error> {
        let mut out = Vec::new();
        // The walk yields the root first under the empty path, which a listing does not list.
        reader.walk_tree::<Error, _>(|reader, entry| {
            if entry.path.is_empty() {
                return Ok(());
            }
            out.push(describe(reader, entry.path, entry.node, xattrs)?);
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
        let node = reader.lookup(path).map_err(from_apfs_read)?;
        if !node.is_file() {
            return Err(Error::NotAFile(path.to_vec()));
        }
        reader.read_data_to(&node, out).map_err(from_apfs_read)?;
        Ok(())
    }
}

/// One node as the shared description carries it.
fn describe(
    reader: &mut Reader<File>,
    path: Vec<u8>,
    node: Node,
    xattrs: bool,
) -> Result<Described, Error> {
    // A compressed file whose header could not be read has no size to describe.
    if let Some(Err(e)) = &node.compression {
        return Err(from_apfs_read(e.clone()));
    }
    let attributes = if xattrs {
        reader.xattrs(&node).map_err(from_apfs_read)?
    } else {
        Vec::new()
    };
    let target = if node.is_symlink() {
        Some(reader.link_target(&node).map_err(from_apfs_read)?)
    } else {
        None
    };
    // A directory's record holds its child count where another inode holds its link count, so
    // only a node that is not a directory has a link count to report. A negative one is no
    // count, and is reported as none rather than as another number; the scan names it.
    let links = (!node.is_dir())
        .then(|| u32::try_from(node.links()).ok())
        .flatten();
    Ok(Described {
        path,
        kind: kind_of(&node),
        size: node.size(),
        attrs: Attributes::read(node.metadata(), attributes),
        number: Some(node.inode),
        links,
        target,
        blocks: None,
        flags: (node.value.bsd_flags != 0).then_some(node.value.bsd_flags),
    })
}

/// The file-type bits of a mode, and the types they name.
const IFMT: u16 = 0o170000;
const IFDIR: u16 = 0o040000;
const IFREG: u16 = 0o100000;
const IFLNK: u16 = 0o120000;
const IFCHR: u16 = 0o020000;
const IFBLK: u16 = 0o060000;
const IFIFO: u16 = 0o010000;
const IFSOCK: u16 = 0o140000;

/// What a node is, as the shared vocabulary names it. A device node's numbers come out of the
/// device field Darwin packs them into.
///
/// `None` for a mode naming no file type at all, which an image read leniently can carry.
fn kind_of(node: &Node) -> Option<NodeKind> {
    let (major, minor) = split_device(node.device.unwrap_or(0));
    Some(match node.value.mode & IFMT {
        IFDIR => NodeKind::Directory,
        IFREG => NodeKind::File { size: node.size() },
        IFLNK => NodeKind::Symlink,
        IFCHR => NodeKind::CharDevice { major, minor },
        IFBLK => NodeKind::BlockDevice { major, minor },
        IFIFO => NodeKind::Fifo,
        IFSOCK => NodeKind::Socket,
        _ => return None,
    })
}
