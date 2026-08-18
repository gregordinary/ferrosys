//! Resolving and describing a path in a btrfs filesystem.
//!
//! A btrfs inode records every property a report names, so nothing here is invented and the
//! synthesis inputs go unused: what is stored is what is reported. Two of the three fields the
//! shared description makes optional are present — an inode number and a link count — and the
//! third is the one this format states differently, since what an inode records is how many
//! bytes of the volume it occupies rather than how many blocks.
//!
//! # An inode number here is a number within a tree
//!
//! Every other family in this tool numbers its nodes once for the whole filesystem. A btrfs
//! numbers them per subvolume, so two subvolumes each have an inode 256 and they are different
//! files. What a listing shows is the number within the subvolume the node is in, which is what
//! the format's own tools show and what a `subvol=` mount would report.

use std::fs::File;
use std::io::Write;

use ferrosys::btrfs::{Node, Reader};
use ferrosys::{Attributes, FsTree, Metadata, NodeKind, Synthesis};

use crate::extract::{Describe, Described};
use crate::{Error, from_btrfs_read};

/// The btrfs family, as the extraction's per-family questions reach it.
pub struct Family;

impl Describe<Reader<File>> for Family {
    fn one(
        &self,
        reader: &mut Reader<File>,
        path: &[u8],
        _synthesis: &Synthesis,
    ) -> Result<Described, Error> {
        // Not following a link in the last component, so a listing of a path naming a link
        // describes the link rather than what it points at — which is what an extraction has to
        // write, and what every other family answering this question answers.
        let node = reader.lookup_no_follow(path).map_err(from_btrfs_read)?;
        describe(reader, path.to_vec(), node, true)
    }

    fn all(
        &self,
        reader: &mut Reader<File>,
        _synthesis: &Synthesis,
        xattrs: bool,
    ) -> Result<Vec<Described>, Error> {
        let mut out = Vec::new();
        // The walk yields the root first under the empty path, which is what a sink needs and
        // what a listing does not: a listing lists names, and the root has none.
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
        // Following, here: a path naming a link and asked for its contents means the contents
        // of what it names, which is what every reader of a path does and what the ext side of
        // this command already answers.
        let node = reader.lookup(path).map_err(from_btrfs_read)?;
        if !node.is_file() {
            return Err(Error::NotAFile(path.to_vec()));
        }
        reader.read_data_to(&node, out).map_err(from_btrfs_read)?;
        Ok(())
    }
}

/// One node as the shared description carries it.
///
/// A symbolic link's target is read here rather than left to the caller, because a link's target
/// is part of what its name means and a listing that left it out would say less than it knows.
fn describe(
    reader: &mut Reader<File>,
    path: Vec<u8>,
    node: Node,
    xattrs: bool,
) -> Result<Described, Error> {
    let attributes = if xattrs {
        reader.xattrs(&node).map_err(from_btrfs_read)?
    } else {
        Vec::new()
    };
    let target = if node.is_symlink() {
        Some(reader.link_target(&node).map_err(from_btrfs_read)?)
    } else {
        None
    };
    Ok(Described {
        path,
        kind: kind_of(&node),
        size: node.item.size,
        attrs: Attributes::read(
            Metadata {
                mode: mode_bits(node.item.mode),
                uid: node.item.uid,
                gid: node.item.gid,
                atime: node.item.atime,
                ctime: node.item.ctime,
                mtime: node.item.mtime,
            },
            attributes,
        ),
        number: Some(node.inode),
        links: Some(node.item.nlink),
        target,
        // What the inode records is a byte count rather than a block count, and the shared
        // description's field is blocks — so the number that would go here is one this format
        // does not state. Reported as absent rather than divided by a block size this filesystem
        // does not allocate in.
        blocks: None,
        created: Some(node.item.otime),
    })
}

/// The permission bits of a mode, as the shared metadata carries them.
///
/// The field is thirty-two bits wide here where a host's mode is sixteen; the type and
/// permission bits are all in the low half, so the mask is what makes the two one value.
fn mode_bits(mode: u32) -> u16 {
    (mode & 0o7777) as u16
}

/// The file-type bits of a mode, and the types they name.
const IFMT: u32 = 0o170000;
const IFDIR: u32 = 0o040000;
const IFREG: u32 = 0o100000;
const IFLNK: u32 = 0o120000;
const IFCHR: u32 = 0o020000;
const IFBLK: u32 = 0o060000;
const IFIFO: u32 = 0o010000;
const IFSOCK: u32 = 0o140000;

/// What a node is, as the shared vocabulary names it.
///
/// A device node's numbers come out of the inode's `rdev`, which is where btrfs stores them, so
/// the kind carries them rather than the caller asking a second question.
///
/// `None` for a mode naming no file type at all, which an image read leniently can carry. The
/// description is where that is said rather than refused: draining such a tree is a
/// [`TreeError::Malformed`](ferrosys::TreeError::Malformed) from the library, and describing one
/// is what tells a person why.
fn kind_of(node: &Node) -> Option<NodeKind> {
    let (major, minor) = node.item.device();
    Some(match node.item.mode & IFMT {
        IFDIR => NodeKind::Directory,
        IFREG => NodeKind::File {
            size: node.item.size,
        },
        IFLNK => NodeKind::Symlink,
        IFCHR => NodeKind::CharDevice { major, minor },
        IFBLK => NodeKind::BlockDevice { major, minor },
        IFIFO => NodeKind::Fifo,
        IFSOCK => NodeKind::Socket,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mode_wider_than_a_hosts_narrows_to_its_permission_bits() {
        // The field is thirty-two bits and a host's is sixteen, so what crosses is the low
        // twelve. A cast without the mask would carry the file-type bits into a permission
        // value and give a directory the set-user-id bit.
        assert_eq!(mode_bits(0o040_755), 0o755);
        assert_eq!(mode_bits(0o100_644), 0o644);
        assert_eq!(mode_bits(0o120_777), 0o777);
        // And the high half is not permission bits either. Every filesystem in circulation
        // carries zero there, and a reader that trusted that rather than masking would hand a
        // sink a mode out of an image that had not.
        assert_eq!(mode_bits(0xFFFF_0000 | 0o644), 0o644);
    }
}
