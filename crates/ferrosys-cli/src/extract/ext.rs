//! Resolving and describing a path in an ext filesystem.
//!
//! An ext inode records every property a report names, so nothing here is invented and the
//! synthesis inputs go unused: what is stored is what is reported. The three fields the
//! shared description makes optional — an inode number, a link count, and a block count —
//! are all present, because this is the family they are named after.

use std::fs::File;
use std::io::Write;

use ferrosys::ext::ondisk::Inode;
use ferrosys::ext::{Reader, WalkEntry};
use ferrosys::{Attributes, Metadata, NodeKind, Synthesis};

use crate::extract::{Describe, Described};
use crate::{Error, from_read};

/// The file-type bits of a mode, and the types they name.
const IFMT: u16 = 0o170000;
const IFDIR: u16 = 0o040000;
const IFREG: u16 = 0o100000;
const IFLNK: u16 = 0o120000;
const IFCHR: u16 = 0o020000;
const IFBLK: u16 = 0o060000;
const IFIFO: u16 = 0o010000;
const IFSOCK: u16 = 0o140000;

/// The ext family, as the extraction's per-family questions reach it.
pub struct Family;

impl Describe<Reader<File>> for Family {
    fn one(
        &self,
        reader: &mut Reader<File>,
        path: &[u8],
        _synthesis: &Synthesis,
    ) -> Result<Described, Error> {
        let (number, inode) = reader.lookup_no_follow(path).map_err(from_read)?;
        let xattrs = reader.xattrs(&inode).map_err(from_read)?;
        describe(reader, path.to_vec(), number, &inode, xattrs)
    }

    fn all(
        &self,
        reader: &mut Reader<File>,
        _synthesis: &Synthesis,
        xattrs: bool,
    ) -> Result<Vec<Described>, Error> {
        let entries: Vec<WalkEntry> = reader.walk().map_err(from_read)?;
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let attrs = if xattrs {
                reader.xattrs(&e.inode).map_err(from_read)?
            } else {
                Vec::new()
            };
            out.push(describe(reader, e.path, e.number, &e.inode, attrs)?);
        }
        Ok(out)
    }

    fn cat(
        &self,
        reader: &mut Reader<File>,
        path: &[u8],
        out: &mut dyn Write,
    ) -> Result<(), Error> {
        let (_, inode) = reader.lookup(path).map_err(from_read)?;
        if inode.mode & IFMT != IFREG {
            return Err(Error::NotAFile(path.to_vec()));
        }
        reader.read_data_to(&inode, out).map_err(from_read)?;
        Ok(())
    }
}

/// One inode as the shared description carries it.
///
/// A symbolic link's target is read here rather than left to the caller, because a link's
/// target is part of what its name means and a listing that left it out would say less than
/// it knows.
fn describe(
    reader: &mut Reader<File>,
    path: Vec<u8>,
    number: u32,
    inode: &Inode,
    xattrs: Vec<ferrosys::Xattr>,
) -> Result<Described, Error> {
    let kind = kind_of(reader, inode);
    let target = if inode.mode & IFMT == IFLNK {
        Some(reader.read_symlink(inode).map_err(from_read)?)
    } else {
        None
    };
    Ok(Described {
        path,
        kind,
        size: inode.size,
        attrs: Attributes::read(
            Metadata {
                mode: inode.mode & 0o7777,
                uid: inode.uid,
                gid: inode.gid,
                atime: inode.atime,
                ctime: inode.ctime,
                mtime: inode.mtime,
            },
            xattrs,
        ),
        number: Some(u64::from(number)),
        links: Some(u32::from(inode.links_count)),
        target,
        blocks: Some(inode.blocks),
        created: Some(inode.crtime),
    })
}

/// What an inode is, as the shared vocabulary names it.
///
/// A device node's numbers come out of the inode's block array, which is where ext stores
/// them, so the kind carries them rather than the caller asking a second question.
///
/// `None` for a mode naming no file type at all, which an image read leniently can carry.
/// The description is where that is said rather than refused: draining such a tree is a
/// [`TreeError::Malformed`](ferrosys::TreeError::Malformed) from the library, and describing
/// one is what tells a person why.
fn kind_of(reader: &Reader<File>, inode: &Inode) -> Option<NodeKind> {
    Some(match inode.mode & IFMT {
        IFDIR => NodeKind::Directory,
        IFREG => NodeKind::File { size: inode.size },
        IFLNK => NodeKind::Symlink,
        IFCHR => {
            let (major, minor) = reader.device(inode);
            NodeKind::CharDevice { major, minor }
        }
        IFBLK => {
            let (major, minor) = reader.device(inode);
            NodeKind::BlockDevice { major, minor }
        }
        IFIFO => NodeKind::Fifo,
        IFSOCK => NodeKind::Socket,
        _ => return None,
    })
}
