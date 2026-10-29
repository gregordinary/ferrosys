//! A volume's records: what its file-system and extent-reference trees hold, from its
//! [`model`](super::model) and the blocks each of its streams was given.
//!
//! Every field is one of three things. A value the source states (a name, an owner, a time, an
//! attribute). A value the model or the placement decided (an identifier, a count, a block).
//! Or a constant every record of its kind macOS 14 to 27 wrote carries, in every `hdiutil` and
//! `newfs_apfs` image measured. The constants are named where they are written.
//!
//! This module is pure: it builds records and does no I/O.

use std::collections::HashMap;

use crate::bytes::put_u64;

use super::btree::compare_records;
use super::bulk::Record;
use super::model::{ApfsModel, Inode, InodeKind, ModelXattr, Stream, nanos_of};
use super::names;
use super::ondisk::{
    BlockRange, DataStream, EntryKey, EntryValue, ExtendedField, FileExtent, INTERNAL_COMPRESSED,
    INTERNAL_WITH_RESOURCE_FORK, INTERNAL_WITH_SECURITY_ATTRIBUTE, INTERNAL_WITHOUT_RESOURCE_FORK,
    InodeValue, KeyHeader, PhysicalExtent, RESOURCE_FORK_XATTR, SECURITY_XATTR, SYMLINK_XATTR,
    SiblingLink, XattrValue, extended_field_blob, inode_field, inode_number, record_kind,
    sibling_map_record, xattr_flags, xattr_key,
};

/// The write counter of an inode written once: what `newfs_apfs` gives the two directories a
/// volume is made with.
pub(crate) const INODE_WRITE_GENERATION: u32 = 1;

/// The protection class of an inode of `kind`: 4 for a pipe, a socket and a device node, and 0
/// for a directory, a file and a symbolic link. macOS gives every node of the first three kinds
/// it makes the first (500 of 500 in the corpus, macOS 14 to 27), and the second to the rest.
pub(crate) const fn protection_class(kind: &InodeKind) -> u32 {
    match kind {
        InodeKind::Fifo | InodeKind::Socket | InodeKind::Device { .. } => 4,
        InodeKind::Directory(_) | InodeKind::File { .. } | InodeKind::Symlink(_) => 0,
    }
}

/// The flags of an inode's name field, on every inode macOS wrote.
pub(crate) const NAME_FIELD_FLAGS: u8 = 0x2;

/// The flags of an inode's data-stream field, on every one macOS wrote.
const DATA_STREAM_FIELD_FLAGS: u8 = 0x20;

/// The flags of a device node's number field, on every one macOS wrote.
const DEVICE_FIELD_FLAGS: u8 = 0x22;

/// The flags of a directory entry's sibling-identifier field, on every one macOS wrote.
const SIBLING_FIELD_FLAGS: u8 = 0x2;

/// The kind a physical extent of a run and its count records, on every one macOS wrote.
const RUN_AND_COUNT: u8 = 1;

/// The `DT_*` type of a directory.
pub(crate) const DT_DIR: u16 = 4;

/// The private directory's identifier, name and mode, as `newfs_apfs` makes it, owned by user
/// and group 0.
const PRIVATE_NAME: &[u8] = b"private-dir";
const PRIVATE_MODE: u16 = 0o040_644;

/// A volume's records, each tree's in the order it is built in.
pub(crate) struct VolumeRecords {
    /// The file-system tree's four records a volume is made with, in the order `newfs_apfs`
    /// inserts them: the root directory's entry and inode, then the private directory's.
    pub(crate) made: Vec<Record>,
    /// The file-system tree's other records, in key order.
    pub(crate) rest: Vec<Record>,
    /// The extent-reference tree's records, in key order.
    pub(crate) extents: Vec<Record>,
    /// Blocks every stream takes together.
    pub(crate) stream_blocks: u64,
}

impl VolumeRecords {
    /// Every file-system record, in key order.
    pub(crate) fn sorted(&self) -> Vec<Record> {
        let mut all: Vec<Record> = self.made.iter().chain(&self.rest).cloned().collect();
        sort(&mut all);
        all
    }
}

/// The records of the volume `model` describes, its streams in the blocks `runs` gives each by
/// its identifier, every block `block_size` bytes, on a volume whose names `fold` case or keep
/// it; `time` is the instant, in nanoseconds since 1970, the private directory records and every
/// directory entry records as when it was added.
pub(crate) fn volume_records(
    model: &ApfsModel,
    runs: &HashMap<u64, Vec<BlockRange>>,
    block_size: u32,
    fold: bool,
    time: i64,
) -> VolumeRecords {
    let bs = u64::from(block_size);
    let allocated = |stream: u64| -> u64 {
        runs.get(&stream)
            .map_or(0, |runs| runs.iter().map(|run| run.count).sum::<u64>())
            * bs
    };
    let streams: HashMap<u64, &Stream> = model.streams.iter().map(|s| (s.id, s)).collect();

    // The two directories every volume is made with, under the root's parent.
    let hash = |name: &[u8]| {
        names::hash(&names::key(name, fold).expect("a directory the volume makes is UTF-8"))
    };
    let made = vec![
        entry_record(
            inode_number::ROOT_PARENT,
            b"root",
            hash(b"root"),
            inode_number::ROOT,
            DT_DIR,
            None,
            time,
        ),
        inode_record(&model.root, &streams, &allocated, time),
        entry_record(
            inode_number::ROOT_PARENT,
            PRIVATE_NAME,
            hash(PRIVATE_NAME),
            inode_number::PRIVATE,
            DT_DIR,
            None,
            time,
        ),
        private_directory(time),
    ];

    let mut rest = Vec::new();
    for inode in std::iter::once(&model.root).chain(&model.inodes) {
        if inode.id != inode_number::ROOT {
            rest.push(inode_record(inode, &streams, &allocated, time));
        }
        for xattr in &inode.xattrs {
            rest.push(xattr_record(inode.id, xattr, &streams, &allocated));
        }
        match &inode.kind {
            InodeKind::Symlink(target) => {
                let mut stored = target.clone();
                stored.push(0);
                rest.push((
                    xattr_key(inode.id, SYMLINK_XATTR),
                    XattrValue {
                        flags: xattr_flags::EMBEDDED | xattr_flags::FILESYSTEM_OWNED,
                        data: &stored,
                    }
                    .to_value(),
                ));
            }
            InodeKind::File {
                stream: Some(stream),
                ..
            } => {
                rest.push((
                    KeyHeader {
                        id: *stream,
                        kind: record_kind::DATA_STREAM_ID,
                    }
                    .key(&[]),
                    1u32.to_le_bytes().to_vec(),
                ));
            }
            InodeKind::Directory(children) => {
                for child in children {
                    rest.push(entry_record(
                        inode.id,
                        &child.name,
                        child.hash,
                        child.inode,
                        child.entry_type,
                        child.sibling,
                        time,
                    ));
                }
            }
            _ => {}
        }
        for sibling in &inode.siblings {
            rest.push(
                SiblingLink {
                    sibling_id: sibling.id,
                    parent_id: sibling.parent,
                    name: &sibling.name,
                }
                .to_record(inode.id),
            );
            rest.push(sibling_map_record(sibling.id, inode.id));
        }
    }

    // Every stream's extents, and the extent-reference tree's record of each run.
    let mut extents = Vec::new();
    let mut stream_blocks = 0;
    for stream in &model.streams {
        let mut logical = 0;
        for run in runs.get(&stream.id).map_or(&[][..], Vec::as_slice) {
            rest.push(
                FileExtent {
                    logical,
                    length: run.count * bs,
                    flags: 0,
                    physical_block: run.start,
                    crypto_id: 0,
                }
                .to_record(stream.id),
            );
            extents.push(
                PhysicalExtent {
                    start: run.start,
                    blocks: run.count,
                    kind: RUN_AND_COUNT,
                    owner: stream.owner,
                    references: 1,
                }
                .to_record(),
            );
            logical += run.count * bs;
            stream_blocks += run.count;
        }
    }
    sort(&mut rest);
    sort(&mut extents);
    VolumeRecords {
        made,
        rest,
        extents,
        stream_blocks,
    }
}

/// Sort records by their keys, as a tree holds them.
fn sort(records: &mut [Record]) {
    records.sort_by(|a, b| {
        compare_records(&a.0, &b.0)
            .expect("a record this writer made parses")
            .expect("two records this writer made are ordered")
    });
}

/// The private directory: `newfs_apfs`'s, unchanged by what the volume holds.
fn private_directory(time: i64) -> Record {
    let mut value = vec![0u8; InodeValue::SIZE];
    InodeValue {
        parent_id: inode_number::ROOT_PARENT,
        private_id: inode_number::PRIVATE,
        create_time: time,
        modify_time: time,
        change_time: time,
        access_time: time,
        internal_flags: INTERNAL_WITHOUT_RESOURCE_FORK,
        links_or_children: 0,
        protection_class: 0,
        write_generation: INODE_WRITE_GENERATION,
        bsd_flags: 0,
        owner: 0,
        group: 0,
        mode: PRIVATE_MODE,
        pad: 0,
        uncompressed_size: 0,
    }
    .write_to(&mut value);
    let mut name = PRIVATE_NAME.to_vec();
    name.push(0);
    value.extend_from_slice(&extended_field_blob(&[ExtendedField {
        kind: inode_field::NAME,
        flags: NAME_FIELD_FLAGS,
        data: &name,
    }]));
    (inode_key(inode_number::PRIVATE), value)
}

/// An inode's key.
fn inode_key(id: u64) -> Vec<u8> {
    KeyHeader {
        id,
        kind: record_kind::INODE,
    }
    .key(&[])
}

/// When an inode written at `time` was created, for a source stating no birth time, given its
/// modification time: the modification time where it is not before 1970 and not after `time`,
/// and `time` otherwise.
///
/// macOS 15, 26 and 27 answer a `stat` of an inode created
/// before 1970 with `EBADMSG` (407 of 407 inodes sent, every release), and no inode of the 455,694
/// in the images on hand was created before 1970, though twelve were modified before it. `hdiutil
/// create -srcfolder` gives each inode it copies the time of the copy, pulled back to its
/// modification time where that is earlier and not before 1970, which this is with the format's
/// instant for the copy's.
pub(crate) const fn birth_time(mtime: i64, time: i64) -> i64 {
    if 0 <= mtime && mtime <= time {
        mtime
    } else {
        time
    }
}

/// The record of `inode`, written at `time`: its fields, then its name and, where it has them,
/// its data stream and its device number as extended fields, in that order.
fn inode_record(
    inode: &Inode,
    streams: &HashMap<u64, &Stream>,
    allocated: &dyn Fn(u64) -> u64,
    time: i64,
) -> Record {
    let meta = &inode.meta;
    let nanos = |t| nanos_of(t).expect("the model holds every time to the field");
    let mtime = nanos(meta.mtime);
    let links = match &inode.kind {
        InodeKind::Directory(children) => children.len(),
        _ => inode.links as usize,
    };
    // An inode holding a resource fork says so in place of saying it holds none, and a
    // compressed file says that too, as does one holding the security attribute.
    let fork = if inode
        .xattrs
        .iter()
        .any(|x| matches!(x, ModelXattr::Stream { name, .. } if name == RESOURCE_FORK_XATTR))
    {
        INTERNAL_WITH_RESOURCE_FORK
    } else {
        INTERNAL_WITHOUT_RESOURCE_FORK
    };
    let security = inode.xattrs.iter().any(|x| match x {
        ModelXattr::Embedded { name, .. } | ModelXattr::Stream { name, .. } => {
            name == SECURITY_XATTR
        }
    });
    let mut internal_flags = fork;
    if inode.compressed {
        internal_flags |= INTERNAL_COMPRESSED;
    }
    if security {
        internal_flags |= INTERNAL_WITH_SECURITY_ATTRIBUTE;
    }
    let uncompressed_size = match &inode.kind {
        InodeKind::File { size, .. } if inode.compressed => *size,
        _ => 0,
    };
    let mut value = vec![0u8; InodeValue::SIZE];
    InodeValue {
        parent_id: inode.parent,
        private_id: inode.id,
        create_time: meta.btime.map_or_else(|| birth_time(mtime, time), nanos),
        modify_time: mtime,
        change_time: nanos(meta.ctime),
        access_time: nanos(meta.atime),
        internal_flags,
        // A count of names the source holds in memory, each an entry of its own, so 2^31 of
        // them is past what any process holds.
        links_or_children: i32::try_from(links).expect("fewer than 2^31 names in memory"),
        protection_class: protection_class(&inode.kind),
        write_generation: INODE_WRITE_GENERATION,
        bsd_flags: inode.bsd_flags,
        owner: meta.uid,
        group: meta.gid,
        mode: inode.kind.mode_bits() | meta.mode,
        pad: 0,
        uncompressed_size,
    }
    .write_to(&mut value);

    let mut name = inode.name.clone();
    name.push(0);
    let mut stream_field = [0u8; DataStream::SIZE];
    let device_field = match &inode.kind {
        InodeKind::Device { number, .. } => number.to_le_bytes(),
        _ => [0; 4],
    };
    let mut fields = vec![ExtendedField {
        kind: inode_field::NAME,
        flags: NAME_FIELD_FLAGS,
        data: &name,
    }];
    match &inode.kind {
        InodeKind::File {
            size,
            stream: Some(stream),
        } => {
            debug_assert!(streams.contains_key(stream));
            DataStream {
                size: *size,
                allocated: allocated(*stream),
                crypto_id: 0,
                bytes_written: *size,
                bytes_read: 0,
            }
            .write_to(&mut stream_field);
            fields.push(ExtendedField {
                kind: inode_field::DATA_STREAM,
                flags: DATA_STREAM_FIELD_FLAGS,
                data: &stream_field,
            });
        }
        InodeKind::Device { .. } => {
            fields.push(ExtendedField {
                kind: inode_field::DEVICE,
                flags: DEVICE_FIELD_FLAGS,
                data: &device_field,
            });
        }
        _ => {}
    }
    value.extend_from_slice(&extended_field_blob(&fields));
    (inode_key(inode.id), value)
}

/// The record of attribute `xattr` of inode `id`: its value in the record, or its stream's
/// identifier and size.
fn xattr_record(
    id: u64,
    xattr: &ModelXattr,
    streams: &HashMap<u64, &Stream>,
    allocated: &dyn Fn(u64) -> u64,
) -> Record {
    match xattr {
        ModelXattr::Embedded { name, value, flags } => (
            xattr_key(id, name),
            XattrValue {
                flags: *flags,
                data: value,
            }
            .to_value(),
        ),
        ModelXattr::Stream {
            name,
            stream,
            flags,
        } => {
            let held = streams[stream];
            let mut data = vec![0u8; XattrValue::STREAM_SIZE];
            put_u64(&mut data, 0, *stream);
            DataStream {
                size: held.len,
                allocated: allocated(*stream),
                crypto_id: 0,
                bytes_written: held.written,
                bytes_read: 0,
            }
            .write_to(&mut data[8..]);
            (
                xattr_key(id, name),
                XattrValue {
                    flags: *flags,
                    data: &data,
                }
                .to_value(),
            )
        }
    }
}

/// The entry of directory `parent` naming inode `file` as `name`, keyed by `hash`, the hash of
/// the name's form under the volume's kind of name.
fn entry_record(
    parent: u64,
    name: &[u8],
    hash: u32,
    file: u64,
    entry_type: u16,
    sibling: Option<u64>,
    time: i64,
) -> Record {
    let key = EntryKey { hash, name }.to_key(parent);
    let mut value = vec![0u8; EntryValue::SIZE];
    EntryValue {
        file_id: file,
        date_added: time,
        flags: entry_type,
    }
    .write_to(&mut value);
    if let Some(sibling) = sibling {
        let id = sibling.to_le_bytes();
        value.extend_from_slice(&extended_field_blob(&[ExtendedField {
            kind: super::ondisk::SIBLING_ID_FIELD,
            flags: SIBLING_FIELD_FLAGS,
            data: &id,
        }]));
    }
    (key, value)
}
