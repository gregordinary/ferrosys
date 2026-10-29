//! A tree this crate reads, as a [`Source`]: what one image holds, handed to a format that
//! writes another.
//!
//! [`ImageSource::read`] walks any family's reader through the extraction surface,
//! [`FsTree`], and gives every entry it reaches as the [`SourceEntry`] that would write it
//! again: its path, its kind, its ownership, mode and times, its extended attributes, and
//! from a Darwin filesystem its BSD flags and a compressed file's stored form. A second name
//! for a node is a hard link to the first name the walk met. A regular file's
//! content is an [`ImageFile`], which reads the file from the image when a format places it,
//! so what a source of a large image costs in memory is its entry records, as it is for a host
//! directory, and not the bytes of its files.
//!
//! # What was read and what was invented
//!
//! A family whose format records no owner, mode or change time fills one from the
//! [`Synthesis`] a caller hands [`read`](ImageSource::read), as its reader always does. Each
//! property filled that way is a [`Direction::Synthesized`] record of
//! [`ImageSource::fidelity`], under the entry's path, so a caller writing the tree elsewhere
//! knows which values the image never held.
//!
//! # The image must not change while the source is alive
//!
//! A file's bytes are read when it is placed, through the reader the source holds. A format
//! writing over the image the source reads is a format reading what it has already
//! overwritten.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::fidelity::{Direction, FidelityReport, Synthesis};
use crate::source::{EntryKind, FileContent, Source, SourceEntry};
use crate::tree::{FsTree, NodeKind, TreeError, made_by_the_format};

/// A regular file's bytes in an image this crate reads, read when the file is placed.
///
/// Clones share the reader they read through, and a read names its own offset, so two reads of
/// one file, or of two files of one image, never disturb each other: each holds the reader for
/// the length of its own read.
#[derive(Clone)]
pub struct ImageFile {
    reader: Arc<Mutex<dyn ReadNode>>,
    index: usize,
    len: u64,
}

/// A reader holding the nodes of the files a source names, reading one by its index.
trait ReadNode: Send {
    /// Fill `buf` from `offset` of the file at `index`, returning how many bytes were placed.
    fn read_node(&mut self, index: usize, offset: u64, buf: &mut [u8]) -> Result<usize, TreeError>;
}

/// A family's reader and the node of every file a source of it names, by index.
struct Held<T: FsTree> {
    tree: T,
    nodes: Vec<T::Node>,
}

impl<T> ReadNode for Held<T>
where
    T: FsTree + Send,
    T::Node: Send,
{
    fn read_node(&mut self, index: usize, offset: u64, buf: &mut [u8]) -> Result<usize, TreeError> {
        self.tree.read_bytes(&self.nodes[index], offset, buf)
    }
}

impl ImageFile {
    /// The file's length in bytes, as the image records it.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the file is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Fill `buf` with the file's bytes from offset `at` onward.
    ///
    /// # Errors
    ///
    /// [`std::io::ErrorKind::InvalidInput`] if `at` plus the buffer's length runs past the
    /// file's end; [`std::io::ErrorKind::UnexpectedEof`] if the image yields fewer bytes than
    /// the file's length says it holds; and otherwise the reader's own failure, as
    /// [`std::io::ErrorKind::InvalidData`] for a malformed image or the kind of the underlying
    /// i/o error.
    pub fn read_at(&self, at: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let end = at.checked_add(buf.len() as u64);
        if end.is_none_or(|end| end > self.len) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} bytes at {at} run past the end of a file of {} bytes in an image",
                    buf.len(),
                    self.len
                ),
            ));
        }
        let mut reader = self.reader.lock().unwrap_or_else(PoisonError::into_inner);
        let mut done = 0;
        while done < buf.len() {
            let n = reader
                .read_node(self.index, at + done as u64, &mut buf[done..])
                .map_err(io_error)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "a file of {} bytes in an image ends after {}",
                        self.len,
                        at + done as u64
                    ),
                ));
            }
            done += n;
        }
        Ok(())
    }
}

/// A read through the extraction surface's failure, as an i/o error a format reports.
fn io_error(e: TreeError) -> std::io::Error {
    match e {
        TreeError::Io { kind, message } => std::io::Error::new(kind, message),
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
    }
}

impl PartialEq for ImageFile {
    /// One file of one image: the same reader and the same node.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.reader, &other.reader) && self.index == other.index
    }
}

impl Eq for ImageFile {}

impl std::fmt::Debug for ImageFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageFile")
            .field("index", &self.index)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// A tree an image holds, as the entries a format writes it again from.
///
/// ```no_run
/// use ferrosys::{ImageSource, Synthesis, open};
///
/// let image = open(std::fs::File::open("root.img")?)?;
/// # let ferrosys::FsReader::Ext(reader) = image else { unreachable!() };
/// let source = ImageSource::read(reader, &Synthesis::default())?;
/// assert!(source.fidelity().is_faithful());
/// // `source` is a `Source`: hand it, or a `LayeredSource` holding it, to any format.
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct ImageSource {
    entries: Vec<SourceEntry>,
    fidelity: FidelityReport,
}

impl ImageSource {
    /// Every entry `tree` walks, as the source that would write it again: the root first,
    /// then each entry in the order the walk meets it. What the family's format makes for
    /// itself, an ext filesystem's `/lost+found`, is not among them, as no sink writes it out.
    ///
    /// A property the family's format does not record is filled from `synthesis`, as the
    /// reader's [`stat`](FsTree::stat) fills it, and recorded in
    /// [`fidelity`](Self::fidelity). A regular file's content is an [`ImageFile`] reading from
    /// `tree`, which the source keeps.
    ///
    /// # Errors
    ///
    /// The [`TreeError`] the walk, a stat, a link's target, or the reader's cap on a file's
    /// length reports.
    pub fn read<T>(tree: T, synthesis: &Synthesis) -> Result<Self, TreeError>
    where
        T: FsTree + Send + 'static,
        T::Node: Send + 'static,
    {
        let mut tree = tree;
        let mut fidelity = FidelityReport::new();
        let mut nodes: Vec<T::Node> = Vec::new();
        // Each entry, and where it is a regular file, the index and length of its content.
        let mut found: Vec<(SourceEntry, Option<(usize, u64)>)> = Vec::new();
        let mut first_name: HashMap<u64, Vec<u8>> = HashMap::new();
        tree.walk_tree(|tree, entry| -> Result<(), TreeError> {
            if made_by_the_format(&entry.path, tree.family()) {
                return Ok(());
            }
            let path = if entry.path.is_empty() {
                b"/".to_vec()
            } else {
                entry.path.clone()
            };
            let second = match entry.shared {
                Some(id) => match first_name.get(&id) {
                    Some(first) => Some(first.clone()),
                    None => {
                        first_name.insert(id, path.clone());
                        None
                    }
                },
                None => None,
            };
            if let Some(target) = second {
                // Attributes and metadata belong to the node, which the first name carries.
                let meta = tree.stat(&entry.node, synthesis)?.meta;
                found.push((
                    SourceEntry::new(path, EntryKind::HardLink { target }, meta),
                    None,
                ));
                return Ok(());
            }
            let attributes = tree.stat(&entry.node, synthesis)?;
            let darwin = tree.darwin(&entry.node)?;
            for property in &attributes.synthesized {
                fidelity.record(Direction::Synthesized, &path, *property);
            }
            let mut content = None;
            let kind = match entry.kind {
                NodeKind::Directory => EntryKind::Directory,
                NodeKind::File { size } => {
                    tree.check_file_size(&path, size)?;
                    content = Some((nodes.len(), size));
                    nodes.push(entry.node);
                    EntryKind::File(FileContent::Owned(Vec::new()))
                }
                NodeKind::Symlink => EntryKind::Symlink(tree.link_target(&entry.node)?),
                NodeKind::CharDevice { major, minor } => EntryKind::CharDevice { major, minor },
                NodeKind::BlockDevice { major, minor } => EntryKind::BlockDevice { major, minor },
                NodeKind::Fifo => EntryKind::Fifo,
                NodeKind::Socket => EntryKind::Socket,
            };
            let mut source =
                SourceEntry::new(path, kind, attributes.meta).with_xattrs(attributes.xattrs);
            source.darwin = darwin;
            found.push((source, content));
            Ok(())
        })?;
        let reader: Arc<Mutex<dyn ReadNode>> = Arc::new(Mutex::new(Held { tree, nodes }));
        let entries = found
            .into_iter()
            .map(|(mut entry, content)| {
                if let Some((index, len)) = content {
                    entry.kind = EntryKind::File(FileContent::Image(ImageFile {
                        reader: Arc::clone(&reader),
                        index,
                        len,
                    }));
                }
                entry
            })
            .collect();
        Ok(Self { entries, fidelity })
    }

    /// What the reader filled from the caller's [`Synthesis`] rather than read from the image,
    /// by entry: empty for a family whose format records every property.
    #[must_use]
    pub const fn fidelity(&self) -> &FidelityReport {
        &self.fidelity
    }

    /// The entries, without consuming the source.
    #[must_use]
    pub fn entries(&self) -> &[SourceEntry] {
        &self.entries
    }
}

impl Source for ImageSource {
    fn into_entries(self) -> Vec<SourceEntry> {
        self.entries
    }
}
