//! Choosing which volume of an APFS container a read verb reads, and at which snapshot.
//!
//! An APFS container holds several volumes, each a filesystem of its own, so `inspect` and
//! `extract` take `--volume` and `--snapshot` for it. The selection is made when the container
//! is opened rather than after, since what a read of the wrong volume refuses would stop it
//! first.
//!
//! # The volume a read naming none reads
//!
//! The first volume this tool reads, in slot order. On a Mac's own disk the first slot holds a
//! sealed system volume, which this tool refuses, and the user's files are in a data volume
//! after it, so a volume refused by design is passed over, and the standard error says so and
//! why. A volume whose superblock cannot be read is not passed over: damage is reported where
//! it stops the read, never stepped around unasked. Where no volume reads, the first slot's
//! refusal is the answer, in the words a read naming it gets.

use std::cell::Cell;
use std::fs::File;

use ferrosys::apfs::{Container, ReadError, Reader, UnreadableVolume, VolumeEntry};

use ferrosys::{DetectOptions, Filesystem, FsReader};

use crate::args::VolumeChoice;
use crate::{Error, render};

/// Open the image as whichever family holds it, honouring `choice` where it is an APFS
/// container and refusing it where it is anything else.
///
/// An image of another family is opened by the root, and refused by an option that does not
/// apply to it rather than by a failure to open. The volumes passed over on the way to the one
/// read are named on the standard error unless `said` says they were, by an earlier open of the
/// same image, and `said` then says so.
pub fn open_choosing(
    mut file: File,
    path: &str,
    options: &ferrosys::OpenOptions,
    choice: &VolumeChoice,
    said: &Cell<bool>,
) -> Result<FsReader<File>, Error> {
    let mut detect = DetectOptions::new().base(options.base);
    detect.len = options.len;
    let found =
        ferrosys::detect_with(&mut file, &detect).map_err(|source| Error::NotAFilesystem {
            path: path.to_string(),
            source: source.into(),
        })?;
    if found != Filesystem::Apfs {
        let Some(option) = choice.named_option() else {
            return ferrosys::open_with(file, options).map_err(|source| Error::NotAFilesystem {
                path: path.to_string(),
                source,
            });
        };
        // A btrfs keeps snapshots too, as subvolumes a path reaches, so its refusal says so
        // rather than that it has none.
        let reason = if found == Filesystem::Btrfs && option == "--snapshot" {
            "a btrfs snapshot is a subvolume, which a path in the filesystem reaches"
        } else {
            "an image of this family holds one filesystem, where an APFS container holds \
             several volumes and their snapshots"
        };
        return Err(Error::NotForFamily {
            option,
            family: crate::detect::words(&found).0,
            reason,
        });
    }
    // What the container and the volume refuse is refused as the root's open refuses it; a
    // snapshot is read once its volume has opened, so what it fails on is classed as a read of
    // the volume is.
    let refused = |source| Error::Apfs {
        path: path.to_string(),
        source,
    };
    let container = Container::open_with(file, options).map_err(refused)?;
    let entry = match choice.volume.as_deref() {
        Some(wanted) => named(&container, wanted).map_err(|e| e.into_error(path))?,
        None => first_read(&container, said).map_err(|e| e.into_error(path))?,
    };
    let mut reader = Reader::over(container, entry).map_err(refused)?;
    if let Some(name) = &choice.snapshot {
        let held = reader.snapshots().map_err(crate::from_apfs_read)?;
        if !held.iter().any(|s| &s.name == name) {
            return Err(Error::NoSuchSnapshot {
                wanted: render::printable(name),
                holds: listed(held.iter().map(|s| render::printable(&s.name))),
            });
        }
        reader = reader.at_snapshot(name).map_err(crate::from_apfs_read)?;
    }
    Ok(FsReader::Apfs(reader))
}

/// Why no volume was chosen, before it is told with the image's path.
enum Unchosen {
    /// The volume chosen, or the first slot, refused, with its reason.
    Refused(ReadError),
    /// No volume answers the name, identifier or number asked for.
    NoSuchVolume { wanted: String, holds: String },
    /// More than one volume has the name asked for.
    Ambiguous { wanted: String, slots: String },
    /// The container lists no volume.
    Empty,
}

impl Unchosen {
    fn into_error(self, path: &str) -> Error {
        match self {
            Unchosen::Refused(source) => Error::Apfs {
                path: path.to_string(),
                source,
            },
            Unchosen::NoSuchVolume { wanted, holds } => Error::NoSuchVolume { wanted, holds },
            Unchosen::Ambiguous { wanted, slots } => Error::AmbiguousVolume { wanted, slots },
            Unchosen::Empty => Error::NoVolume {
                path: path.to_string(),
            },
        }
    }
}

/// The volume `wanted` names: by name first, then by the identifier a report prints for it,
/// dashed or bare, and by slot number where neither answers. A name two volumes share names
/// neither, and a slot the container could not read is refused with why.
fn named(container: &Container<File>, wanted: &[u8]) -> Result<VolumeEntry, Unchosen> {
    let volumes = container.volumes();
    let by_name: Vec<&VolumeEntry> = volumes.iter().filter(|v| v.name() == wanted).collect();
    match by_name.as_slice() {
        [one] => return Ok((*one).clone()),
        [] => {}
        several => {
            return Err(Unchosen::Ambiguous {
                wanted: render::printable(wanted),
                slots: listed(several.iter().map(|v| v.slot.to_string())),
            });
        }
    }
    let bare = |text: &str| text.replace('-', "").to_ascii_lowercase();
    if let Ok(text) = std::str::from_utf8(wanted)
        && let Some(volume) = volumes
            .iter()
            .find(|v| bare(&render::uuid(&v.superblock.uuid)) == bare(text))
    {
        return Ok(volume.clone());
    }
    let slot: Option<usize> = std::str::from_utf8(wanted)
        .ok()
        .and_then(|text| text.parse().ok());
    if let Some(slot) = slot {
        if let Some(volume) = volumes.iter().find(|v| v.slot == slot) {
            return Ok(volume.clone());
        }
        if let Some(unread) = container
            .unreadable_volumes()
            .iter()
            .find(|u| u.slot == slot)
        {
            return Err(Unchosen::Refused(unread.error.clone()));
        }
    }
    Err(Unchosen::NoSuchVolume {
        wanted: if wanted.is_empty() {
            "named by an empty name".to_string()
        } else {
            render::printable(wanted)
        },
        holds: listed(
            volumes
                .iter()
                .map(|v| format!("{} (slot {})", render::printable(v.name()), v.slot)),
        ),
    })
}

/// One slot the container lists, in a read naming no volume.
enum Slot<'c> {
    /// A volume whose superblock was read.
    Volume(&'c VolumeEntry),
    /// One whose superblock could not be.
    Unreadable(&'c UnreadableVolume),
}

/// How a read naming no volume takes a slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    /// This tool reads its volume.
    Reads,
    /// This tool refuses its volume by design: encrypted, sealed, a feature it does not read.
    Refused,
    /// Its superblock could not be read.
    Unreadable,
}

impl Slot<'_> {
    fn slot(&self) -> usize {
        match self {
            Slot::Volume(v) => v.slot,
            Slot::Unreadable(u) => u.slot,
        }
    }

    fn status(&self) -> Status {
        match self {
            Slot::Volume(v) if v.refusal().is_none() => Status::Reads,
            Slot::Volume(_) => Status::Refused,
            Slot::Unreadable(_) => Status::Unreadable,
        }
    }

    /// Why a read of it is refused, where it is.
    fn why(&self) -> Option<ReadError> {
        match self {
            Slot::Volume(v) => v.refusal(),
            Slot::Unreadable(u) => Some(u.error.clone()),
        }
    }

    /// The slot as a person names it.
    fn shown(&self) -> String {
        match self {
            Slot::Volume(v) => format!("volume {} ({})", v.slot, render::printable(v.name())),
            Slot::Unreadable(u) => format!("volume {}", u.slot),
        }
    }
}

/// The volume a read naming none reads (see the module documentation), with a line on the
/// standard error for each volume before it that was passed over, unless `said` says those
/// lines were written.
fn first_read(container: &Container<File>, said: &Cell<bool>) -> Result<VolumeEntry, Unchosen> {
    let mut slots: Vec<Slot<'_>> = container
        .volumes()
        .iter()
        .map(Slot::Volume)
        .chain(container.unreadable_volumes().iter().map(Slot::Unreadable))
        .collect();
    slots.sort_by_key(Slot::slot);
    if slots.is_empty() {
        return Err(Unchosen::Empty);
    }
    let statuses: Vec<Status> = slots.iter().map(Slot::status).collect();
    match default_slot(&statuses) {
        Ok(at) => {
            let Slot::Volume(volume) = slots[at] else {
                unreachable!("a slot that reads holds a volume whose superblock was read");
            };
            if said.replace(true) {
                return Ok(volume.clone());
            }
            for passed in &slots[..at] {
                let why = passed.why().map(|e| e.to_string()).unwrap_or_default();
                eprintln!(
                    "{}: {} is not read here: {why}",
                    crate::args::TOOL,
                    passed.shown()
                );
            }
            if at > 0 {
                eprintln!(
                    "{}: reading {}; --volume names another",
                    crate::args::TOOL,
                    slots[at].shown()
                );
            }
            Ok(volume.clone())
        }
        Err(at) => Err(Unchosen::Refused(
            slots[at].why().expect("a slot that does not read says why"),
        )),
    }
}

/// Which of `statuses`, each a slot's in slot order, a read naming no volume reads, by its
/// place: the first that reads, passing over the ones before it this tool refuses by design.
/// Where a slot whose superblock cannot be read comes first, or no slot reads, the answer is
/// the place of the slot whose refusal is the reason: that one, or the first.
fn default_slot(statuses: &[Status]) -> Result<usize, usize> {
    for (at, status) in statuses.iter().enumerate() {
        match status {
            Status::Reads => return Ok(at),
            Status::Refused => {}
            Status::Unreadable => return Err(at),
        }
    }
    Err(0)
}

/// `items` as a comma-separated list, or `none`.
fn listed(items: impl Iterator<Item = String>) -> String {
    let list: Vec<String> = items.collect();
    if list.is_empty() {
        "none".to_string()
    } else {
        list.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::{Status, default_slot};

    #[test]
    fn a_read_naming_no_volume_passes_over_a_refusal_and_stops_at_damage() {
        use Status::{Reads, Refused, Unreadable};
        // A Mac's own disk: the sealed system volume, then the data volume.
        assert_eq!(default_slot(&[Refused, Reads]), Ok(1));
        assert_eq!(default_slot(&[Reads, Refused]), Ok(0));
        assert_eq!(default_slot(&[Refused, Refused, Reads]), Ok(2));
        // Damage is the answer where it comes first, and the first slot where nothing reads.
        assert_eq!(default_slot(&[Unreadable, Reads]), Err(0));
        assert_eq!(default_slot(&[Refused, Unreadable, Reads]), Err(1));
        assert_eq!(default_slot(&[Refused, Refused]), Err(0));
    }
}
