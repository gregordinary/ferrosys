//! `ferrosys detect`: say which filesystem an image holds.
//!
//! This answers "what is this, and is it here" — the question a partition table, a carver,
//! or a pipeline of unlabelled images asks — and nothing else. It is deliberately more
//! forgiving than `inspect`: an image whose identity is readable is classified even where a
//! strict read of it would be refused, because whether a filesystem *is one* and whether it
//! is *sound* are different questions, and `inspect` answers the second.

use std::fs::File;

use ferrosys::{DetectOptions, Filesystem};

use crate::{Error, emit};

/// The two words a classified filesystem answers to: the family, and the finer variant
/// where the family has one.
///
/// The same pair `inspect`'s head carries and `detect` prints, kept in one table because
/// every command that names what an image holds must name it in the same words — a refusal
/// calling a volume by a word `detect` does not print would be two vocabularies for one
/// filesystem.
pub fn words(found: &Filesystem) -> (&'static str, Option<&'static str>) {
    match found {
        Filesystem::Ext(profile) => ("ext", Some(profile.as_str())),
        Filesystem::Fat(fat_type) => ("fat", Some(fat_type.as_str())),
        // No variant, and the null is the answer rather than a gap: these two families have one
        // format each, with no lineage to spell and no revisions to tell apart, so the family
        // *is* the finer answer and there is nothing finer to give.
        Filesystem::ExFat => ("exfat", None),
        Filesystem::Btrfs => ("btrfs", None),
        // A family the library classified and this binary has no name for, which a newer
        // library linked against an older tool would produce. Saying `unknown` is honest;
        // saying `unrecognized` would not be, since something did recognize it.
        _ => ("unknown", None),
    }
}

/// Classify the image the arguments name.
pub fn run(args: crate::args::DetectArgs) -> Result<(), Error> {
    let file = File::open(&args.image).map_err(|e| Error::io(&args.image, e))?;
    let found = ferrosys::detect_with(file, &DetectOptions::new().base(args.offset));

    // The classification is the artifact of the run, so it goes to the standard output —
    // including the negative answer, which is as much an answer as the positive one. An
    // unrecognized image is not a failure of the command; the exit code says which it was.
    let (family, variant) = match &found {
        Ok(filesystem) => words(filesystem),
        Err(_) => ("unrecognized", None),
    };

    let text = if args.json {
        crate::json::document(|o| {
            o.str("family", family);
            match variant {
                Some(name) => o.str("variant", name),
                None => o.raw("variant", "null"),
            }
            o.u64("offset", args.offset);
        })
    } else {
        // One word for the answer, so `$(ferrosys detect img)` is usable in a shell test.
        // The variant is the finer answer where there is one, and it is what a caller acts
        // on: ext2, ext3, and ext4 are read by the same reader but mounted by name, and so
        // are fat12, fat16, and fat32.
        match variant {
            Some(name) => format!("{name}\n"),
            None => format!("{family}\n"),
        }
    };
    emit(text.as_bytes())?;

    // Nothing was classified: the bytes are not a filesystem this build knows, which is the
    // same verdict `inspect` reports when it cannot open an image at all.
    match found {
        Ok(_) => Ok(()),
        Err(source) => Err(Error::NotDetected {
            path: args.image.display().to_string(),
            source,
        }),
    }
}
