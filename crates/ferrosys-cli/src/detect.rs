//! `ferrosys detect`: say which filesystem an image holds.
//!
//! This answers "what is this, and is it here" — the question a partition table, a carver,
//! or a pipeline of unlabelled images asks — and nothing else. It is deliberately more
//! forgiving than `inspect`: an image whose identity is readable is classified even where a
//! strict read of it would be refused, because whether a filesystem *is one* and whether it
//! is *sound* are different questions, and `inspect` answers the second.

use std::fs::File;

use ferrosys::{DetectOptions, Filesystem};

use crate::json::Obj;
use crate::{Error, emit};

/// Classify the image the arguments name.
pub fn run(args: crate::args::DetectArgs) -> Result<(), Error> {
    let file = File::open(&args.image).map_err(|e| Error::io(&args.image, e))?;
    let found = ferrosys::detect_with(file, &DetectOptions::new().base(args.offset));

    // The classification is the artifact of the run, so it goes to the standard output —
    // including the negative answer, which is as much an answer as the positive one. An
    // unrecognized image is not a failure of the command; the exit code says which it was.
    let (family, profile) = match &found {
        Ok(Filesystem::Ext(profile)) => ("ext", Some(profile.name())),
        // A family the library classified and this binary has no name for, which a newer
        // library linked against an older tool would produce. Saying `unknown` is honest;
        // saying `unrecognized` would not be, since something did recognize it.
        Ok(_) => ("unknown", None),
        Err(_) => ("unrecognized", None),
    };

    let text = if args.json {
        let mut out = String::new();
        let mut o = Obj::new(&mut out);
        o.u64("schema", crate::json::SCHEMA_VERSION);
        o.str("family", family);
        match profile {
            Some(name) => o.str("profile", name),
            None => o.raw("profile", "null"),
        }
        o.u64("offset", args.offset);
        o.end();
        out.push('\n');
        out
    } else {
        // One word for the answer, so `$(ferrosys detect img)` is usable in a shell test.
        // The profile is the finer answer where there is one, and it is what a caller acts
        // on: ext2, ext3, and ext4 are read by the same reader but mounted by name.
        match profile {
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
