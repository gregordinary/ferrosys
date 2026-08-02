//! `ferrosys identity`: change what an existing filesystem is known by — its UUID, its
//! volume label, or the seed its metadata checksums derive from.
//!
//! This is the one command that writes to an image it did not create. It rewrites the
//! identity fields of every superblock copy and the journal's own record of the UUID, and
//! touches nothing else: a copy keeps every field the rewrite does not name, including the
//! ones this tool has no opinion about.
//!
//! Nothing is written until every copy has been read and every check has passed, so a
//! refusal leaves the image exactly as it was. What cannot be done wholly is not begun —
//! there is no `--atomic` here, because an image is rewritten in place rather than produced,
//! and a sibling temporary file would mean copying every byte of it to change sixteen.

use ferrosys::ext::{IdentityChange, rewrite_identity};

use crate::args::IdentityArgs;
use crate::json::Obj;
use crate::{Error, emit};

/// Rewrite the identity of the image the arguments name.
pub fn run(args: IdentityArgs) -> Result<(), Error> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.image)
        .map_err(|e| Error::io(&args.image, e))?;

    let mut change = IdentityChange::new();
    change.uuid = args.uuid;
    change.volume_name = args.volume_name;
    change.set_checksum_seed = args.set_checksum_seed;

    let report = rewrite_identity(&mut file, &change).map_err(|source| Error::Identity {
        path: args.image.display().to_string(),
        source,
    })?;

    let text = if args.json {
        let mut out = String::new();
        let mut o = Obj::new(&mut out);
        o.u64("schema", crate::json::SCHEMA_VERSION);
        o.u64("superblocks", u64::from(report.superblocks));
        o.raw(
            "journal_superblock",
            if report.journal_superblock {
                "true"
            } else {
                "false"
            },
        );
        o.raw(
            "checksum_seed_set",
            if report.checksum_seed_set {
                "true"
            } else {
                "false"
            },
        );
        o.end();
        out.push('\n');
        out
    } else {
        // What was written, in the terms the operation is understood in: how many copies
        // now agree, and whether the log and the seed moved with them.
        let mut text = format!("{} superblock copies written", report.superblocks);
        if report.journal_superblock {
            text.push_str(", journal superblock updated");
        }
        if report.checksum_seed_set {
            text.push_str(", metadata_csum_seed set");
        }
        text.push('\n');
        text
    };
    emit(text.as_bytes())
}
