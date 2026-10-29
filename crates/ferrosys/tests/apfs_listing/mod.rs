//! macOS's listing of an APFS volume, and the comparison that holds a reader's view to it field
//! by field: what the corpus gate and the restore RAM disk gate both hold a volume to.
//!
//! A listing is the one `apfs-probes`'s `corpusutil.py manifest` records from a mounted volume:
//! every entry the system calls reach, with its inode number, mode, owner, group, BSD flags, link
//! count, four times, size, device number, link target, every attribute's name, length and
//! digest, a compressed file's type and size, a directory's names, and every file's digest.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

use ferrosys::Darwin;
use ferrosys::apfs::ondisk::{
    INTERNAL_COMPRESSED, INTERNAL_WITH_RESOURCE_FORK, INTERNAL_WITH_SECURITY_ATTRIBUTE,
    INTERNAL_WITHOUT_RESOURCE_FORK, SECURITY_XATTR,
};
use ferrosys::apfs::{Node, Reader, WalkEntry};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Hold every entry `reader` walks to the listing `manifest`, and every entry listed to the walk,
/// adding each disagreement to `faults` under `label`. Returns how many entries were walked.
pub fn compare<R: Read + Seek>(
    reader: &mut Reader<R>,
    manifest: &Value,
    label: &str,
    faults: &mut Faults,
) -> usize {
    let errors = manifest["errors"].as_array().expect("an error list");
    assert!(
        errors.is_empty(),
        "{label}: macOS's listing records errors: {errors:?}"
    );
    // A listing names a path relative to the volume's root, the root itself empty; the walk
    // names it from `/`, the root itself empty.
    let mut listed: BTreeMap<Vec<u8>, &Value> = BTreeMap::new();
    for entry in manifest["entries"].as_array().expect("an entry list") {
        let relative = unhex(&entry["path_hex"]);
        let path = if relative.is_empty() {
            relative
        } else {
            [b"/".as_slice(), &relative].concat()
        };
        listed.insert(path, entry);
    }

    let walked = reader.walk().expect("the walk reaches every name");
    let mut seen = BTreeSet::new();
    for WalkEntry { path, node, .. } in walked {
        match listed.get(&path) {
            Some(want) => compare_entry(reader, &path, &node, want, label, faults),
            None => faults.add(label, &path, "path", &"walked", &"not listed"),
        }
        seen.insert(path);
    }
    for path in listed.keys().filter(|p| !seen.contains(*p)) {
        faults.add(label, path, "path", &"not walked", &"listed");
    }
    seen.len()
}

/// Hold one entry to its listing, field by field.
fn compare_entry<R: Read + Seek>(
    reader: &mut Reader<R>,
    path: &[u8],
    node: &Node,
    want: &Value,
    label: &str,
    faults: &mut Faults,
) {
    let mut check = |field: &str, read: i128, listed: &Value| {
        let listed = listed
            .as_i64()
            .map(i128::from)
            .or(listed.as_u64().map(i128::from));
        if Some(read) != listed {
            faults.add(label, path, field, &read, &format!("{listed:?}"));
        }
    };
    let v = &node.value;
    check("inode", i128::from(node.inode), &want["ino"]);
    check("mode", i128::from(v.mode), &want["mode"]);
    check("owner", i128::from(v.owner), &want["uid"]);
    check("group", i128::from(v.group), &want["gid"]);
    check("flags", i128::from(v.bsd_flags), &want["flags"]);
    check("access time", i128::from(v.access_time), &want["atime_ns"]);
    check("modify time", i128::from(v.modify_time), &want["mtime_ns"]);
    check("change time", i128::from(v.change_time), &want["ctime_ns"]);
    check(
        "birth time",
        i128::from(v.create_time),
        &want["birthtime_ns"],
    );
    // A directory's inode keeps how many names it holds, and macOS reports that and the two
    // every directory has, `.` and `..`. Its size is macOS's own figure, made from the same
    // count, and nothing the volume stores.
    if node.is_dir() {
        check(
            "link count",
            i128::from(v.links_or_children) + 2,
            &want["nlink"],
        );
    } else {
        check(
            "link count",
            i128::from(v.links_or_children),
            &want["nlink"],
        );
        check("size", i128::from(node.size()), &want["size"]);
    }
    if let Some(rdev) = want.get("rdev") {
        check("device", node.device.map_or(-1, i128::from), rdev);
    }

    match (
        node.compression
            .as_ref()
            .map(|c| c.as_ref().map_err(ToString::to_string)),
        want.get("compression").filter(|c| !c.is_null()),
    ) {
        (None, None) => {}
        (Some(Ok(c)), Some(listed)) => {
            let mut check = |field: &str, read: u64, listed: &Value| {
                if Some(read) != listed.as_u64() {
                    faults.add(label, path, field, &read, listed);
                }
            };
            check("compression type", u64::from(c.method), &listed["type"]);
            check("compressed size", c.size, &listed["header_size"]);
        }
        (read, listed) => faults.add(
            label,
            path,
            "compression",
            &format!("{read:?}"),
            &format!("{listed:?}"),
        ),
    }

    // The internal flags the writer gives an inode of this kind, which every inode macOS wrote
    // carries: one saying whether a resource fork is present, a compressed file's beside it, and
    // one saying the security attribute is held. A compressed file's fork is its content, which
    // the reader does not list as an attribute, so its type says where the content is.
    let forked = match &node.compression {
        Some(Ok(c)) => matches!(c.method, 4 | 8 | 10 | 12 | 14),
        _ => reader
            .xattrs(node)
            .expect("read the attributes")
            .iter()
            .any(|x| x.name == b"com.apple.ResourceFork"),
    };
    let fork_flag = if forked {
        INTERNAL_WITH_RESOURCE_FORK
    } else {
        INTERNAL_WITHOUT_RESOURCE_FORK
    };
    let compressed = v.bsd_flags & Darwin::COMPRESSED != 0;
    let secured = reader
        .xattrs(node)
        .expect("read the attributes")
        .iter()
        .any(|x| x.name == SECURITY_XATTR);
    let expected = fork_flag
        | if compressed { INTERNAL_COMPRESSED } else { 0 }
        | if secured {
            INTERNAL_WITH_SECURITY_ATTRIBUTE
        } else {
            0
        };
    let held = v.internal_flags
        & (INTERNAL_WITH_RESOURCE_FORK
            | INTERNAL_WITHOUT_RESOURCE_FORK
            | INTERNAL_COMPRESSED
            | INTERNAL_WITH_SECURITY_ATTRIBUTE);
    if held != expected {
        faults.add(
            label,
            path,
            "internal flags, against the ones the writer gives",
            &format!("{held:#x}"),
            &format!("{expected:#x}"),
        );
    }

    if let Some(target) = want.get("target_hex") {
        let read = reader.link_target(node).expect("read the link target");
        if read != unhex(target) {
            faults.add(label, path, "target", &hex(&read), target);
        }
    }

    if let Some(digest) = want.get("sha256") {
        let mut hasher = Hashing(Sha256::new());
        let read = reader
            .read_data_to(node, &mut hasher)
            .expect("read the file");
        let read_digest = hex(&hasher.0.finalize());
        if read_digest != text(digest) {
            faults.add(label, path, "content", &read_digest, digest);
        }
        if Some(read) != want["read_len"].as_u64() {
            faults.add(label, path, "bytes read", &read, &want["read_len"]);
        }
    }

    // macOS's listing has no attributes for a device node, whose `listxattr` it refuses with
    // `EPERM`; every other node's list is compared, sorted, by name, length, and digest.
    if let Some(listed) = want["xattrs"].as_array() {
        let listed_names: Vec<&str> = listed.iter().map(|x| text(&x["name_hex"])).collect();
        let mut read: Vec<(String, u64, String)> = reader
            .xattrs(node)
            .expect("read the attributes")
            .into_iter()
            // The security attribute is one `listxattr` never returns, so it is set aside where
            // the listing lacks it.
            .filter(|x| x.name != SECURITY_XATTR || listed_names.contains(&hex(&x.name).as_str()))
            .map(|x| {
                (
                    hex(&x.name),
                    x.value.len() as u64,
                    hex(&Sha256::digest(&x.value)),
                )
            })
            .collect();
        read.sort();
        let mut want: Vec<(String, u64, String)> = listed
            .iter()
            .map(|x| {
                (
                    text(&x["name_hex"]).to_string(),
                    x["len"].as_u64().expect("a length"),
                    text(&x["sha256"]).to_string(),
                )
            })
            .collect();
        want.sort();
        if read != want {
            faults.add(
                label,
                path,
                "attributes",
                &format!("{read:?}"),
                &format!("{want:?}"),
            );
        }
    }

    if node.is_dir() {
        let mut read: Vec<String> = reader
            .read_dir(node)
            .expect("list the directory")
            .into_iter()
            .map(|e| hex(&e.name))
            .collect();
        read.sort();
        let mut listed: Vec<String> = want["children_hex"]
            .as_array()
            .expect("a directory lists its names")
            .iter()
            .map(|n| text(n).to_string())
            .collect();
        listed.sort();
        if read != listed {
            faults.add(label, path, "names", &read.len(), &listed.len());
        }
    }
}

/// Every disagreement the gate found, kept so one run reports all of them.
#[derive(Default)]
pub struct Faults(pub Vec<String>);

impl Faults {
    pub fn add(
        &mut self,
        label: &str,
        path: &[u8],
        field: &str,
        read: &dyn std::fmt::Display,
        listed: &dyn std::fmt::Display,
    ) {
        self.0.push(format!(
            "{label}: {}: {field}: read {read}, macOS listed {listed}",
            String::from_utf8_lossy(path)
        ));
    }

    pub fn assert_none(&self) {
        assert!(
            self.0.is_empty(),
            "{} disagreements with macOS, the first of them:\n{}",
            self.0.len(),
            self.0
                .iter()
                .take(60)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// A writer that hashes what it is given, so a file is digested as it is read.
pub struct Hashing(pub Sha256);

impl Write for Hashing {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn json(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("expected a string, got {value}"))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(value: &Value) -> Vec<u8> {
    let s = text(value);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
