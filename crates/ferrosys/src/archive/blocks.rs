//! The tar block layer: framing a tar stream into members and parsing the PAX
//! extended-header records that decorate them.
//!
//! Framing walks the stream once, front to back, in one of two modes. [`read_members`]
//! is eager: it reads each member's body as owned bytes, so no seeking is required and
//! the peak memory is the sum of the members' bodies rather than the archive's size.
//! [`read_members_seeking`] instead records where each body lies and seeks past it,
//! which needs a seekable source and leaves the peak memory independent of what the
//! archive holds.
//!
//! A tar stream is a sequence of 512-byte blocks. Each member is one header block
//! followed by its body padded up to a block boundary. Four header types carry no
//! file of their own and instead decorate the member that follows: `x` (PAX records
//! for the next member), `g` (archive-wide PAX defaults), `L` (a long path) and `K`
//! (a long link target). A fifth, `V` (a GNU volume label), names the archive
//! itself and decorates nothing. [`read_members`] consumes all five and yields only
//! the members that describe a file, each already carrying the decoration that
//! applied to it.
//!
//! PAX records are parsed length-prefix-first: a record is `LEN KEY=VALUE\n` where
//! `LEN` is the decimal byte length of the whole record including the digits, the
//! space and the trailing newline. The length is what delimits a record, so a value
//! may contain any byte — a newline included, which a binary `system.posix_acl_*`
//! attribute naming user or group 10 routinely does.

use std::io::{Read, Seek, SeekFrom};

use tar::{EntryType, Header};

use super::ArchiveError;

/// The size of a tar block. Every header is one block and every body is padded to a
/// multiple of one.
const BLOCK: usize = 512;

/// The byte range a tar header's checksum field occupies, which is summed as eight
/// spaces when the checksum is computed.
const CKSUM_FIELD: std::ops::Range<usize> = 148..156;

/// One PAX extended-header record.
pub(super) struct PaxRecord {
    /// The record key, e.g. `mtime` or `SCHILY.xattr.user.comment`.
    pub key: Vec<u8>,
    /// The record value, verbatim. Any byte may appear here, including a newline.
    pub value: Vec<u8>,
}

/// One archive member that describes a file, with everything that decorates it
/// already resolved.
pub(super) struct Member {
    /// The member's own header block, exactly as the archive stores it. Field
    /// accessors read the archive's bytes, never a value folded in from a PAX
    /// record, so a record and its header field stay distinguishable.
    pub header: Header,
    /// The member's path: the `L` long name if it has one, else a PAX `path`
    /// record, else the header's name (with its `ustar` prefix joined).
    pub path: Vec<u8>,
    /// The link target for a symlink or hard link: the `K` long link if present,
    /// else a PAX `linkpath` record, else the header's link name.
    pub link: Option<Vec<u8>>,
    /// The PAX records that apply to this member, in archive order.
    pub records: Vec<PaxRecord>,
    /// The member's body: its bytes, or where to find them in a seekable archive.
    pub body: MemberBody,
}

/// A member's body, either read or located.
///
/// The eager parser reads every body; the seeking one records where each lies and moves
/// on, which is what lets a whole archive's file contents stay on disk until each is
/// placed.
pub(super) enum MemberBody {
    /// The bytes, read while parsing.
    Bytes(Vec<u8>),
    /// Where the bytes lie in the archive, which was verified to hold them.
    Range {
        /// Byte offset of the body within the archive file.
        offset: u64,
        /// Length of the body in bytes.
        len: u64,
    },
}

impl Member {
    /// The value of the last record with `key`, or `None` when the member carries
    /// none. A repeated key takes its last value, the rule POSIX gives for a record
    /// appearing more than once in one header.
    fn record(&self, key: &[u8]) -> Option<&[u8]> {
        self.records
            .iter()
            .rev()
            .find(|r| r.key == key)
            .map(|r| r.value.as_slice())
    }
}

/// Frame `reader` into the members that describe files.
///
/// # Errors
///
/// An [`ArchiveError::Malformed`] if the block structure, a header checksum or a
/// PAX record body cannot be read, and [`ArchiveError::Io`] if the stream fails.
pub(super) fn read_members<R: Read>(reader: R) -> Result<Vec<Member>, ArchiveError> {
    read_members_with(reader, |r, size| Ok(MemberBody::Bytes(read_body(r, size)?)))
}

/// Parse an archive from a seekable source, recording where each member's body lies
/// rather than reading it.
///
/// The archive is checked to actually hold every body it declares, so a range handed back
/// here names bytes that were present at parse time — a truncated archive fails now, not
/// when a file is placed.
pub(super) fn read_members_seeking<R: Read + Seek>(
    mut reader: R,
) -> Result<Vec<Member>, ArchiveError> {
    let end = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    read_members_with(reader, move |r, size| {
        let offset = r.stream_position()?;
        // Bodies are padded to a whole block, and the padding is part of the framing:
        // skipping only the body would read the next header from the wrong offset.
        //
        // Both steps are checked. A PAX `size` record carries a full `u64`, so rounding
        // one near the top of the range up to a block is not representable — and a
        // wrapped round-up would name a body of zero padded bytes, passing the bound
        // below that exists to reject exactly this member.
        let next = size
            .checked_next_multiple_of(BLOCK as u64)
            .and_then(|padded| offset.checked_add(padded))
            .filter(|&next| next <= end)
            .ok_or(ArchiveError::Malformed {
                reason: "archive ends inside a member body",
            })?;
        r.seek(SeekFrom::Start(next))?;
        Ok(MemberBody::Range { offset, len: size })
    })
}

fn read_members_with<R: Read>(
    mut reader: R,
    mut take_body: impl FnMut(&mut R, u64) -> Result<MemberBody, ArchiveError>,
) -> Result<Vec<Member>, ArchiveError> {
    let mut members = Vec::new();
    // The decoration accumulated for the member that comes next. A `g` header does
    // not consume it: PAX assigns an `x` header to the next member that carries a
    // file, and the extension headers between are transparent.
    let mut records: Vec<PaxRecord> = Vec::new();
    let mut long_path: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;
    let mut first_block = true;

    while let Some(block) = read_block(&mut reader)? {
        // A zero block is the end-of-archive marker. The trailing blocks after it
        // are padding and are not read.
        if block.iter().all(|&b| b == 0) {
            break;
        }
        if let Err(e) = verify_cksum(&block) {
            // The head of the stream is where a compressed archive is recognizable, and the
            // first block failing its checksum is what a compressed one looks like from
            // here. Later blocks are past any wrapper's header, so a failure there is
            // corruption and is reported as such.
            if first_block && let Some(format) = compression(&block) {
                return Err(ArchiveError::Compressed { format });
            }
            return Err(e);
        }
        first_block = false;
        let header = Header::from_byte_slice(&block);
        let stored = header.entry_size().map_err(|_| ArchiveError::Malformed {
            reason: "unreadable member size",
        })?;
        match header.entry_type() {
            EntryType::XHeader => {
                records = parse_records(&read_body(&mut reader, stored)?)?;
            }
            EntryType::GNULongName => {
                long_path = Some(trim_nul(read_body(&mut reader, stored)?));
            }
            EntryType::GNULongLink => {
                long_link = Some(trim_nul(read_body(&mut reader, stored)?));
            }
            // A `g` header carries archive-wide defaults, not a file — every
            // `git archive` tarball begins with one. Its records are not applied,
            // since this layer resolves per-member records only.
            EntryType::XGlobalHeader => {
                read_body(&mut reader, stored)?;
            }
            // A GNU volume label (`tar --label`) names the archive itself, not a
            // file in it, so it is passed over the way every extractor passes it
            // over. A label carries no body, but a producer that writes one is
            // consumed anyway to keep the framing aligned.
            t if t.as_byte() == b'V' => {
                read_body(&mut reader, stored)?;
            }
            _ => {
                let mut member = Member {
                    header: header.clone(),
                    path: Vec::new(),
                    link: None,
                    records: std::mem::take(&mut records),
                    body: MemberBody::Bytes(Vec::new()),
                };
                member.path = match long_path.take() {
                    Some(p) => p,
                    None => match member.record(b"path") {
                        Some(v) => v.to_vec(),
                        None => header.path_bytes().into_owned(),
                    },
                };
                member.link = match long_link.take() {
                    Some(l) => Some(l),
                    None => match member.record(b"linkpath") {
                        Some(v) => Some(v.to_vec()),
                        None => header.link_name_bytes().map(std::borrow::Cow::into_owned),
                    },
                };
                // An old-GNU sparse member ('S') can continue its hole map into
                // further header blocks, so the block after it is not necessarily
                // the next member. Framing past one is not possible, and the model
                // cannot represent a sparse member in any case, so it ends the walk
                // here rather than resynchronizing on whatever follows.
                if header.entry_type() == EntryType::GNUSparse {
                    return Err(ArchiveError::Bad {
                        path: member.path,
                        reason: "old-GNU sparse files are not supported",
                    });
                }
                // A PAX `size` record overrides the header field, which caps out at
                // 8 GiB in its octal form. Reading the header's value for a member
                // that declared a larger one would frame the rest of the archive
                // from the wrong offset.
                let size = match member.record(b"size") {
                    Some(v) => parse_decimal(v).ok_or(ArchiveError::Malformed {
                        reason: "invalid PAX size record",
                    })?,
                    None => stored,
                };
                member.body = take_body(&mut reader, size)?;
                members.push(member);
            }
        }
    }
    Ok(members)
}

/// Read the next whole block, or `None` at a clean end of stream.
fn read_block<R: Read>(reader: &mut R) -> Result<Option<[u8; BLOCK]>, ArchiveError> {
    let mut block = [0u8; BLOCK];
    let mut filled = 0;
    while filled < BLOCK {
        match reader.read(&mut block[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    match filled {
        0 => Ok(None),
        BLOCK => Ok(Some(block)),
        // A stream too short to hold one block is often a compressed archive small enough
        // to fit in one, and its magic says which — a far more useful thing to be told than
        // that tar framing the caller never wrote is incomplete.
        _ => Err(compression(&block[..filled]).map_or(
            ArchiveError::Malformed {
                reason: "archive ends inside a block",
            },
            |format| ArchiveError::Compressed { format },
        )),
    }
}

/// The compression format the bytes at the head of a stream identify, if any.
///
/// A compressed archive is the commonest thing handed to a tar parser by mistake, and every
/// format that wraps one announces itself in its first bytes. The check is made only where a
/// block has already failed to be a tar block, so a valid archive whose first member's name
/// happens to begin with one of these bytes is never mislabelled.
fn compression(head: &[u8]) -> Option<&'static str> {
    const MAGIC: &[(&[u8], &str)] = &[
        (&[0x1f, 0x8b], "gzip"),
        (&[0x28, 0xb5, 0x2f, 0xfd], "zstd"),
        (&[0xfd, b'7', b'z', b'X', b'Z', 0x00], "xz"),
        (b"BZh", "bzip2"),
        (&[0x04, 0x22, 0x4d, 0x18], "lz4"),
        (&[0x5d, 0x00, 0x00], "lzma"),
        (b"\x89LZO", "lzop"),
        (&[0x1f, 0x9d], "compress"),
    ];
    MAGIC
        .iter()
        .find(|(magic, _)| head.starts_with(magic))
        .map(|&(_, format)| format)
}

/// Read a body of `size` bytes and consume the padding up to the next block
/// boundary. The read is bounded by the bytes the stream actually holds, so a
/// header declaring a huge size cannot drive an allocation the archive cannot back.
fn read_body<R: Read>(reader: &mut R, size: u64) -> Result<Vec<u8>, ArchiveError> {
    let mut data = Vec::new();
    reader.by_ref().take(size).read_to_end(&mut data)?;
    if data.len() as u64 != size {
        return Err(ArchiveError::Malformed {
            reason: "archive ends inside a member body",
        });
    }
    let mut padding = (BLOCK - (data.len() % BLOCK)) % BLOCK;
    let mut sink = [0u8; BLOCK];
    while padding > 0 {
        match reader.read(&mut sink[..padding])? {
            0 => {
                return Err(ArchiveError::Malformed {
                    reason: "archive ends inside a member body",
                });
            }
            n => padding -= n,
        }
    }
    Ok(data)
}

/// Check a header block's checksum: the unsigned sum of every byte, with the
/// checksum field itself counted as eight spaces.
fn verify_cksum(block: &[u8; BLOCK]) -> Result<(), ArchiveError> {
    let declared = Header::from_byte_slice(block)
        .cksum()
        .map_err(|_| ArchiveError::Malformed {
            reason: "unreadable header checksum",
        })?;
    let sum: u32 = block[..CKSUM_FIELD.start]
        .iter()
        .chain(&block[CKSUM_FIELD.end..])
        .map(|&b| u32::from(b))
        .sum::<u32>()
        + (CKSUM_FIELD.len() as u32) * u32::from(b' ');
    if sum != declared {
        return Err(ArchiveError::Malformed {
            reason: "header checksum mismatch",
        });
    }
    Ok(())
}

/// Parse an `x` or `g` header body into its records.
///
/// Each record is `LEN KEY=VALUE\n`, where `LEN` counts the whole record. The
/// length is what ends a record, so a value carrying a newline — or any other byte
/// — is read intact. Trailing NUL padding some producers append is accepted.
fn parse_records(body: &[u8]) -> Result<Vec<PaxRecord>, ArchiveError> {
    let malformed = || ArchiveError::Malformed {
        reason: "malformed PAX extended header",
    };
    let mut records = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        if rest.iter().all(|&b| b == 0) {
            break;
        }
        let space = rest.iter().position(|&b| b == b' ').ok_or_else(malformed)?;
        let len = parse_decimal(&rest[..space]).ok_or_else(malformed)?;
        let len = usize::try_from(len)
            .ok()
            .filter(|&l| l <= rest.len())
            .ok_or_else(malformed)?;
        // The record must hold its own length prefix, the space, a `KEY=VALUE` of at
        // least three bytes and the newline. The lower bound also guarantees the
        // walk advances.
        if len < space + 5 {
            return Err(malformed());
        }
        let record = &rest[..len];
        if record[len - 1] != b'\n' {
            return Err(malformed());
        }
        let pair = &record[space + 1..len - 1];
        let equals = pair.iter().position(|&b| b == b'=').ok_or_else(malformed)?;
        if equals == 0 {
            return Err(malformed());
        }
        records.push(PaxRecord {
            key: pair[..equals].to_vec(),
            value: pair[equals + 1..].to_vec(),
        });
        rest = &rest[len..];
    }
    Ok(records)
}

/// Parse an unsigned decimal ASCII number, rejecting an empty or non-digit token.
fn parse_decimal(text: &[u8]) -> Option<u64> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// Drop the terminating NUL a `L`/`K` body carries.
fn trim_nul(mut body: Vec<u8>) -> Vec<u8> {
    if body.last() == Some(&0) {
        body.pop();
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_delimited_by_length_not_newline() {
        // A binary POSIX ACL naming user 10 embeds `0A` — a newline — in its value.
        // Splitting the body on newlines would cut this record in half; the length
        // prefix reads it intact.
        let value = b"\x02\x00\x00\x00\x01\x00\x06\x00\x0a\x00\x00\x00";
        let key = b"SCHILY.xattr.system.posix_acl_access";
        let payload_len = key.len() + 1 + value.len() + 1;
        // The length field counts itself, and 2 digits is stable for this size.
        let len = payload_len + 2 + 1;
        let mut body = format!("{len} ").into_bytes();
        body.extend_from_slice(key);
        body.push(b'=');
        body.extend_from_slice(value);
        body.push(b'\n');

        let records = parse_records(&body).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key, key);
        assert_eq!(records[0].value, value);
    }

    #[test]
    fn records_reject_a_length_that_does_not_delimit() {
        // A length running past the body, a length too short to hold a pair, a
        // record not ending in a newline, and a pair with no key are all malformed.
        assert!(parse_records(b"99 mtime=1\n").is_err());
        assert!(parse_records(b"3 a\n").is_err());
        assert!(parse_records(b"11 mtime=1 ").is_err());
        assert!(parse_records(b"9 =value\n").is_err());
        // Trailing NUL padding is not a record.
        assert!(parse_records(b"11 mtime=1\n\0\0\0").unwrap().len() == 1);
    }

    #[test]
    fn a_body_shorter_than_its_header_claims_is_malformed() {
        let mut stream = vec![0u8; BLOCK];
        assert!(matches!(
            read_body(&mut &stream[..], 4096),
            Err(ArchiveError::Malformed { .. })
        ));
        stream.truncate(BLOCK - 1);
        assert!(matches!(
            read_block(&mut &stream[..]),
            Err(ArchiveError::Malformed { .. })
        ));
        assert!(read_block(&mut &[][..]).unwrap().is_none());
    }

    /// A one-member archive whose `x` header declares `size` for the member that follows.
    /// The member's own header records a size of zero and carries no body, so everything
    /// the framing does with the declared size comes from the PAX record.
    fn pax_sized_archive(size: &str) -> Vec<u8> {
        let payload = format!("size={size}\n");
        // The length prefix counts itself, so it is solved for rather than measured.
        let mut len = payload.len() + 2;
        while format!("{len} ").len() + payload.len() != len {
            len += 1;
        }
        let records = format!("{len} {payload}");

        let mut out = Vec::new();
        let mut push_block = |bytes: &[u8]| {
            out.extend_from_slice(bytes);
            out.resize(out.len().next_multiple_of(BLOCK), 0);
        };

        let mut x = Header::new_gnu();
        x.set_entry_type(EntryType::XHeader);
        x.set_size(records.len() as u64);
        x.set_cksum();
        push_block(x.as_bytes());
        push_block(records.as_bytes());

        let mut h = Header::new_gnu();
        h.set_entry_type(EntryType::Regular);
        h.set_size(0);
        h.set_path("big").unwrap();
        h.set_cksum();
        push_block(h.as_bytes());

        // The end-of-archive marker.
        out.resize(out.len() + 2 * BLOCK, 0);
        out
    }

    #[test]
    fn a_pax_size_no_offset_can_hold_is_malformed() {
        // Framing a declared size computes the body's start plus its length rounded up to
        // a whole block, and each step of that has a size it cannot represent. All three
        // are one verdict — the archive does not hold the body it declares — so each is
        // named here beside the size that reaches it, since a single unchecked step is
        // enough to hand back a range the archive cannot back.
        //
        // The member's body begins 1536 bytes in, after the `x` header, its records, and
        // the member's own header.
        let cases = [
            // The round-up: no multiple of 512 at or above these fits a `u64`.
            (u64::MAX, "the round-up"),
            (u64::MAX - 510, "the round-up"),
            // Block-aligned already, so the round-up is the identity — and the sum with
            // the body's offset is what overflows.
            (u64::MAX - 511, "the sum with the offset"),
            (u64::MAX - 1000, "the sum with the offset"),
            // Both steps succeed; the body simply runs far past the end of the archive.
            (u64::MAX / 2 + 1, "the bound against the archive's length"),
        ];
        for (size, step) in cases {
            let archive = pax_sized_archive(&size.to_string());
            assert!(
                matches!(
                    read_members_seeking(std::io::Cursor::new(&archive)),
                    Err(ArchiveError::Malformed { .. })
                ),
                "size {size} framed successfully; {step} did not refuse it"
            );
            // The eager parser bounds its read by the bytes the stream holds, so it
            // reaches the same verdict by a different route.
            assert!(
                matches!(
                    read_members(&archive[..]),
                    Err(ArchiveError::Malformed { .. })
                ),
                "size {size} read successfully"
            );
        }
    }

    #[test]
    fn the_seeking_parser_records_a_body_the_archive_holds() {
        // The refusals above are worth nothing if they also refuse a sound archive. A size
        // the archive genuinely holds is recorded as a range rather than read, at the
        // offset the framing computed.
        let mut archive = pax_sized_archive("512");
        // Splice a body block in after the member's header, which is the third block.
        archive.splice(3 * BLOCK..3 * BLOCK, [0xab; BLOCK]);
        let members = read_members_seeking(std::io::Cursor::new(&archive)).unwrap();
        assert_eq!(members.len(), 1);
        assert!(matches!(
            members[0].body,
            MemberBody::Range {
                offset: 1536,
                len: 512
            }
        ));

        // A body shorter than its padding is framed from the padded length: the range is
        // the body, and the next header is read from the block boundary after it.
        let mut archive = pax_sized_archive("8");
        archive.splice(3 * BLOCK..3 * BLOCK, [0xcd; BLOCK]);
        let members = read_members_seeking(std::io::Cursor::new(&archive)).unwrap();
        assert!(matches!(
            members[0].body,
            MemberBody::Range {
                offset: 1536,
                len: 8
            }
        ));
    }
}
