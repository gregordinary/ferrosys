#!/usr/bin/env python3
"""Regenerate `rootfs-pax.tar`, the seed for the `archive_parse` fuzz target.

    python3 make-archive-seed.py seeds/archive_parse/rootfs-pax.tar

It lives here rather than in the seed directory because libFuzzer reads every file in a
seed directory as an input.

Every field is fixed — no clock, no host ownership, no random padding — so the archive is
byte-reproducible and a regenerated seed is either identical or a deliberate change.

The archive carries one of each shape the parser resolves, so a mutation lands somewhere
that matters: a `g` global header, PAX timestamps and ownership, a binary `SCHILY.xattr.*`
value (whose NUL bytes are what makes a length-delimited record parser necessary), a text
`SCHILY.acl.*` record, a symlink, a hard link, a character device, a name past the header's
100-byte field, and a body spanning several blocks.
"""

import io
import sys
import tarfile

# One fixed instant for every entry, so nothing is read from the clock.
FAKE = 1700000000

# A version-2 capability value (CAP_NET_RAW), as the bytes a PAX record carries. Every
# byte is under 0x80, so the record holds them verbatim once tarfile encodes it as UTF-8.
CAPABILITY = bytes([1, 0, 0, 2, 0, 32] + [0] * 14).decode("latin-1")


def entry(tf, name, typ, *, mode=0o644, size=0, link="", major=0, minor=0, pax=None, data=b""):
    """Append one member with every field set explicitly."""
    ti = tarfile.TarInfo(name)
    ti.type = typ
    ti.mode = mode
    ti.uid = 0
    ti.gid = 0
    ti.uname = ""
    ti.gname = ""
    ti.mtime = FAKE
    ti.size = size
    ti.linkname = link
    ti.devmajor = major
    ti.devminor = minor
    if pax:
        ti.pax_headers = pax
    tf.addfile(ti, io.BytesIO(data) if data else None)


def build():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        # A `g` header: archive-wide defaults, which the framing passes over.
        tf.pax_headers = {"comment": "ferrosys fuzz seed"}
        entry(tf, "etc", tarfile.DIRTYPE, mode=0o755)
        # Distinct atime/ctime and a non-root owner, all through PAX records.
        entry(
            tf,
            "etc/hostname",
            tarfile.REGTYPE,
            size=9,
            data=b"ferrosys\n",
            pax={
                "atime": "1600000000",
                "ctime": "1650000000",
                "uid": "1000",
                "gid": "1000",
            },
        )
        entry(tf, "etc/mtab", tarfile.SYMTYPE, mode=0o777, link="/proc/self/mounts")
        entry(tf, "bin", tarfile.DIRTYPE, mode=0o755)
        # A binary xattr and a text ACL on one member.
        entry(
            tf,
            "bin/sh",
            tarfile.REGTYPE,
            mode=0o755,
            size=64,
            data=bytes(range(64)),
            pax={
                "SCHILY.xattr.security.capability": CAPABILITY,
                "SCHILY.acl.access": "u::rwx,u:1000:rw-,g::r-x,m::rwx,o::r--",
            },
        )
        entry(tf, "bin/dash", tarfile.LNKTYPE, mode=0o755, link="bin/sh")
        entry(tf, "dev", tarfile.DIRTYPE, mode=0o755)
        entry(tf, "dev/null", tarfile.CHRTYPE, mode=0o666, major=1, minor=3)
        # A name past the 100-byte header field, so a PAX `path` record carries it.
        long_name = "etc/" + "a-name-that-runs-past-the-hundred-byte-header-field-" * 2
        entry(tf, long_name, tarfile.REGTYPE, size=4, data=b"leaf")
        # A body spanning several blocks, so the framing skips more than one.
        entry(tf, "etc/multiblock", tarfile.REGTYPE, size=2600, data=bytes(2600))
    return buf.getvalue()


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "rootfs-pax.tar"
    data = build()
    with open(out, "wb") as f:
        f.write(data)
    print(f"{out}: {len(data)} bytes")
