"""Take Apple's restore RAM disk out of a macOS restore image without fetching the image whole.

    python3 -I apple-ramdisk.py member URL NAME OUT
    python3 -I apple-ramdisk.py payload IM4P OUT

`member` writes the member NAME of the ZIP archive at URL to OUT, reading the archive by HTTP
range requests: its end records, its central directory, the member's local header, then the
member's bytes. A restore image is several gigabytes and the member a few hundred megabytes, so
this is what the fetch costs. The layout is the one PKWARE's APPNOTE documents, ZIP64 records
included, since a restore image is past what 32-bit offsets reach.

`payload` writes the container an IM4P file wraps to OUT. The file is DER: one SEQUENCE, whose
elements are strings, and the payload is the one OCTET STRING whose bytes are a container, with
a container superblock's magic at offset 32 of its first block. That is the whole of what is
taken from the wrapper, by observation of the image this fetch pins.
"""

import struct
import sys
import urllib.request
import zlib

CHUNK = 1 << 20


def fetch(url, start, end):
    """Bytes start..end (inclusive) of url."""
    req = urllib.request.Request(url, headers={"Range": "bytes=%d-%d" % (start, end)})
    with urllib.request.urlopen(req) as r:
        if r.status != 206:
            raise SystemExit("%s answered %d to a range request" % (url, r.status))
        return r.read()


def length(url):
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req) as r:
        return int(r.headers["Content-Length"])


def central_directory(url):
    """The central directory's bytes, from the end records."""
    size = length(url)
    tail_start = max(0, size - (1 << 16) - 22)
    tail = fetch(url, tail_start, size - 1)
    end = tail.rfind(b"PK\x05\x06")
    if end < 0:
        raise SystemExit("no end of central directory record")
    (cd_size, cd_offset) = struct.unpack_from("<II", tail, end + 12)
    locator = tail.rfind(b"PK\x06\x07", 0, end)
    if locator >= 0:
        (zip64_end,) = struct.unpack_from("<Q", tail, locator + 8)
        record = fetch(url, zip64_end, zip64_end + 55)
        if record[:4] != b"PK\x06\x06":
            raise SystemExit("no ZIP64 end of central directory record")
        (cd_size, cd_offset) = struct.unpack_from("<QQ", record, 40)
    return fetch(url, cd_offset, cd_offset + cd_size - 1)


def find(directory, name):
    """The member's method, compressed size, and local header offset."""
    at = 0
    want = name.encode()
    while at + 46 <= len(directory):
        if directory[at:at + 4] != b"PK\x01\x02":
            raise SystemExit("a central directory entry without its signature")
        method = struct.unpack_from("<H", directory, at + 10)[0]
        csize, usize = struct.unpack_from("<II", directory, at + 20)
        nlen, xlen, clen = struct.unpack_from("<HHH", directory, at + 28)
        (offset,) = struct.unpack_from("<I", directory, at + 42)
        entry = directory[at + 46:at + 46 + nlen]
        extra = directory[at + 46 + nlen:at + 46 + nlen + xlen]
        if entry == want:
            x = 0
            while x + 4 <= len(extra):
                tag, n = struct.unpack_from("<HH", extra, x)
                if tag == 1:
                    vals = extra[x + 4:x + 4 + n]
                    v = 0
                    if usize == 0xFFFFFFFF:
                        usize = struct.unpack_from("<Q", vals, v)[0]
                        v += 8
                    if csize == 0xFFFFFFFF:
                        csize = struct.unpack_from("<Q", vals, v)[0]
                        v += 8
                    if offset == 0xFFFFFFFF:
                        offset = struct.unpack_from("<Q", vals, v)[0]
                x += 4 + n
            return method, csize, offset
        at += 46 + nlen + xlen + clen
    raise SystemExit("no member named %s" % name)


def member(url, name, out):
    method, csize, offset = find(central_directory(url), name)
    if method not in (0, 8):
        raise SystemExit("member %s is compressed by method %d" % (name, method))
    local = fetch(url, offset, offset + 29)
    if local[:4] != b"PK\x03\x04":
        raise SystemExit("no local header at the member's offset")
    nlen, xlen = struct.unpack_from("<HH", local, 26)
    start = offset + 30 + nlen + xlen
    inflate = zlib.decompressobj(-15) if method == 8 else None
    with open(out, "wb") as f:
        at = start
        while at < start + csize:
            data = fetch(url, at, min(at + 16 * CHUNK, start + csize) - 1)
            at += len(data)
            f.write(inflate.decompress(data) if inflate else data)
        if inflate:
            f.write(inflate.flush())


def header(f):
    """A DER element's tag, and its content's length, at f's position."""
    tag, first = f.read(2)
    if first < 0x80:
        return tag, first
    n = first & 0x7F
    return tag, int.from_bytes(f.read(n), "big")


def payload(im4p, out):
    with open(im4p, "rb") as f:
        f.seek(0, 2)
        end = f.tell()
        f.seek(0)
        tag, size = header(f)
        if tag != 0x30:
            raise SystemExit("an IM4P is one SEQUENCE")
        stop = f.tell() + size
        if stop != end:
            raise SystemExit("the SEQUENCE does not fill the file")
        while f.tell() < stop:
            tag, size = header(f)
            here = f.tell()
            if tag == 0x04 and size > 36:
                f.seek(here + 32)
                if f.read(4) == b"NXSB":
                    f.seek(here)
                    with open(out, "wb") as o:
                        left = size
                        while left:
                            block = f.read(min(CHUNK, left))
                            o.write(block)
                            left -= len(block)
                    return
            f.seek(here + size)
    raise SystemExit("no OCTET STRING holding a container")


if __name__ == "__main__":
    if sys.argv[1:2] == ["member"] and len(sys.argv) == 5:
        member(*sys.argv[2:])
    elif sys.argv[1:2] == ["payload"] and len(sys.argv) == 4:
        payload(*sys.argv[2:])
    else:
        raise SystemExit(__doc__)
