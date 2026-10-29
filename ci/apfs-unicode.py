#!/usr/bin/env python3
"""Generate the Unicode tables the APFS reader compares names with.

    ci/apfs-unicode.py UCD-DIR > crates/ferrosys/src/apfs/unicode_tables.rs

UCD-DIR holds UnicodeData.txt, CaseFolding.txt and DerivedAge.txt of one Unicode version, as
unicode.org publishes them under https://www.unicode.org/Public/<version>/ucd/. The output is
four sorted tables:

- every code point's full canonical decomposition, expanded to the end so a lookup takes one
  step (Hangul syllables are decomposed by the Unicode Standard's arithmetic, section 3.12,
  and are not listed);
- every code point's nonzero canonical combining class;
- every code point's full case folding, statuses C and F;
- every range of assigned code points, with the version that assigned them, adjacent ranges of
  one version joined.

Every input is held to the SHA-256 of the file the tables were made from, pinned below, so
the tables regenerate from the same data rather than from whatever happens to be downloaded; a
new Unicode version is a change to the pins. The generated file records the version and every
digest. Its header carries
the Unicode License v3's copyright and permission notice whole, read from LICENSE-UNICODE at the
workspace root, since the notice is the one condition the license sets on copies of its data.
"""

import hashlib
import os
import re
import sys

# The Unicode Character Database 17.0.0's three files, as unicode.org publishes them.
PINNED = {
    "UnicodeData.txt": "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c",
    "CaseFolding.txt": "ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183",
    "DerivedAge.txt": "f8ecdf768bdc210f201abd271d9bc587825618a86a7046a8146cc816393f1998",
}


def read(path):
    with open(path, "rb") as f:
        data = f.read()
    return data.decode("utf-8"), hashlib.sha256(data).hexdigest()


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    ucd = argv[1]
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    notice, _ = read(os.path.join(root, "LICENSE-UNICODE"))
    unicode_data, unicode_digest = read(os.path.join(ucd, "UnicodeData.txt"))
    case_folding, folding_digest = read(os.path.join(ucd, "CaseFolding.txt"))
    derived_age, age_digest = read(os.path.join(ucd, "DerivedAge.txt"))
    for name, digest in (
        ("UnicodeData.txt", unicode_digest),
        ("CaseFolding.txt", folding_digest),
        ("DerivedAge.txt", age_digest),
    ):
        if digest != PINNED[name]:
            raise SystemExit(
                f"{name} has SHA-256 {digest}, not the {PINNED[name]} the tables are pinned "
                "to; a new Unicode version is a change to PINNED"
            )
    version = re.search(r"CaseFolding-(\d+)\.(\d+)\.(\d+)\.txt", case_folding)
    if not version:
        raise SystemExit("CaseFolding.txt does not name its version")

    decomp, ccc = {}, {}
    for line in unicode_data.splitlines():
        p = line.split(";")
        cp = int(p[0], 16)
        if int(p[3]):
            ccc[cp] = int(p[3])
        if p[5] and not p[5].startswith("<"):
            decomp[cp] = [int(x, 16) for x in p[5].split()]

    def full(cp):
        if cp not in decomp:
            return [cp]
        out = []
        for c in decomp[cp]:
            out.extend(full(c))
        return out

    fold = {}
    for line in case_folding.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        code, status, mapping = [x.strip() for x in line.split(";")[:3]]
        if status in ("C", "F"):
            fold[int(code, 16)] = [int(x, 16) for x in mapping.split()]

    ages = []
    for line in derived_age.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        span, age = [x.strip() for x in line.split(";")]
        first, _, last = span.partition("..")
        age_major, age_minor = (int(x) for x in age.split("."))
        ages.append((int(first, 16), int(last or first, 16), age_major, age_minor))
    ages.sort()
    assigned = []
    for first, last, age_major, age_minor in ages:
        if assigned and assigned[-1][1] + 1 == first and assigned[-1][2:] == (age_major, age_minor):
            assigned[-1] = (assigned[-1][0], last, age_major, age_minor)
        else:
            assigned.append((first, last, age_major, age_minor))

    major, minor, update = version.groups()
    out = []
    w = out.append
    w("//! The Unicode tables an APFS volume's names are compared with: generated, not written.")
    w("//!")
    w(f"//! From the Unicode Character Database {major}.{minor}.{update}, by `ci/apfs-unicode.py`:")
    w(f"//! `UnicodeData.txt` (SHA-256 {unicode_digest}),")
    w(f"//! `CaseFolding.txt` (SHA-256 {folding_digest}) and")
    w(f"//! `DerivedAge.txt` (SHA-256 {age_digest}).")
    w("//! The data is the Unicode Character Database's, under the Unicode License v3, whose")
    w("//! copyright and permission notice follows; `LICENSE-UNICODE` holds the same text.")
    w("//!")
    for line in notice.rstrip("\n").split("\n"):
        w(f"//! {line}".rstrip())
    w("//!")
    w("//! Regenerate rather than edit. This module is pure data.")
    w("")
    w("/// Every code point's full canonical decomposition, in code-point order. A code point")
    w("/// not listed is its own decomposition; Hangul syllables decompose by arithmetic.")
    w("pub(super) const DECOMPOSITION: &[(u32, &[u32])] = &[")
    for cp in sorted(decomp):
        w(f"    (0x{cp:X}, &[{', '.join(f'0x{c:X}' for c in full(cp))}]),")
    w("];")
    w("")
    w("/// Every code point whose canonical combining class is not zero, with the class, in")
    w("/// code-point order.")
    w("pub(super) const COMBINING_CLASS: &[(u32, u8)] = &[")
    for cp in sorted(ccc):
        w(f"    (0x{cp:X}, {ccc[cp]}),")
    w("];")
    w("")
    w("/// Every code point's full case folding, statuses C and F, in code-point order. A code")
    w("/// point not listed folds to itself.")
    w("pub(super) const CASE_FOLDING: &[(u32, &[u32])] = &[")
    for cp in sorted(fold):
        w(f"    (0x{cp:X}, &[{', '.join(f'0x{c:X}' for c in fold[cp])}]),")
    w("];")
    w("")
    w("/// Every range of assigned code points, first and last, with the major and minor version")
    w("/// of Unicode that assigned them, in code-point order. A code point in no range is")
    w("/// unassigned in every version these tables hold.")
    w("pub(super) const ASSIGNED: &[(u32, u32, u8, u8)] = &[")
    for first, last, age_major, age_minor in assigned:
        w(f"    (0x{first:X}, 0x{last:X}, {age_major}, {age_minor}),")
    w("];")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main(sys.argv)
