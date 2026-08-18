#!/usr/bin/env python3
"""Every page that names one filesystem family names all of them.

A family is added to this crate over many files, and the code half of that work fails
loudly: a module that does not compile, a match arm that is not exhaustive, an API
snapshot that no longer matches. The prose half fails silently. A README keeps rendering,
a registry keeps serving the description it was published with, and the only symptom is a
reader who cannot tell from the landing page that the family is there at all.

It is a gate rather than a checklist because the failure is silent and recurs on a different
page each time. It reads the families the crate itself defines, and holds every public prose
surface to naming all of them.

  ci/family-coverage.sh            check
  ci/family-coverage.sh --list     print the surfaces and the spellings without checking

It holds two things, and the second is narrower than the first. Every page that names one
family names all of them; and every *field* that names one — a `description`, a keyword
list — spells each in the form a search is typed as, because a lineage has more than one
member and `ext2/3/4` is a string containing the word `ext2` and never the word `ext4`.

It is lexical, so it is neither sound nor complete: it cannot tell a family named in
passing from one the page actually covers, and it would accept a page that names them all
badly. What it catches is the failure that keeps happening — a page that stops one short.

A surface here is a page a stranger reads before they read any code: the two crate front
pages a registry renders, the workspace front page a forge renders, the guide's own first
page, and the `description` and `keywords` a registry search matches word for word. A
`description` is the strictest of them, because `cargo publish` freezes it.

Two artifacts ship, and a family reaches them on different days: the library gains one when
its module lands, and the binary gains one when its own dependency names the feature. So a
surface is held to the families *its own artifact* carries — the library's pages to the
families the crate defines, and the binary's to the features its dependency line asks for.
Anything else would make one of the two pages lie: the library's by omitting a family it
has, or the binary's by claiming one it cannot open.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Where the crate says which families it has. Read rather than restated, so a family added
# to the enum is a family this gate demands prose for on the same day.
FAMILY_SOURCE = ROOT / "crates" / "ferrosys" / "src" / "finding.rs"
FAMILY_ARM = re.compile(r"Family::\w+ => \"(\w+)\"")
# The enum itself, so the arms can be counted against the variants they name. An arm
# written in some other shape would drop out of the list above while the gate went on
# looking alive with one family fewer to ask for.
FAMILY_ENUM = re.compile(r"pub enum Family \{(.*?)\n\}", re.DOTALL)
FAMILY_VARIANT = re.compile(r"^\s{4}([A-Z]\w*),\s*$", re.MULTILINE)

# How each family is spelled where a person would recognize it, and where a registry search
# would match it. A name and no format number is not a naming: `ext` is the first three
# letters of `extract` and `extent`, and `FAT` is the last four of `exFAT`.
SPELLINGS = {
    "ext": r"\bext[234]\b",
    "fat": r"\bfat(?:12|16|32)\b",
    "exfat": r"\bex-?fat\b",
    # The one family whose name carries no format number and needs none: nothing else is
    # spelled this way, where `ext` is the first three letters of `extract`.
    "btrfs": r"\bbtrfs\b",
}

# And the one spelling a search is actually typed as, for the fields a search reads.
#
# A lineage has more than one member and the rule above is satisfied by any of them, so
# `ext2/3/4` passes it while containing the word `ext2` and never the word `ext4` -- the
# most-searched term this crate has, absent from the field a registry indexes. Prose may
# say `ext2` and mean the family; a `description` is matched word for word, so it says the
# word. Applied only to the surfaces below that name a field, which are the ones a search
# reads rather than a reader.
SEARCHED = {
    "ext": r"\bext4\b",
    "fat": r"\bfat32\b",
    "exfat": r"\bexfat\b",
    "btrfs": r"\bbtrfs\b",
}

# Each surface, and how much of the file is prose a stranger reads. `None` is the whole
# file; a pattern takes the values it captures, which is what keeps a `Cargo.toml` check on
# the two fields a registry publishes rather than on the feature names beneath them.
CARGO_FIELDS = re.compile(r"^(?:description|keywords)\s*=\s*(.+)$", re.MULTILINE)

# The binary's own dependency line, which is where it says which families it carries. Read
# rather than restated, so the day that line gains a family is the day this gate asks the
# binary's pages for it.
CLI_MANIFEST = ROOT / "crates" / "ferrosys-cli" / "Cargo.toml"
CLI_FEATURES = re.compile(r"^ferrosys\s*=.*\bfeatures\s*=\s*\[([^\]]*)\]", re.MULTILINE)

LIBRARY = "library"
BINARY = "binary"
# The guide's front matter, which a reader meets before any page: the `description` a
# rendered book puts in its head, held to the same rule the crate descriptions are.
BOOK_FIELDS = re.compile(r"^(?:title|description)\s*=.*$", re.MULTILINE)

SURFACES = [
    ("README.md", None, LIBRARY),
    ("crates/ferrosys/README.md", None, LIBRARY),
    ("crates/ferrosys-cli/README.md", None, BINARY),
    ("book/book.toml", BOOK_FIELDS, LIBRARY),
    ("book/src/introduction.md", None, LIBRARY),
    # The guide's design pages make claims per family — which values are inputs, which
    # byte orders are fixed — so a family missing from one is a guarantee the page
    # silently withholds. Taken as a glob rather than a list: a page added to that
    # directory is a page a stranger reads, and a hand-kept list is a list a new page is
    # not added to. The walkthrough chapters are not here: each introduces the families
    # one at a time under its own headings, which the rule below (name one, name all) is
    # the wrong shape for.
    *sorted(
        (str(p.relative_to(ROOT)), None, LIBRARY)
        for p in (ROOT / "book" / "src" / "design").glob("*.md")
    ),
    ("crates/ferrosys/Cargo.toml", CARGO_FIELDS, LIBRARY),
    ("crates/ferrosys-cli/Cargo.toml", CARGO_FIELDS, BINARY),
]


def families():
    """The families the crate defines, in the order it defines them."""
    text = FAMILY_SOURCE.read_text()
    found = FAMILY_ARM.findall(text)
    if not found:
        sys.exit(
            f"no family names found in {FAMILY_SOURCE.relative_to(ROOT)}: this gate would "
            "pass by having nothing to ask for"
        )
    # One name per variant. Zero matches already fails above; this is the failure that
    # would otherwise pass -- a family whose arm is written differently leaves the list
    # one short, and a gate asking for three of four families is green on a page that
    # stops at three.
    enum = FAMILY_ENUM.search(text)
    if not enum:
        sys.exit(f"no `pub enum Family` found in {FAMILY_SOURCE.relative_to(ROOT)}")
    variants = FAMILY_VARIANT.findall(enum.group(1))
    if len(found) != len(variants):
        sys.exit(
            f"{FAMILY_SOURCE.relative_to(ROOT)}: {len(variants)} families are declared "
            f"({', '.join(variants)}) and {len(found)} are named ({', '.join(found)}). "
            "A family this gate cannot read the name of is a family it never asks for."
        )
    return found


def binary_families(known):
    """The families the shipping binary carries, in the order the crate defines them."""
    found = CLI_FEATURES.search(CLI_MANIFEST.read_text())
    if not found:
        sys.exit(
            f"no ferrosys dependency features found in "
            f"{CLI_MANIFEST.relative_to(ROOT)}: this gate would pass by having nothing to "
            "ask the binary's pages for"
        )
    asked = {word.strip().strip("\"'") for word in found.group(1).split(",")}
    return [f for f in known if f in asked]


def prose(path, fields):
    """The part of `path` a stranger reads, lowercased for matching."""
    text = (ROOT / path).read_text()
    if fields is not None:
        text = "\n".join(fields.findall(text))
    return text.lower()


def main():
    known = families()
    unspelled = [f for f in known if f not in SPELLINGS]
    if unspelled:
        print("A family the crate defines has no spelling written down here.\n")
        for f in unspelled:
            print(f"  {f}")
        print(
            "\nAdd it to SPELLINGS with the form a reader recognizes and a registry search\n"
            "matches, then this gate can hold the pages to naming it."
        )
        return 1

    carried = {LIBRARY: known, BINARY: binary_families(known)}

    if "--list" in sys.argv[1:]:
        print("families:")
        for f in known:
            print(f"  {f:<8} {SPELLINGS[f]}")
        for artifact, families_of in carried.items():
            print(f"\n{artifact} carries: {', '.join(families_of)}")
        print("\nsurfaces:")
        for path, fields, artifact in SURFACES:
            scope = "description and keywords" if fields else "whole file"
            print(f"  {path:<38} {artifact:<8} {scope}")
        return 0

    problems = []
    for path, fields, artifact in SURFACES:
        expected = carried[artifact]
        text = prose(path, fields)
        named = [f for f in known if re.search(SPELLINGS[f], text)]
        # A page naming no family is not this gate's business: a licence, a changelog, a
        # page about something else. What it holds is that a page which names one is
        # complete for the artifact it introduces.
        if named and sorted(named) != sorted(expected):
            missing = ", ".join(f for f in expected if f not in named)
            extra = ", ".join(f for f in named if f not in expected)
            fault = f"not {missing}" if missing else f"and claims {extra}, which it cannot open"
            problems.append(f"{path} ({artifact}): names {', '.join(named)} -- {fault}")
        # A field a search reads must carry the word that search is typed as. Only where a
        # field was named: the whole-file surfaces are prose, and prose introduces a lineage
        # by whichever member the sentence is about.
        if named and fields is not None:
            unfindable = [
                f for f in expected if f in named and not re.search(SEARCHED[f], text, re.I)
            ]
            if unfindable:
                want = ", ".join(re.sub(r"\\b", "", SEARCHED[f]) for f in unfindable)
                problems.append(
                    f"{path} ({artifact}): names {', '.join(unfindable)} in a form a search "
                    f"does not match -- spell out {want}"
                )

    if problems:
        print("A page names some of this crate's filesystem families and not the rest.\n")
        for p in problems:
            print(f"  {p}")
        print(
            "\nA reader who cannot find a family on the page that introduces the crate has\n"
            "no reason to believe it is there. Name every family, or say nothing about any\n"
            "of them on that page."
        )
        return 1

    print(
        f"family coverage: {len(SURFACES)} surfaces — "
        f"{len(carried[LIBRARY])} families in the library, "
        f"{len(carried[BINARY])} in the binary"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
