#!/usr/bin/env python3
"""Find a tracked file that names another implementation's internals.

Driven by ci/provenance.txt, which holds the rules, the names the formats' own documentation
uses, and the reasoning. This is the scanner: it reads every tracked text file, finds each
spelling a rule denies, and reports every one that no entry accounts for.

Why not grep alone: `fat_type` is a field of this crate and `fat_ent_read` would be a routine
of another implementation, and what tells them apart is whether this tree defines the name,
which no grep knows. So the scanner first collects every identifier the tree's own Rust
defines, and a prefixed identifier the tree defines is the tree's own.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "ci" / "provenance.txt"
# The gate's own two files spell out what they deny.
SELF = {"ci/provenance.py", "ci/provenance.txt"}

# A tree this size has well over this many Rust files. Fewer means the listing went wrong,
# and a gate that scanned nothing would pass.
MIN_RUST_FILES = 50

# A Rust item: the item keywords, `const fn` among them, and `macro_rules!`.
DEFINITION = re.compile(
    r"\b(?:fn|struct|enum|const|static|mod|type|trait|union)\s+(?:fn\s+)?([A-Za-z_]\w*)"
    r"|\bmacro_rules!\s*([A-Za-z_]\w*)"
)
# A field, a parameter, or a field named in a literal or a pattern: a name and a single
# colon. Read from code only, since prose is full of words followed by colons.
BINDING = re.compile(r"\b([a-z_][a-z0-9_]*)\s*:(?!:)")
# The names a pattern binds: whatever stands left of a match arm's `=>`, of a `let`'s `=`,
# and between a closure's bars.
PATTERN = re.compile(r"^(.*?)=>|\blet\s+(.*?)=|\|([^|]*)\|")
IDENTIFIER = re.compile(r"\b[a-z_][a-z0-9_]*\b")
# A string literal that is one identifier and nothing else: a key in a document this tree
# emits, which is a name of its own.
KEY = re.compile(r'"([a-z_][a-z0-9_]*)"')


class Entry:
    """One line of ci/provenance.txt."""

    def __init__(self, kind, value, reason, line, file=None):
        self.kind = kind
        self.value = value
        self.reason = reason
        self.line = line
        self.file = file
        self.pattern = re.compile(value) if kind in ("path", "macro") else None


def parse(text):
    """Every entry, by kind, in the order written.

    `path` and `macro` carry their regex last, because an extended regex contains `|` and
    splitting on it would silently truncate the pattern: a gate that runs and checks less
    than it claims to.
    """
    kinds = ("prefix", "name", "path", "macro", "format", "interface", "operational", "known")
    entries = {k: [] for k in kinds}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        kind, _, rest = line.partition("|")
        if kind not in entries:
            sys.exit(f"ci/provenance.txt:{n}: unknown kind {kind!r}")
        if kind in ("path", "macro"):
            reason, _, value = rest.partition("|")
            entries[kind].append(Entry(kind, value, reason, n))
        elif kind == "known":
            parts = rest.split("|", 2)
            if len(parts) != 3:
                sys.exit(f"ci/provenance.txt:{n}: known needs <file>|<spelling>|<why>")
            file, value, reason = parts
            if not (ROOT / file).is_file():
                sys.exit(f"ci/provenance.txt:{n}: {file!r} is not a file in this tree")
            entries[kind].append(Entry(kind, value, reason, n, file))
        else:
            value, _, reason = rest.partition("|")
            entries[kind].append(Entry(kind, value, reason, n))
        entry = entries[kind][-1]
        if not entry.value or not entry.reason.strip():
            sys.exit(
                f"ci/provenance.txt:{n}: an entry with no reason is not an entry. Say what "
                "the spelling names, or why it stands."
            )
    return entries


def tracked():
    """Every tracked file that reads as text, as (path, text)."""
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode()
    for rel in listing.split("\0"):
        if not rel or rel in SELF:
            continue
        try:
            yield rel, (ROOT / rel).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # an image fixture: bytes, not prose
        except FileNotFoundError:
            continue  # deleted in the working tree and not yet staged


def code_part(line):
    """`line` up to a `//` comment that does not sit inside a string literal."""
    at = line.find("//")
    while at != -1:
        if line[:at].count('"') % 2 == 0:
            return line[:at]
        at = line.find("//", at + 2)
    return line


def own_names(files):
    """Every identifier this tree's Rust defines, and every tracked file's stem."""
    names = set()
    rust = 0
    for rel, text in files:
        names.add(Path(rel).stem)
        if not rel.endswith(".rs"):
            continue
        rust += 1
        for line in text.splitlines():
            code = code_part(line)
            for match in DEFINITION.finditer(code):
                names.update(g for g in match.groups() if g)
            names.update(BINDING.findall(code))
            names.update(KEY.findall(code))
            for match in PATTERN.finditer(code):
                for group in match.groups():
                    if group:
                        names.update(IDENTIFIER.findall(group))
    if rust < MIN_RUST_FILES:
        sys.exit(f"only {rust} Rust files found: the gate would pass by looking at nothing")
    return names


def main():
    if not RULES.is_file():
        sys.exit("ci/provenance.txt is not readable: the gate has no rules to run")
    entries = parse(RULES.read_text())
    if not entries["prefix"] or not entries["path"]:
        sys.exit("ci/provenance.txt declares no prefixes or no paths: a gate that checks "
                 "nothing passes")

    if "--list" in sys.argv[1:]:
        for kind in ("prefix", "name", "path", "macro"):
            for e in entries[kind]:
                print(f"  {kind:<6} {e.value}")
                print(f"         {e.reason}")
        for kind in ("format", "interface", "operational", "known"):
            print(f"  {len(entries[kind])} {kind} entries")
        return 0

    files = list(tracked())
    own = own_names(files)

    prefixes = sorted((e.value for e in entries["prefix"]), key=len, reverse=True)
    prefixed = re.compile(
        r"(?<![A-Za-z0-9_])((?:" + "|".join(map(re.escape, prefixes)) + r")[A-Za-z0-9_]*)"
    )
    names = {e.value: e for e in entries["name"]}
    named = re.compile(
        r"(?<![A-Za-z0-9_])(" + "|".join(map(re.escape, names)) + r")(?![A-Za-z0-9_])"
    ) if names else None
    format_names = {e.value: e for e in entries["format"]}
    interface = {e.value: e for e in entries["interface"]}
    operational = {e.value: e for e in entries["operational"]}
    known = {(e.file, e.value): e for e in entries["known"]}

    used = set()
    findings = []

    def account(rel, n, line, spelling, rule):
        entry = known.get((rel, spelling))
        if entry:
            used.add(id(entry))
            return
        findings.append((rel, n, line.strip(), spelling, rule))

    for rel, text in files:
        for n, line in enumerate(text.splitlines(), 1):
            for token in prefixed.findall(line):
                for table in (format_names, interface):
                    if token in table:
                        used.add(id(table[token]))
                        break
                else:
                    if token not in own:
                        account(rel, n, line, token, "a routine of another implementation")
            if named:
                for token in named.findall(line):
                    account(rel, n, line, token, names[token].reason)
            for e in entries["macro"]:
                for match in e.pattern.finditer(line):
                    account(rel, n, line, match.group(0), e.reason)
            if rel in operational:
                used.add(id(operational[rel]))
                continue
            for e in entries["path"]:
                for match in e.pattern.finditer(line):
                    account(rel, n, line, match.group(0), e.reason)

    stale = [
        e
        for kind in ("format", "interface", "operational", "known")
        for e in entries[kind]
        if id(e) not in used
    ]

    if findings:
        print("A file names another implementation's internals.\n")
        for rel, n, line, spelling, rule in findings:
            print(f"  {rel}:{n}  {spelling}")
            print(f"      {line}")
            print(f"      {rule}\n")
        print("Describe the rule in the format's own terms — the structure its documentation")
        print("names, or what a tool or a kernel is observed to do — rather than by the")
        print("routine in another implementation that applies it. A name the format's")
        print("documentation uses is a `format` line in ci/provenance.txt, with the document.")
        return 1

    if stale:
        print("An entry in ci/provenance.txt accounts for nothing in the tree.\n")
        for e in stale:
            where = f"{e.file}: " if e.file else ""
            print(f"  line {e.line}: {e.kind} {where}{e.value}")
        print()
        print("The spelling it accounted for is gone, so the line goes too. A `known` line")
        print("only ever leaves: it is never added back for a new spelling.")
        return 1

    print(
        f"provenance: {len(files)} files, {len(entries['prefix'])} prefixes, "
        f"{len(entries['path'])} source paths, {len(entries['known'])} known spellings, "
        "nothing new"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
