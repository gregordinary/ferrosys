#!/usr/bin/env python3
"""Find a shared primitive spelled out a second time.

Driven by ci/one-home.txt, which holds the rules and the reasoning. This is the scanner:
it reads each rule, searches the tree for the spelling that rule exists to catch, and
reports every hit outside the rule's own home and outside the allowlist.

Why not grep alone: whether a *test* may open-code a rule depends on the rule, and no
grep can tell a test module from the code beside it.

  A behavioural rule — what a path splits into, which names a directory can hold — binds
  tests too. A test that reimplements the rule stops checking the rule the moment the rule
  changes, which is the same drift one module further out.

  A byte-layout rule does not. A test that pins an on-disk record asserts the raw bytes at
  literal offsets *on purpose*: reading them back through the same accessor the writer used
  would make the assertion tautological, and byte-exactness is the one property this crate
  cannot afford to check against itself.

So each rule declares its scope, and this strips `mod tests` bodies for the rules that ask
it to.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "ci" / "one-home.txt"


class Rule:
    """One concept, its home, and the spelling that means someone answered it again."""

    def __init__(self, home, scope, instead, pattern):
        self.home = home
        self.scope = scope
        self.instead = instead
        self.pattern = re.compile(pattern)

    def applies_to(self, path):
        # A rule never fires on the module that holds the answer -- that one file and no
        # other. Compared whole rather than by suffix: two crates in this workspace can
        # hold a file of the same name, and a rule that excused both would leave the
        # second one unguarded by an entry written about the first.
        return str(path) != self.home


def parse_rules(text):
    """Rules and allowlist entries, in the order written.

    A rule's regex is everything after the fourth delimiter, because an extended regex
    contains `|` and splitting on that would silently truncate the pattern — a gate that
    runs and checks less than it claims to.
    """
    rules, allowed = [], []
    for line in text.splitlines():
        if line.startswith("rule|"):
            parts = line.split("|", 4)
            if len(parts) < 5:
                sys.exit(f"malformed rule (needs home, scope, instead, regex): {line}")
            _, home, scope, instead, pattern = parts
            if not (ROOT / home).is_file():
                sys.exit(
                    f"a rule's home is not a file in this tree: {home!r}. A home that "
                    "does not resolve excuses nothing and guards the wrong file."
                )
            if scope not in ("code", "all"):
                sys.exit(f"rule scope must be 'code' or 'all', not {scope!r}: {line}")
            rules.append(Rule(home, scope, instead, pattern))
        elif line.startswith("skip|"):
            key = line.split("|", 2)[1]
            frag, _, literal = key.partition(":")
            if not literal:
                sys.exit(f"allowlist key must be <path>:<spelling>: {line}")
            if not (ROOT / frag).is_file():
                sys.exit(
                    f"an allowlist entry names a file this tree does not have: {frag!r}. "
                    "The path is the whole path from the workspace root."
                )
            allowed.append((frag, literal))
    return rules, allowed


def strip_tests(source):
    """`source` with every `mod tests` body blanked, keeping the line numbering.

    Brace counting rather than parsing: a test module opens at `mod tests {` and closes
    where its depth returns to zero. Lines are replaced by empty ones so a hit outside a
    test module still reports the line it is really on.
    """
    out = list(source.splitlines())
    i = 0
    while i < len(out):
        if re.match(r"\s*(pub\s+)?mod tests\s*\{", out[i]):
            depth = 0
            while i < len(out):
                depth += out[i].count("{") - out[i].count("}")
                out[i] = ""
                i += 1
                if depth <= 0:
                    break
        else:
            i += 1
    return out


def main():
    if not RULES.is_file():
        sys.exit("ci/one-home.txt is not readable: the gate has no rules to run")
    rules, allowed = parse_rules(RULES.read_text())
    if not rules:
        sys.exit("ci/one-home.txt declares no rules: a gate that checks nothing passes")

    if "--list" in sys.argv[1:]:
        for rule in rules:
            print(f"  {rule.home:<14} {rule.scope:<5} {rule.pattern.pattern}")
            print(f"       -> {rule.instead}")
        for frag, literal in allowed:
            print(f"  allowed: {frag}  ({literal})")
        return 0

    sources = sorted(ROOT.glob("crates/*/src/**/*.rs"))
    if not sources:
        sys.exit("no sources found: the gate would pass by looking at nothing")

    findings = []
    # Which exceptions were actually needed. An allowlist entry that stops matching is the
    # same rot one level up: a reason recorded for code that has moved on, which the next
    # reader takes for a live decision.
    used = set()
    for path in sources:
        rel = path.relative_to(ROOT)
        text = path.read_text()
        all_lines = text.splitlines()
        code_lines = strip_tests(text)
        for rule in rules:
            if not rule.applies_to(rel):
                continue
            lines = code_lines if rule.scope == "code" else all_lines
            for n, line in enumerate(lines, 1):
                if not rule.pattern.search(line):
                    continue
                excused = [e for e in allowed if e[0] == str(rel) and e[1] in line]
                if excused:
                    used.update(excused)
                    continue
                findings.append((rel, n, line.strip(), rule.instead))

    stale = [e for e in allowed if e not in used]

    if findings:
        print("A concept this crate answers once is spelled out a second time.\n")
        for rel, n, line, instead in findings:
            print(f"  {rel}:{n}")
            print(f"      {line}")
            print(f"      call instead: {instead}")
            print("      or add a skip line to ci/one-home.txt saying why this is not")
            print("      a copy\n")
        print("Two implementations of one concept both work the day they are written.")
        print("They drift later, and the disagreement is silent.")
        return 1

    if stale:
        print("An exception is recorded for something no rule finds any more.\n")
        for frag, literal in stale:
            print(f"  {frag}  ({literal})")
        print()
        print("Either the code it excused is gone — in which case delete the line — or a")
        print("rule stopped matching it, in which case the rule is what to look at. A")
        print("reason kept for code that has moved on reads as a live decision.")
        return 1

    print(
        f"one home per concept: {len(rules)} rules over {len(sources)} files, "
        f"{len(allowed)} stated exceptions, no second spellings"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
