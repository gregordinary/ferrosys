#!/usr/bin/env python3
"""Find two functions whose bodies are the same code written twice.

The companion to ci/one-home.py, and the other half of the same idea. That gate knows
what has been standardized and catches a *named* concept spelled out again. This one knows
nothing: it compares every function body in the tree against every other and reports the
pairs that are the same code, whatever the concept is called.

Which is what catches the case the rule table cannot — a concept nobody has extracted yet,
so nobody has written a rule for it. The two together are the census and the sweep.

  ci/duplicate-bodies.py                 report pairs over the floor
  ci/duplicate-bodies.py --bless         rewrite the accepted list from what is found now

Similarity, not equality. Code transcribed from one module to another is edited as it
lands — a different type, a different field, a different error — so the pair this is
looking for is rarely identical and an exact comparison finds almost none of them. Two
functions this crate had transcribed between its readers measured 89% and 37% alike; the
89% one is the copy, and the 37% one is two algorithms that resemble each other.

So bodies are compared as sets of overlapping token runs, and a pair over THRESHOLD is
reported. That number is a judgement: high enough that resembling each other is not
enough, low enough that renaming a few things while copying does not hide it.

A pair under MIN_STATEMENTS is not reported at all. Short bodies coincide for reasons that
are not copying, and a gate that cries about every two-line accessor is a gate somebody
turns off.

An accepted pair is one someone has looked at and written a reason for, in
ci/duplicate-bodies.txt. Same discipline as the allowlist next door: a pair with no reason
is not accepted, and an accepted pair that stops matching is reported so the reason cannot
outlive what it excused.
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ACCEPTED = ROOT / "ci" / "duplicate-bodies.txt"

# Below this, two bodies resembling each other says more about how short they are than
# about anything having been copied.
MIN_STATEMENTS = 6

# How alike two bodies must be to be reported, as a Jaccard ratio over their token runs.
#
# Calibrated against a pair this crate is known to have carried — `walk_children`,
# transcribed between the two readers and edited as it landed — which measures 0.66. Two
# algorithms that merely rhyme (`walk_with`, same pair of files) measure 0.41.
#
# There is no number that separates the two cleanly. The transcription at 0.66 sits *below*
# benign test pairs at 0.70 to 0.79, because two tests that set up the same fixture and
# assert different things about it really are that alike. So this is not a threshold gate;
# it is a pinned baseline, the way the public API snapshot is. The number goes low enough
# to catch a real copy, every pair under it is blessed once with a reason, and what fails
# afterwards is a pair that is *new*.
THRESHOLD = 0.60

# Tokens per shingle. Long enough that a run says something about the order of the code
# rather than about which tokens appear in it, short enough to survive a substitution
# every few tokens.
SHINGLE = 4


def shingles(body):
    """`body` as the set of overlapping token runs it contains.

    Identifiers are kept as they are. Two functions that do the same thing to differently
    named things are usually a shared *shape* rather than a copy, and erasing identifiers
    would report every pair of builders in the crate as duplicates of each other.
    """
    tokens = re.findall(r"\w+|[^\w\s]", re.sub(r"//.*", "", body))
    if len(tokens) < SHINGLE:
        return frozenset()
    return frozenset(
        tuple(tokens[i:i + SHINGLE]) for i in range(len(tokens) - SHINGLE + 1)
    )


def similarity(a, b):
    """How alike two shingle sets are, from 0 to 1."""
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def functions(path):
    """Every `fn` in `path` as (name, line, normalized body).

    Brace counting from the opening `{` of the signature. Good enough for this tree, whose
    functions are ordinary Rust: what it would get wrong is a brace inside a string or char
    literal in a signature, and a miscount there costs a missed pair rather than a wrong
    report.
    """
    # Comments are blanked rather than removed, so a hit still reports the line it is
    # really on. Doc comments especially: an example inside one is Rust that declares
    # functions, and a scanner reading those would compare a doctest's `fn main` against
    # every other doctest's.
    text = re.sub(r"//.*", "", path.read_text())
    out = []
    for m in re.finditer(r"\bfn\s+([a-z_][a-z0-9_]*)\s*[(<]", text):
        name = m.group(1)
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        # A `;` before the next `{` means a signature without a body: a trait's required
        # method, or an extern declaration.
        if ";" in text[m.end():brace]:
            continue
        depth, i = 0, brace
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[brace + 1:i]
        if body.count(";") < MIN_STATEMENTS:
            continue
        start = text[:m.start()].count("\n") + 1
        out.append((name, start, start + body.count("\n"), shingles(body)))
    return out


def load_accepted():
    """The pairs someone has looked at, keyed by the two `file::fn` names."""
    if not ACCEPTED.is_file():
        return {}
    pairs = {}
    for line in ACCEPTED.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) != 3:
            sys.exit(f"malformed accepted pair (needs two sites and a reason): {line}")
        a, b, reason = parts
        if not reason.strip():
            sys.exit(f"an accepted pair needs a reason: {line}")
        pairs[frozenset((a.strip(), b.strip()))] = reason.strip()
    return pairs


def main():
    bless = "--bless" in sys.argv[1:]
    accepted = load_accepted()

    sources = sorted(ROOT.glob("crates/*/src/**/*.rs"))
    if not sources:
        sys.exit("no sources found: the gate would pass by looking at nothing")
    bodies = []
    for path in sources:
        rel = path.relative_to(ROOT)
        for name, line, end, sh in functions(path):
            if sh:
                bodies.append((f"{rel}::{name}", line, end, sh, str(rel)))

    # An inverted index over shingles, so a body is only compared against the ones it
    # shares a run with. Comparing every body against every other is quadratic in a number
    # that grows with the crate, and nearly all of those pairs share nothing at all.
    index = defaultdict(list)
    for i, entry in enumerate(bodies):
        for run in entry[3]:
            index[run].append(i)

    candidates = set()
    for sites in index.values():
        # A run shared by very many bodies says nothing about any pair of them — it is
        # boilerplate, not a copy — and pairing them all up is what makes this quadratic.
        if len(sites) > 12:
            continue
        for i in range(len(sites)):
            for j in range(i + 1, len(sites)):
                candidates.add((sites[i], sites[j]))

    found = []
    for i, j in candidates:
        name_a, line_a, end_a, sh_a, file_a = bodies[i]
        name_b, line_b, end_b, sh_b, file_b = bodies[j]
        # A function declared inside another is not a copy of it: the outer body contains
        # the inner one, so the two are alike by construction.
        if file_a == file_b and (line_a <= line_b <= end_a or line_b <= line_a <= end_b):
            continue
        ratio = similarity(sh_a, sh_b)
        if ratio >= THRESHOLD:
            found.append(((name_a, line_a), (name_b, line_b), ratio))
    found.sort(key=lambda f: -f[2])

    if bless:
        lines = [
            "# Function bodies that are the same code twice, and why each one is allowed.",
            "#",
            "# Written by ci/duplicate-bodies.py --bless and edited by hand: blessing records",
            "# the pair, and a person writes what makes it not a copy. A pair whose reason is",
            "# 'generated' or 'trivial' is usually a pair that should have been extracted.",
            "#",
            "# format: <file::fn>|<file::fn>|<why this is two functions and not one>",
            "",
        ]
        for (a, _), (b, _), ratio in sorted(found, key=lambda f: (f[0][0], f[1][0])):
            key = frozenset((a, b))
            lines.append(f"{a}|{b}|{accepted.get(key, f'REASON NEEDED ({ratio:.0%} alike)')}")
        ACCEPTED.write_text("\n".join(lines) + "\n")
        print(f"blessed {len(found)} pairs into {ACCEPTED.relative_to(ROOT)}")
        if any(frozenset((a, b)) not in accepted for (a, _), (b, _), _ in found):
            print("Some carry REASON NEEDED. Write the reason, or extract the body.")
        return 0

    unexplained = [p for p in found if frozenset((p[0][0], p[1][0])) not in accepted]
    seen = {frozenset((a, b)) for (a, _), (b, _), _ in found}
    stale = [k for k in accepted if k not in seen]

    if unexplained:
        print("The same body is written twice.\n")
        for (a, la), (b, lb), ratio in unexplained:
            print(f"  {a}  (line {la})")
            print(f"  {b}  (line {lb})")
            print(f"      {ratio:.0%} alike")
            print("      extract it, or record the pair with its reason in")
            print("      ci/duplicate-bodies.txt\n")
        return 1

    if stale:
        print("A pair is recorded as accepted and is no longer a pair.\n")
        for key in stale:
            print("  " + "  and  ".join(sorted(key)))
        print("\nDelete the line: a reason kept for code that has moved on reads as a")
        print("live decision.")
        return 1

    print(
        f"duplicate bodies: {len(bodies)} bodies over {len(sources)} files, "
        f"{len(accepted)} accepted pairs, nothing written twice"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
