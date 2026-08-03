#!/usr/bin/env bash
# Run every gate CI runs, before pushing.
#
# CI is the authority and it lives on a machine this one is not: a different filesystem,
# a different set of installed targets, and warnings promoted to errors across the whole
# build. A gate that is easy to run by hand is a gate that gets run by hand differently —
# with one flag missing, or one job forgotten — and the forgotten ones are exactly the
# ones that fail after a tag is cut.
#
#   ci/preflight.sh                run every gate; one that could not run is a failure
#   ci/preflight.sh --allow-skips  report what could not run and keep going
#   ci/preflight.sh --list         print the gates and what each one mirrors
#
# A gate that cannot run is a failure rather than a quiet pass, for the reason the test
# suite's own `available()` asserts rather than returning: a skipped gate has verified
# nothing, and a run that says so is worth more than one that looks green.
#
# Two things here are not in the workflow. The host-policy run covers the part of the gap
# that mirroring commands cannot close — a filesystem that records access times, which
# this machine may not have and the runner does. The workflow-parity check pins the mirror
# itself: a `run:` step added to CI that nothing here covers is a failure, the same way a
# `pub` item added to the crate is a failure against the API snapshot.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 1

# What the workflow pins, spelled out here rather than read out of it: these are inputs
# to this run, and the parity check below is what holds the two files together.
NIGHTLY="nightly-2026-07-09"
MSRV="1.88.0"
E2FSPROGS="1.47.0"
UUID="f0e17055-0000-4000-8000-000000000000"
FAKE_TIME="1700000000"

# The three targets the cross job builds, each with the flags that job passes it.
CROSS_TARGETS=(
    "x86_64-apple-darwin|--all-targets"
    "x86_64-pc-windows-msvc|"
    "i686-unknown-linux-gnu|--all-targets"
)

# The two gates the host-policy run cannot judge. Mounting a filesystem needs a user
# namespace, and inside one this process is root: a reserved extended attribute behaves
# differently for a root that no outside id maps to, and GNU tar attempts a `chown` it
# cannot make. Both are covered by the ordinary test gate, which runs unprivileged.
NAMESPACE_ARTIFACTS=(
    "a_reserved_attribute_is_refused_or_recorded_rather_than_lost_in_silence"
    "gnu_tar_reads_the_archive_we_write"
)

# A target directory of its own: these gates build with warnings promoted to errors, a
# different fingerprint from an ordinary `cargo build`, and sharing a directory with one
# would leave each rebuilding what the other just built.
export CARGO_TARGET_DIR="$root/target/preflight"
export FERROSYS_API_NIGHTLY="$NIGHTLY"
# What the runner asserts of the oracle, so a local run cannot pass by not consulting it.
export FERROSYS_REQUIRE_HOST_TOOLS=1

allow_skips=0
list_only=0
for arg in "$@"; do
    case "$arg" in
        --allow-skips) allow_skips=1 ;;
        --list) list_only=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

passed=() ; failed=() ; skipped=()

# Run one gate and report it. Output is discarded on success and shown on failure, where
# the tail of it is what a reader needs.
gate() {
    local label="$1"; shift
    printf '  %-44s ' "$label"
    local log; log="$(mktemp)"
    if "$@" >"$log" 2>&1; then
        printf 'ok\n'
        passed+=("$label")
    else
        printf 'FAILED\n'
        failed+=("$label")
        sed 's/^/      | /' "$log" | tail -40
    fi
    rm -f "$log"
}

# Record a gate that could not run, and why. Never silent: the reason is the point.
skip() {
    printf '  %-44s SKIPPED  (%s)\n' "$1" "$2"
    skipped+=("$1 — $2")
}

have() { command -v "$1" >/dev/null 2>&1; }

# Every `run:` step in the workflow, and how this script covers it. A step named there
# and absent here, or named here and gone from there, fails: the mirror rots silently
# otherwise, which is the failure this script exists to prevent. Only `ci.yml` is pinned;
# the docs workflow publishes a site rather than gating a push.
parity() {
    python3 - "$root/.github/workflows/ci.yml" <<'PY'
import re, sys

# Steps deliberately not mirrored, and why. Everything else must be a gate above.
NOT_APPLICABLE = {
    "Toolchain": "rust-toolchain.toml pins the local channel already",
    "Toolchain and target": "the cross gates install their own targets",
    "Install the pinned nightly for rustdoc JSON": "the public API gate installs it",
    "Install MSRV toolchain": "the MSRV gate installs it",
    "Install mdbook": "the book gate requires mdbook on PATH",
    "Install attr for the getfattr xattr gate": "getfattr is required on PATH",
    "Build e2fsprogs, put it on PATH, pin its config, assert the version":
        "the version already on PATH is asserted rather than built",
    "Build crate": "the book gate builds what it links against",
}
MIRRORED = {
    "Format", "Clippy", "Test",
    "Base library builds and passes its tests without the archive source",
    "Fuzz targets still type-check",
    "Fuzz seeds are still readable images",
    "Fuzz archive seed still parses, and reproduces from its generator",
    "Rustdoc", "Check", "Public API matches its snapshot", "cargo check on MSRV",
    "Build book", "Test guide examples against the crate",
}

steps, name = [], None
for line in open(sys.argv[1]):
    if (m := re.match(r"^\s+- name:\s*(.+?)\s*$", line)):
        name = m.group(1)
    elif re.match(r"^\s+-?\s*uses:", line):
        name = None
    elif name and re.match(r"^\s+run:", line):
        steps.append(name)
        name = None

# By name rather than by occurrence: a step name repeats across jobs — every job
# begins with a toolchain step — and what is being accounted for is the command, not
# how many runners happen to invoke it.
seen = set(steps)
known = MIRRORED | set(NOT_APPLICABLE)
print(f"    distinct run: steps in ci.yml ... {len(seen)}")
print(f"    mirrored here ................... {len(MIRRORED & seen)}")
print(f"    not applicable locally .......... {len(set(NOT_APPLICABLE) & seen)}")

ok = True
for s in seen - known:
    print(f"    UNCOVERED: ci.yml runs {s!r}; preflight does not mirror it")
    ok = False
for s in known - seen:
    print(f"    STALE: preflight names {s!r}; ci.yml no longer runs it")
    ok = False
sys.exit(0 if ok else 1)
PY
}

# The gap mirroring commands cannot close. A host that records access times moves a
# directory's the moment it is read, and a freshly written tree has its access time equal
# to its modification time — exactly the case `relatime` updates on. A machine mounted
# `noatime` therefore passes gates a runner fails, with nothing about the commands
# differing. So the suite runs again over a filesystem that keeps them.
host_policy_run() {
    local skips=()
    local name
    for name in "${NAMESPACE_ARTIFACTS[@]}"; do
        skips+=(--skip "$name")
    done
    PREFLIGHT_ROOT="$root" PREFLIGHT_TARGET="$CARGO_TARGET_DIR" \
    unshare -Urm --propagation private sh -c '
        set -e
        mkdir -p /tmp/preflight-atime
        mount -t tmpfs -o relatime,size=8G tmpfs /tmp/preflight-atime
        cd "$PREFLIGHT_ROOT"
        export TMPDIR=/tmp/preflight-atime
        export CARGO_TARGET_DIR="$PREFLIGHT_TARGET"
        exec "$@"
    ' _ cargo test --workspace --all-features --profile ci --no-fail-fast -- "${skips[@]}"
}

can_unshare() { have unshare && unshare -Urm --propagation private true 2>/dev/null; }

if [ "$list_only" = 1 ]; then
    cat <<EOF
gates preflight runs, mirroring .github/workflows/ci.yml:

  check       fmt, clippy, the workspace suite, the base library without the archive
              source, three fuzz gates, and rustdoc over private items
  cross       ${CROSS_TARGETS[0]%%|*}, ${CROSS_TARGETS[1]%%|*}, ${CROSS_TARGETS[2]%%|*}
  public-api  ci/public-api.sh under $NIGHTLY
  msrv        cargo +$MSRV check --all-targets --all-features
  book        mdbook build, and the guide's examples against the crate

and two gates the workflow cannot express:

  host policy the suite again over a relatime filesystem, where a host that records
              access times is what the runner is and this machine may not be
  parity      every run: step in ci.yml is accounted for here
EOF
    exit 0
fi

echo "preflight — every gate CI runs, plus the two it cannot express"
echo
echo "check"

# Warnings are errors across this job in the workflow, so they are here too — and scoped
# the same way. The MSRV check below is deliberately outside it: a lint that a newer
# compiler added is not a reason to fail a build-compatibility gate.
export RUSTFLAGS="-D warnings"

gate "fmt" cargo fmt --all --check
gate "clippy" cargo clippy --all-targets --all-features -- -D warnings

if ! have e2fsck; then
    skip "test (workspace, host tools)" "e2fsprogs not on PATH"
elif ! e2fsck -V 2>&1 | grep -q "$E2FSPROGS"; then
    skip "test (workspace, host tools)" "e2fsprogs on PATH is not $E2FSPROGS"
elif ! have getfattr; then
    skip "test (workspace, host tools)" "getfattr not on PATH — install attr"
else
    gate "test (workspace, host tools)" \
        cargo test --workspace --all-features --profile ci --no-fail-fast
fi

gate "base lib without the archive source" cargo test -p ferrosys --no-default-features --lib
gate "fuzz targets type-check" \
    cargo check --manifest-path crates/ferrosys/fuzz/Cargo.toml --all-targets

# `inspect` exits 4 on a readable-but-unsound image, which this accepts; anything else is
# a seed that fuzzes nothing.
gate "fuzz seeds are readable images" bash -c '
    set -e
    cargo build -q -p ferrosys-cli
    for seed in crates/ferrosys/fuzz/seeds/*/*.img; do
        status=0
        "$CARGO_TARGET_DIR/debug/ferrosys" inspect "$seed" >/dev/null 2>&1 || status=$?
        case $status in
            0|4) ;;
            *) echo "seed $seed is not a readable image (exit $status)"; exit 1 ;;
        esac
    done'

gate "fuzz archive seed parses and reproduces" bash -c '
    set -e
    # A scratch directory of its own, removed however this ends: `TMPDIR` is not
    # something a shell can count on being set, and a bare relative name would leave
    # the image in the tree.
    work="$(mktemp -d)"
    trap "rm -rf \"$work\"" EXIT
    for seed in crates/ferrosys/fuzz/seeds/archive_parse/*.tar; do
        "$CARGO_TARGET_DIR/debug/ferrosys" format --size 32M --from-tar "$seed" \
            --uuid "'"$UUID"'" --time "'"$FAKE_TIME"'" "$work/archive-seed.img" >/dev/null \
            || { echo "seed $seed no longer parses"; exit 1; }
    done
    python3 crates/ferrosys/fuzz/make-archive-seed.py "$work/regenerated.tar" >/dev/null
    cmp "$work/regenerated.tar" crates/ferrosys/fuzz/seeds/archive_parse/rootfs-pax.tar \
        || { echo "make-archive-seed.py no longer reproduces the seed"; exit 1; }'

gate "rustdoc (--document-private-items)" \
    env RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --document-private-items

unset RUSTFLAGS

echo
echo "cross"
for entry in "${CROSS_TARGETS[@]}"; do
    target="${entry%%|*}" ; flags="${entry#*|}"
    if ! rustup target list --installed 2>/dev/null | grep -qx "$target" \
       && ! rustup target add "$target" >/dev/null 2>&1; then
        skip "cross: $target" "the target could not be installed"
        continue
    fi
    # Unquoted on purpose: an empty flags entry must expand to no argument at all.
    # shellcheck disable=SC2086
    gate "cross: $target" cargo check --workspace --all-features --target "$target" $flags
done

echo
echo "public API"
if rustup toolchain list 2>/dev/null | grep -q "$NIGHTLY" \
   || rustup toolchain install "$NIGHTLY" --profile minimal --no-self-update >/dev/null 2>&1; then
    gate "public API matches its snapshot" ci/public-api.sh
else
    skip "public API matches its snapshot" "$NIGHTLY could not be installed"
fi

echo
echo "MSRV"
if rustup toolchain list 2>/dev/null | grep -q "^$MSRV" \
   || rustup toolchain install "$MSRV" --profile minimal --no-self-update >/dev/null 2>&1; then
    gate "cargo +$MSRV check" cargo "+$MSRV" check --all-targets --all-features
else
    skip "cargo +$MSRV check" "$MSRV could not be installed"
fi

echo
echo "book"
if ! have mdbook; then
    skip "mdbook build and guide examples" "mdbook not on PATH"
else
    # A deps directory holding more than one build of the crate makes rustdoc refuse the
    # guide's `extern crate ferrosys` as ambiguous, so the book links against a directory
    # of its own rather than whatever else this run has left behind.
    book_target="$root/target/preflight-book"
    gate "book: build the crate it links against" \
        env CARGO_TARGET_DIR="$book_target" cargo build
    gate "book: mdbook build" mdbook build book
    gate "book: guide examples against the crate" \
        mdbook test book -L "$book_target/debug/deps"
fi

echo
echo "host policy (a filesystem that records access times)"
if ! can_unshare; then
    skip "relatime run" "no private mount namespace available here"
elif ! have e2fsck; then
    skip "relatime run" "e2fsprogs not on PATH"
else
    gate "relatime run (2 namespace artifacts skipped)" host_policy_run
fi

echo
echo "workflow parity"
gate "every ci.yml run: step is accounted for" parity

echo
echo "───────────────────────────────────────────────────────────────────"
printf 'passed %d   failed %d   skipped %d\n' \
    "${#passed[@]}" "${#failed[@]}" "${#skipped[@]}"
for f in "${failed[@]:-}"; do [ -n "$f" ] && echo "  FAILED   $f"; done
for s in "${skipped[@]:-}"; do [ -n "$s" ] && echo "  SKIPPED  $s"; done

if [ "${#failed[@]}" -ne 0 ]; then
    echo
    echo "not ready to push."
    exit 1
fi
if [ "${#skipped[@]}" -ne 0 ] && [ "$allow_skips" = 0 ]; then
    echo
    echo "the gates above did not run, so they verified nothing. Install what they name,"
    echo "or re-run with --allow-skips to accept the gap deliberately."
    exit 1
fi
echo
echo "ready to push."
