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
DOSFSTOOLS="4.2"
MTOOLS="4.0.49"
EXFATPROGS="1.4.2"
RELAN_EXFAT="1.4.0"
BTRFS_PROGS="7.1"
UUID="f0e17055-0000-4000-8000-000000000000"
FAKE_TIME="1700000000"

# The three targets the cross job builds, each with the flags that job passes it.
CROSS_TARGETS=(
    "x86_64-apple-darwin|--all-targets"
    "x86_64-pc-windows-msvc|"
    "i686-unknown-linux-gnu|--all-targets"
)

# The gate the host-policy run cannot judge. Mounting a filesystem needs a user namespace,
# and inside one this process is root — so GNU tar attempts a `chown` it cannot make. It is
# covered by the ordinary test gate, which runs unprivileged.
#
# Keep this list as short as the reason for each entry is real. A test skipped here is a
# test the only privileged run never sees, and the privileged path is exactly where the
# attribute and ownership gates have something to say.
NAMESPACE_ARTIFACTS=(
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

# The tests a tier must actually have run, from ci/test-floors.txt.
#
# "A gate that could not run is a failure" covers the gate that declined to start. It does
# not cover the one that started, selected nothing, and exited zero — which is what a PATH
# missing the directory an oracle installs into produces, and it prints as a pass. A floor
# is the difference between a tier that was invited and a tier that ran.
#
# The numbers are raised deliberately, the way the API snapshot is blessed: one that moves
# in a diff is read beside the change that moved it, and one that falls is the finding.
test_floor() {
    awk -F'|' -v k="$1" '
        /^[^#]/ && $1 == k { value = $2 + 0; found++ }
        END {
            # A key written twice would print two numbers, and the caller comparing them
            # with `-lt` would error and read the error as "not below floor" -- a floor
            # that silently stops holding. One key, one number, or no answer at all.
            if (found > 1) { exit 2 }
            if (!found) { exit 1 }
            print value
        }
    ' "$root/ci/test-floors.txt"
}

# Run a test tier, and hold it to its floor as well as to its exit status.
gate_tests() {
    local label="$1" key="$2"; shift 2
    local floor
    if ! floor="$(test_floor "$key")"; then
        local why="no floor recorded"
        [ "$?" = 2 ] && why="more than one floor recorded"
        printf '  %-44s FAILED  (%s for "%s")\n' "$label" "$why" "$key"
        failed+=("$label")
        return
    fi
    printf '  %-44s ' "$label"
    local log; log="$(mktemp)"
    if ! "$@" >"$log" 2>&1; then
        printf 'FAILED\n'
        failed+=("$label")
        sed 's/^/      | /' "$log" | tail -40
        rm -f "$log"
        return
    fi
    # Every summary line the run printed, counting what passed and what failed rather than
    # what was filtered out: the question is how many tests this tier executed.
    local ran
    ran="$(awk '/^test result:/ { n += $4 + $6 } END { print n + 0 }' "$log")"
    rm -f "$log"
    if [ "$ran" -lt "$floor" ]; then
        printf 'FAILED  (ran %s tests, floor is %s)\n' "$ran" "$floor"
        failed+=("$label — ran $ran tests against a floor of $floor")
        return
    fi
    printf 'ok  (%s tests)\n' "$ran"
    passed+=("$label")
}

have() { command -v "$1" >/dev/null 2>&1; }

# The foreign implementations the suite treats as ground truth, and how each says which
# version it is. There is no flag the five upstreams agree on — `e2fsprogs` answers `-V`,
# only `fatlabel` has `--version` among the dosfstools three, `mkfs.fat` ends its help
# with its banner, `fsck.fat` prints one only once it starts a check and so is pointed
# at a device it fails on, and every mtools name is one binary answering alike. Each
# entry is `name|marker|args`, where the marker is what the banner must contain.
#
# exfatprogs is the suite whose marker names no tool: every binary in it prints the same
# `exfatprogs version : ...` line, so the entries differ only in which name is run. That
# is still the check worth making — a partial install is a partial install, and each name
# a gate calls has to be there.
#
# `exfat-populate` is the one binary this project compiles rather than installs, and what
# it reports is the relan/exfat release it was linked against — the pin that decides what
# the volumes it fills look like.
#
# btrfs-progs names the tool ahead of the suite everywhere but in the multiplexer, which
# is the suite. It is also the one suite whose banner *ends* at the version, so the marker
# carries the line break after it — upstream ships point releases beside their parents,
# and a bare `v7.1` is a prefix of `v7.1.1`. And its corruptor is the one entry here whose
# marker is not a version at all: `btrfs-corrupt-block` prints none anywhere, so what this
# establishes is that the name runs and is the right program, and what holds it to the pin
# is the directory it resolves to — which the tier asserts against the baseline's.
BTRFS_MARK="btrfs-progs v$BTRFS_PROGS"$'\n'
HOST_TOOLS=(
    "e2fsck|e2fsck $E2FSPROGS |-V"
    "mke2fs|mke2fs $E2FSPROGS |-V"
    "dumpe2fs|dumpe2fs $E2FSPROGS |-V"
    "resize2fs|resize2fs $E2FSPROGS |-V"
    "debugfs|debugfs $E2FSPROGS |-V"
    "mkfs.fat|mkfs.fat $DOSFSTOOLS (|--help"
    "fsck.fat|fsck.fat $DOSFSTOOLS (|-n /dev/null"
    "fatlabel|fatlabel $DOSFSTOOLS (|--version"
    "mcopy|mcopy (GNU mtools) $MTOOLS|--version"
    "mdir|mdir (GNU mtools) $MTOOLS|--version"
    "minfo|minfo (GNU mtools) $MTOOLS|--version"
    "mtype|mtype (GNU mtools) $MTOOLS|--version"
    "mkfs.exfat|exfatprogs version : $EXFATPROGS (|-V"
    "fsck.exfat|exfatprogs version : $EXFATPROGS (|-V"
    "tune.exfat|exfatprogs version : $EXFATPROGS (|-V"
    "dump.exfat|exfatprogs version : $EXFATPROGS (|-V"
    "exfatlabel|exfatprogs version : $EXFATPROGS (|-V"
    "exfat-populate|exfat-populate (relan/exfat) $RELAN_EXFAT|--version"
    "mkfs.btrfs|mkfs.btrfs, part of $BTRFS_MARK|--version"
    "btrfs|$BTRFS_MARK|--version"
    "btrfstune|btrfstune, part of $BTRFS_MARK|--version"
    "btrfs-image|btrfs-image, part of $BTRFS_MARK|--version"
    "btrfs-corrupt-block|usage: btrfs-corrupt-block|--help"
)

# Why the host-tool suite cannot run, or nothing and success when it can. The suite
# itself asserts rather than skips under FERROSYS_REQUIRE_HOST_TOOLS, so running it
# without one of these does not report a gap — it reports a failure that reads like a
# broken gate. This is what turns that into the honest answer.
missing_host_tool() {
    local entry name marker args banner
    for entry in "${HOST_TOOLS[@]}"; do
        name="${entry%%|*}"
        marker="${entry#*|}" ; marker="${marker%%|*}"
        args="${entry##*|}"
        if ! have "$name"; then
            echo "$name not on PATH"
            return 1
        fi
        # Captured rather than piped into `grep`, because `pipefail` is on and two of
        # these probes exit non-zero by design: the pipeline's status would be the
        # tool's, not the match's, and every such tool would read as a mismatch.
        # Unquoted on purpose: `fsck.fat`'s probe is two arguments.
        # shellcheck disable=SC2086
        banner="$("$name" $args 2>&1 || true)"
        case "$banner" in
            *"$marker"*) ;;
            *) echo "the $name on PATH does not report the version the gates pin"
               return 1 ;;
        esac
    done
    # Both halves of the `attr` package. The archive round-trip gate reads an extended
    # attribute back with `getfattr`, and the btrfs tier puts one on a source tree with
    # `setfattr` before asking the baseline to carry it into an image.
    local attr
    for attr in getfattr setfattr; do
        if ! have "$attr"; then
            echo "$attr not on PATH — install attr"
            return 1
        fi
    done
    return 0
}

# Every step in the workflow, and how this script covers it. A step named there and
# absent here, or named here and gone from there, fails: the mirror rots silently
# otherwise, which is the failure this script exists to prevent. Only `ci.yml` is pinned;
# the docs workflow publishes a site rather than gating a push.
#
# The mirror is checked in both directions. A workflow step must be accounted for by a
# gate this run *registered* -- not merely by an entry in a list, because a list entry
# outlives the gate it names, and a `gate` call deleted from below would otherwise leave
# parity green over a mirror that no longer holds.
parity() {
    local labels; labels="$(mktemp)"
    printf '%s\n' "${passed[@]:-}" "${failed[@]:-}" "${skipped[@]:-}" > "$labels"
    local status=0
    python3 - "$root/.github/workflows/ci.yml" "$labels" <<'PY' || status=$?
import re, sys

# Steps deliberately not mirrored, and why. Everything else must be a gate above.
NOT_APPLICABLE = {
    "Toolchain": "rust-toolchain.toml pins the local channel already",
    "Toolchain and target": "the cross gates install their own targets",
    "Install the pinned nightly for rustdoc JSON": "the public API gate installs it",
    "Install MSRV toolchain": "the MSRV gate installs it",
    "Install mdbook": "the book gate requires mdbook on PATH",
    "Install cargo-deny": "the dependency gate requires cargo-deny on PATH",
    "Install the distribution packages the gates and the oracle builds need":
        "getfattr is required on PATH, and the oracles are asserted rather than built",
    "Build e2fsprogs, put it on PATH, pin its config, assert the version":
        "the version already on PATH is asserted rather than built",
    "Build dosfstools and mtools, put them on PATH, assert the versions":
        "the versions already on PATH are asserted rather than built",
    "Build exfatprogs, put it on PATH, assert the version":
        "the version already on PATH is asserted rather than built",
    "Build the exFAT populator, put it on PATH, assert the version":
        "the version already on PATH is asserted rather than built",
    "Build btrfs-progs, put it on PATH, assert the version":
        "the version already on PATH is asserted rather than built",
}

# Each workflow step, and the gate here that mirrors it -- by the label that gate
# registers, matched as a prefix so a label carrying a count or a target still names one
# gate. The value is what makes this a mirror rather than a list: the label has to have
# been registered by this run.
MIRRORED = {
    "Format": "fmt",
    "Clippy": "clippy",
    "Test": "test (workspace, host tools)",
    "Library lints clean in every configuration it offers":
        "lib lints clean in every configuration",
    "One home per concept": "one home per concept",
    "No body written twice": "no body written twice",
    "Every page that names a family names all of them":
        "every page that names a family names all of them",
    "The guide asks for the version the crate is":
        "the guide asks for the version the crate is",
    "Base library builds and passes its tests without the archive source":
        "base lib without the archive source",
    "Library builds and passes its tests with FAT as the only family":
        "lib with FAT as the only family",
    "Library builds and passes its tests with a family and no ext":
        "lib with a family, a source, and a sink, and no ext",
    "Library builds and passes its tests with exFAT as the only family":
        "lib with exFAT as the only family",
    "Library builds and passes its tests with btrfs as the only family":
        "lib with the newest family as the only one",
    "Library builds and passes its tests with btrfs and every decoder":
        "lib with that family and every decoder",
    "Fuzz targets still type-check": "fuzz targets type-check",
    "Fuzz seeds are still readable images": "fuzz seeds are readable images",
    "Fuzz archive seed still parses, and reproduces from its generator":
        "fuzz archive seed parses and reproduces",
    "Rustdoc": "rustdoc (--document-private-items)",
    "Check": "cross: ",
    "Public API matches its snapshot": "public API matches its snapshot",
    "cargo check on MSRV": "cargo +",
    "Build crate": "book: build the crate it links against",
    "Build book": "book: mdbook build",
    "Test guide examples against the crate": "book: guide examples against the crate",
    "Dependencies carry no known advisory, and no license this crate cannot grant":
        "advisories, licenses, sources",
}

# The actions the workflow runs. An action's body is somebody else's script, so a new
# one is a new thing running on the runner that nothing here has read -- it is
# acknowledged rather than passed over.
ACTIONS = {"actions/checkout", "actions/cache"}

steps, unnamed, actions, name = [], 0, set(), None
for line in open(sys.argv[1]):
    # A step begins at `- name:`, `- run:`, or `- uses:`; a continuation line carries
    # the same keys without the dash.
    if (m := re.match(r"^\s+-?\s*name:\s*(.+?)\s*$", line)):
        name = m.group(1)
    elif (m := re.match(r"^\s+-?\s*uses:\s*([^@\s]+)", line)):
        actions.add(m.group(1))
        name = None
    elif re.match(r"^\s+-?\s*run:", line):
        # A `run:` the parser cannot attribute to a name is a command in the workflow
        # this mirror cannot see, which is exactly what it must not pass over.
        if name is None:
            unnamed += 1
        else:
            steps.append(name)
            name = None

registered = [l.split(" — ")[0] for l in open(sys.argv[2]).read().splitlines() if l]

# By name rather than by occurrence: a step name repeats across jobs — every job
# begins with a toolchain step — and what is being accounted for is the command, not
# how many runners happen to invoke it.
seen = set(steps)
known = set(MIRRORED) | set(NOT_APPLICABLE)
print(f"    distinct run: steps in ci.yml ... {len(seen)}")
print(f"    mirrored here ................... {len(set(MIRRORED) & seen)}")
print(f"    not applicable locally .......... {len(set(NOT_APPLICABLE) & seen)}")

ok = True
if unnamed:
    print(f"    UNNAMED: {unnamed} run: step(s) in ci.yml carry no name to account for")
    ok = False
for a in sorted(actions - ACTIONS):
    print(f"    UNKNOWN ACTION: ci.yml runs {a!r}, which nothing here has accounted for")
    ok = False
for s in sorted(seen - known):
    print(f"    UNCOVERED: ci.yml runs {s!r}; preflight does not mirror it")
    ok = False
for s in sorted(known - seen):
    print(f"    STALE: preflight names {s!r}; ci.yml no longer runs it")
    ok = False
for step, label in sorted(MIRRORED.items()):
    if step in seen and not any(r.startswith(label) for r in registered):
        print(f"    UNMIRRORED: {step!r} is claimed by a gate {label!r} this run never registered")
        ok = False
sys.exit(0 if ok else 1)
PY
    rm -f "$labels"
    return $status
}

# The dependency graph, judged against deny.toml: known advisories, the licenses the
# crate's own dual grant depends on, and where the crates came from.
#
# Two invocations, because the fuzz package declares its own `[workspace]` and a check
# rooted here never reaches its graph. Both read the one config. The flag suppresses the
# report that one config's entries do not all match one graph — the fuzz package's
# license exception is unmatched here, and this workspace's allowances are unmatched
# there, and neither is stale.
deny_check() {
    cargo deny check --allow license-exception-not-encountered \
        && cargo deny --manifest-path crates/ferrosys/fuzz/Cargo.toml --config deny.toml \
            check --allow license-exception-not-encountered
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

  check       fmt, clippy, the library linted in every configuration it offers, the three
              consistency gates — one home per concept, no body written twice, and every
              page that names a family naming all of them — the workspace suite, the
              base library without the archive source, the library
              with FAT as its only family and again with exFAT as its only family, three
              fuzz gates, and rustdoc over private items
  deps        cargo deny over this workspace and the fuzz package: advisories,
              licenses, and sources, against deny.toml
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
gate "lib lints clean in every configuration" ci/lint-features.sh
gate "one home per concept" ci/one-home.sh
gate "no body written twice" ci/duplicate-bodies.sh
gate "every page that names a family names all of them" ci/family-coverage.sh
gate "the guide asks for the version the crate is" ci/book-version.sh

if ! host_tools_reason="$(missing_host_tool)"; then
    skip "test (workspace, host tools)" "$host_tools_reason"
else
    gate_tests "test (workspace, host tools)" workspace \
        cargo test --workspace --all-features --profile ci --no-fail-fast
fi

gate_tests "base lib without the archive source" base-lib \
    cargo test -p ferrosys --no-default-features --lib
gate_tests "lib with FAT as the only family" fat-only \
    cargo test -p ferrosys --no-default-features --features fat --lib
gate_tests "lib with a family, a source, and a sink, and no ext" fat-dir \
    cargo test -p ferrosys --no-default-features --features fat,dir --lib
gate_tests "lib with exFAT as the only family" exfat-only \
    cargo test -p ferrosys --no-default-features --features exfat --lib
gate_tests "lib with the newest family as the only one" btrfs-only \
    cargo test -p ferrosys --no-default-features --features btrfs --lib
# The same family with the three decoders, which is the only configuration where a
# compressed extent is undone rather than declined. Both rows are run: the one above is what
# a build without them refuses, and this is what a build with them reads.
gate_tests "lib with that family and every decoder" btrfs-decoders \
    cargo test -p ferrosys --no-default-features --features btrfs,zlib,lzo,zstd --lib
gate "fuzz targets type-check" \
    cargo check --manifest-path crates/ferrosys/fuzz/Cargo.toml --all-targets

# `inspect` exits 4 on a readable-but-unsound image, which this accepts; anything else is
# a seed that fuzzes nothing.
#
# `inspect` renders ext images, so the `reader_*` directories go through it. Every seed of
# every family, these included, is also opened and walked in process by `tests/seam.rs`,
# which needs no command and knows no family.
gate "fuzz seeds are readable images" bash -c '
    set -e
    cargo build -q -p ferrosys-cli
    for seed in crates/ferrosys/fuzz/seeds/reader_*/*.img; do
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
echo "dependencies"
# Unlike every other gate here, this one can fail on a tree that has not changed: the
# advisory database moves on its own, and a graph that was clean at the last push is not
# thereby clean now. It needs the network for that reason.
if ! have cargo-deny; then
    skip "advisories, licenses, sources" "cargo-deny not on PATH"
else
    gate "advisories, licenses, sources" deny_check
fi

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

    # A directory of its own is not enough on its own, because this one persists between
    # runs and the crate's artifact name carries a hash over its dependency versions.
    # Change a version and the next run writes a second rlib beside the first rather than
    # replacing it, and the gate fails on the ambiguity with a diagnostic that reads like
    # a broken example. CI never sees it — a fresh checkout has nothing to collide with —
    # which is exactly why it has to be handled here. Only the library's own artifacts go;
    # its dependencies stay compiled, so this costs one crate's rebuild.
    rm -f "$book_target"/debug/deps/libferrosys-*.rlib \
          "$book_target"/debug/deps/libferrosys-*.rmeta

    # Every family the guide has examples for is named here: a family the crate it links
    # against does not carry makes its examples fail to compile, and marking them
    # uncompiled instead would let them rot.
    gate "book: build the crate it links against" \
        env CARGO_TARGET_DIR="$book_target" cargo build --features fat,exfat,btrfs
    gate "book: mdbook build" mdbook build book
    gate "book: guide examples against the crate" \
        mdbook test book -L "$book_target/debug/deps"
fi

echo
echo "host policy (a filesystem that records access times)"
if ! can_unshare; then
    skip "relatime run" "no private mount namespace available here"
elif ! relatime_reason="$(missing_host_tool)"; then
    skip "relatime run" "$relatime_reason"
else
    gate_tests "relatime run (${#NAMESPACE_ARTIFACTS[@]} namespace artifact skipped)" \
        relatime host_policy_run
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
