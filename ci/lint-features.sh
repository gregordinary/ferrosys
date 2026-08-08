#!/usr/bin/env bash
# Lint the library in every configuration a consumer can select.
#
# A reference that names a feature-gated item from code gated differently — a doc link, a
# `use`, a type in a signature — compiles wherever that feature happens to be on. Under
# `--all-features` nothing is ever off, so the deepest build is the one build that cannot
# catch this class at all. The same goes the other way: a value only one family constructs
# is dead code in a build carrying a different one, and `--all-features` sees it live.
#
# So the gate is a set of builds in which something selectable is absent. Each row below
# names what it is missing and what that catches.
#
#   ci/lint-features.sh          clippy and rustdoc over the whole matrix
#   ci/lint-features.sh --list   print the configurations without building
#
# `--all-features` is deliberately not a row: the workspace clippy and rustdoc gates
# already build it, and with `--all-targets` and every crate, which is more than this
# does. This covers what those two cannot reach.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 1

# Each entry is `label|flags`. The flags are the whole feature selection, so an empty one
# is the default — which is a configuration in its own right and the one most consumers
# compile.
CONFIGS=(
    "no family, no source, no sink|--no-default-features"
    "the default: ext alone|"
    "a family that is not the default one|--no-default-features --features fat"
    "the derives, no family to derive over|--no-default-features --features serde"
    "both ends of a tree, no family|--no-default-features --features tar,dir"
    "a family and a sink, no ext|--no-default-features --features fat,dir"
    "the default family, both ends|--features tar,dir"
)

if [ "${1:-}" = "--list" ]; then
    for row in "${CONFIGS[@]}"; do
        printf '  %-38s %s\n' "${row%%|*}" "${row#*|}"
    done
    exit 0
fi

status=0
for row in "${CONFIGS[@]}"; do
    label="${row%%|*}"
    flags="${row#*|}"
    printf '  %-38s ' "$label"
    log="$(mktemp)"
    # Word splitting is what turns the flag string into separate arguments.
    # shellcheck disable=SC2086
    if cargo clippy -p ferrosys --lib $flags -- -D warnings >"$log" 2>&1 &&
        # `--document-private-items` because most of the crate is private and a broken
        # link in a private item renders nowhere, so a run without it sees none of them.
        # shellcheck disable=SC2086
        RUSTDOCFLAGS="-D warnings" cargo doc -p ferrosys --no-deps \
            --document-private-items $flags >>"$log" 2>&1; then
        printf 'ok\n'
    else
        printf 'FAILED   (%s)\n' "${flags:-default features}"
        sed 's/^/      | /' "$log" | tail -30
        status=1
    fi
    rm -f "$log"
done

if [ "$status" != 0 ]; then
    cat >&2 <<'EOF'

The library does not lint clean in every configuration it offers. An item that resolves
under --all-features and not here is one a consumer selecting that configuration cannot
build against.
EOF
fi
exit "$status"
