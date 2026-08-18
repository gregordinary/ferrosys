#!/usr/bin/env bash
# Pin the crate's public API surface.
#
# Renders every item reachable at a public path into a sorted text file and diffs it
# against the committed snapshot. The on-disk bytes have oracles; the API surface has
# this. A `pub` item that leaks through a glob re-export, a field that quietly
# disappears, an enum that loses `#[non_exhaustive]` — none of those fail a build, and
# all of them are breaking changes once the crate is published.
#
#   ci/public-api.sh              check the surface against the committed snapshot
#   ci/public-api.sh --bless      rewrite the snapshot from the current surface
#
# Blessing is the deliberate act: the diff belongs in the commit that changes the API,
# where a reviewer reads it beside the change that caused it.
#
# rustdoc's JSON output is nightly-only. The renderer asserts the schema version it was
# written against, so a nightly whose schema moved fails loudly rather than emitting a
# snapshot built from a misread document. CI pins the exact nightly for reproducibility;
# locally, whatever nightly is installed works as long as its schema matches.
set -euo pipefail

# The nightly CI installs. Override to use a different one; the schema assertion in
# public-api.py is what actually decides whether a toolchain is usable.
NIGHTLY="${FERROSYS_API_NIGHTLY:-nightly}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
renderer="$root/ci/public-api.py"
# A scratch target directory: rustdoc JSON and ordinary HTML docs share `target/doc`,
# and the two toolchains would overwrite each other's output there.
out="${CARGO_TARGET_DIR:-$root/target}/public-api"

bless=0
[ "${1:-}" = "--bless" ] && bless=1

# The seven configurations whose surfaces are pinned separately. `--all-features` is the
# whole crate; `--no-default-features` is the family-agnostic root, whose narrowness is a
# deliberate property rather than an accident of what happens to be gated; `default` is
# what `cargo add ferrosys` gives and so the surface most consumers pin against, and it is
# the only one that would notice an item quietly requiring a feature beyond the family it
# belongs to — present under `--all-features` and absent from every build without that
# feature; `fat` is a build carrying a family that is not the default one, where an item
# gated on the wrong family feature vanishes without any other configuration noticing; and
# `fat-dir` is that family with a source and a sink and still no ext, which is where an
# extraction surface quietly pinned to one family would show up as a type nobody can name;
# `exfat` is a family
# that arrived as a classifier before it had a reader, which is where an item gated on "a
# family" rather than on "a family with a reader" is either missing or uninhabited; and
# `btrfs` is the reverse of that — a family whose reader exists before it is reachable from
# the root, so it is where an item gated on "any family" and meaning "any family the root
# dispatches to" shows up as a surface a caller cannot get to.
config_flags() {
    case "$1" in
        all-features) echo "--all-features" ;;
        no-default-features) echo "--no-default-features" ;;
        default) echo "" ;;
        fat) echo "--no-default-features --features fat" ;;
        fat-dir) echo "--no-default-features --features fat,dir" ;;
        exfat) echo "--no-default-features --features exfat" ;;
        btrfs) echo "--no-default-features --features btrfs" ;;
        *) echo "unknown configuration: $1" >&2; exit 1 ;;
    esac
}

render() {
    local snapshot="$1"
    shift
    cargo "+$NIGHTLY" rustdoc -p ferrosys "$@" --target-dir "$out" -- \
        -Z unstable-options --output-format json >/dev/null
    python3 "$renderer" "$out/doc/ferrosys.json" > "$snapshot"
}

status=0
for config in all-features no-default-features default fat fat-dir exfat btrfs; do
    committed="$root/ci/public-api-$config.txt"
    actual="$out/public-api-$config.txt"
    mkdir -p "$out"
    # Word splitting is what turns the flag string into separate arguments.
    # shellcheck disable=SC2046
    render "$actual" $(config_flags "$config")

    if [ "$bless" = 1 ]; then
        cp "$actual" "$committed"
        echo "blessed $(basename "$committed") ($(wc -l < "$committed") items)"
        continue
    fi

    if ! diff -u "$committed" "$actual" \
        --label "committed/public-api-$config.txt" \
        --label "current/public-api-$config.txt"; then
        echo "::error::public API surface changed under --$config"
        status=1
    fi
done

if [ "$status" != 0 ]; then
    cat >&2 <<'EOF'

The public API no longer matches its snapshot. Every line above is a change a
consumer can see. If the change is intended, re-run with --bless and commit the
new snapshot alongside it.
EOF
fi
exit "$status"
