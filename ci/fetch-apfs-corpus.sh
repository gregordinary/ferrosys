#!/usr/bin/env bash
# Fetch the APFS corpus the APFS foreign-image gate reads.
#
# APFS's oracle is macOS, so the gate's ground truth is what macOS made and what macOS
# reported about it, from GitHub's hosted macOS runners on macOS 14, 15, 26 and 27, by two
# probes of the public apfs-probes repository: ten containers per release from the `corpus`
# probe, each beside macOS's own listing of every volume in it, live and at each snapshot; and
# one image per stage of the eight scenes the `clonerefs` probe takes clones and their sources
# through, each beside what macOS read back of every file in it. A runner's macOS moves
# under its label and Apple's tools make different bytes from the same tree on every run, so
# the images themselves are the oracle: one release asset, pinned here by its sha256, fetched
# once and unpacked into a cache like the oracle tool tarballs.
#
# The asset holds macOS's output and macOS's listings, and nothing this crate wrote.
#
# Usage: fetch-apfs-corpus.sh [--from FILE] [PREFIX]
#   PREFIX defaults to $FERROSYS_APFS_CORPUS, else ~/.cache/ferrosys/apfs-corpus/<ver>.
#   --from FILE unpacks a copy of the asset already on this machine, held to the same sha256.
# On success the corpus is in PREFIX, one directory per macOS release.
set -euo pipefail

VERSION="2"
ASSET_SHA256="e079d784f21b3432b700c4e25928b31da8c651eec8f566350284a005984aa4f7"
URL="https://github.com/gregordinary/apfs-probes/releases/download/corpus-${VERSION}/apfs-corpus-${VERSION}.tar.xz"

# The query flags resolve the cache directory and the three values that *are* the pin, then
# exit. The gate asks for the directory this way rather than restating the version: a second
# copy of it is a second pin, and two pins drift.
default_prefix() { echo "${FERROSYS_APFS_CORPUS:-$HOME/.cache/ferrosys/apfs-corpus/$VERSION}"; }
case "${1:-}" in
    --print-prefix)  default_prefix; exit 0 ;;
    --print-version) echo "$VERSION"; exit 0 ;;
    --print-sha256)  echo "$ASSET_SHA256"; exit 0 ;;
    --print-url)     echo "$URL"; exit 0 ;;
esac

from=""
if [ "${1:-}" = "--from" ]; then
    from="${2:?--from needs a path to the asset}"
    shift 2
fi
PREFIX="${1:-$(default_prefix)}"

parent="$(dirname "$PREFIX")"
mkdir -p "$parent"

# One fetch at a time, where the host has flock: a second waits for the first, and then finds
# its corpus in place rather than unpacking a second one over it.
if command -v flock >/dev/null 2>&1; then
    exec 9>"$parent/.fetch.lock"
    flock 9
fi

# The marker is written last and names the asset's digest, so a cache is trusted only when an
# unpack of this exact asset ran to the end. A cancelled unpack leaves no marker, and a cache
# of another release leaves a marker that does not match.
MARKER="$PREFIX/.complete"
if [ -f "$MARKER" ] && [ "$(cat "$MARKER")" = "$ASSET_SHA256" ]; then
    echo "APFS corpus $VERSION already present at $PREFIX"
    exit 0
fi
# What is replaced is only ever a corpus: an empty directory, or one an earlier unpack marked.
if [ -e "$PREFIX" ] && [ ! -f "$MARKER" ] && [ -n "$(ls -A "$PREFIX" 2>/dev/null)" ]; then
    echo "$PREFIX holds something other than an APFS corpus; not replacing it" >&2
    exit 1
fi

work="$(mktemp -d "$parent/.fetch.XXXXXX")"
trap 'rm -rf "$work"' EXIT

if [ -n "$from" ]; then
    echo "Unpacking APFS corpus $VERSION from $from"
    cp "$from" "$work/asset.tar.xz"
else
    echo "Fetching APFS corpus $VERSION"
    curl -fsSL -o "$work/asset.tar.xz" "$URL"
fi
echo "$ASSET_SHA256  $work/asset.tar.xz" | sha256sum -c -

# Unpacked beside the cache and moved into place by two renames, the previous corpus aside and
# this one in, so PREFIX never holds part of either; the previous one goes with the work
# directory.
mkdir "$work/corpus"
tar -xJf "$work/asset.tar.xz" -C "$work/corpus" --no-same-owner
echo "$ASSET_SHA256" > "$work/corpus/.complete"
if [ -e "$PREFIX" ]; then
    mv "$PREFIX" "$work/previous"
fi
mv "$work/corpus" "$PREFIX"
echo "APFS corpus $VERSION at $PREFIX"
