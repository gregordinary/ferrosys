#!/usr/bin/env bash
# Fetch Apple's restore RAM disk, which the opt-in APFS RAM disk gate reads.
#
# The macOS 26.6.2 restore image carries a RAM disk as an IM4P whose payload is one plain APFS
# container: Apple's own, made by an APFS release older than any the corpus holds, with files
# Apple compressed itself. Apple serves the restore image from its CDN, so the RAM disk
# is fetched from there and kept in a cache. It is never committed or published, here or as a
# release asset.
#
# Only the one member is fetched, by HTTP range requests, and its payload is taken out of the
# wrapper (`apple-ramdisk.py`). Both are held to the digests pinned here.
#
# Usage: fetch-apple-ramdisk.sh [--from FILE] [PREFIX]
#   PREFIX defaults to $FERROSYS_APPLE_RAMDISK, else ~/.cache/ferrosys/apple-ramdisk/<build>.
#   --from FILE takes a copy of the member already on this machine, held to the same sha256.
# On success the container is PREFIX/ramdisk.apfs.
set -euo pipefail

BUILD="25G83"
URL="https://updates.cdn-apple.com/2026SummerFCS/fullrestores/140-75212/A2A24B94-1FC1-45A3-93F7-C51B02AF1F4D/UniversalMac_26.6.2_25G83_Restore.ipsw"
MEMBER="094-96989-093.dmg"
MEMBER_SHA256="934c21768e2fe036c33ba884bcce727d4e9f8e10c72733bf6d6f40da2dd99be8"
PAYLOAD_BYTES="211812352"
PAYLOAD_SHA256="ece2816da790ad6601dd67e20b1c444bd7780e2b70005da06776705f6b604a9c"

# The query flags resolve the cache and the values that are the pin, then exit, so a gate asks
# for the container's path rather than restating the build.
default_prefix() { echo "${FERROSYS_APPLE_RAMDISK:-$HOME/.cache/ferrosys/apple-ramdisk/$BUILD}"; }
case "${1:-}" in
    --print-prefix) default_prefix; exit 0 ;;
    --print-path)   echo "$(default_prefix)/ramdisk.apfs"; exit 0 ;;
    --print-sha256) echo "$PAYLOAD_SHA256"; exit 0 ;;
    --print-url)    echo "$URL"; exit 0 ;;
esac

from=""
if [ "${1:-}" = "--from" ]; then
    from="${2:?--from needs a path to the member}"
    shift 2
fi
PREFIX="${1:-$(default_prefix)}"
HERE="$(cd "$(dirname "$0")" && pwd)"

parent="$(dirname "$PREFIX")"
mkdir -p "$parent"
if command -v flock >/dev/null 2>&1; then
    exec 9>"$parent/.fetch.lock"
    flock 9
fi

# The marker is written last and names the container's digest, so a cache is trusted only when
# a fetch of this exact container ran to the end.
MARKER="$PREFIX/.complete"
if [ -f "$MARKER" ] && [ "$(cat "$MARKER")" = "$PAYLOAD_SHA256" ]; then
    echo "Apple's restore RAM disk $BUILD already present at $PREFIX"
    exit 0
fi
if [ -e "$PREFIX" ] && [ ! -f "$MARKER" ] && [ -n "$(ls -A "$PREFIX" 2>/dev/null)" ]; then
    echo "$PREFIX holds something other than Apple's restore RAM disk; not replacing it" >&2
    exit 1
fi

work="$(mktemp -d "$parent/.fetch.XXXXXX")"
trap 'rm -rf "$work"' EXIT

if [ -n "$from" ]; then
    echo "Taking Apple's restore RAM disk $BUILD from $from"
    cp "$from" "$work/member.im4p"
else
    echo "Fetching Apple's restore RAM disk $BUILD, $MEMBER of the restore image"
    python3 -I "$HERE/apple-ramdisk.py" member "$URL" "$MEMBER" "$work/member.im4p"
fi
echo "$MEMBER_SHA256  $work/member.im4p" | sha256sum -c -
mkdir "$work/ramdisk"
python3 -I "$HERE/apple-ramdisk.py" payload "$work/member.im4p" "$work/ramdisk/ramdisk.apfs"
echo "$PAYLOAD_SHA256  $work/ramdisk/ramdisk.apfs" | sha256sum -c -
[ "$(stat -c %s "$work/ramdisk/ramdisk.apfs")" = "$PAYLOAD_BYTES" ]
echo "$PAYLOAD_SHA256" > "$work/ramdisk/.complete"
if [ -e "$PREFIX" ]; then
    mv "$PREFIX" "$work/previous"
fi
mv "$work/ramdisk" "$PREFIX"
echo "Apple's restore RAM disk $BUILD at $PREFIX/ramdisk.apfs"
