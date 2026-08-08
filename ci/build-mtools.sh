#!/usr/bin/env bash
# Build the pinned mtools the FAT foreign-reader gates run against.
#
# `mkfs.fat` does not populate an image, so it cannot be the authority on directories,
# long names, or file contents. mtools is: it reads and writes a FAT image as a plain
# file, needing neither root nor a mount, which makes it this family's counterpart to
# `debugfs` in the ext tier — the second implementation that says what is actually in
# an image this crate wrote, and the one that puts a populated tree into an image this
# crate then has to read.
#
# Pinned for the same reason the checker is: what an oracle says has to mean the same
# thing next month, and a rolling package is free to change what it reports. The build
# is idempotent, so CI caches the prefix and rebuilds only when the pin changes.
#
# Usage: build-mtools.sh [PREFIX]
#   PREFIX defaults to $FERROSYS_MTOOLS_PREFIX, else ~/.cache/ferrosys/mtools/<ver>.
# On success the tools are in $PREFIX/bin; prepend that to PATH before the tests, and
# point MTOOLSRC at ci/mtools.conf so the host's own configuration cannot reach them.
set -euo pipefail

VERSION="4.0.49"
TARBALL_SHA256="10cd1111da87bf2400a380c1639a6cba8bfb937a24f9c51f5f88d393ae5f6f76"
URL="https://ftp.gnu.org/gnu/mtools/mtools-${VERSION}.tar.gz"

# Every tool a gate runs, so a cache is trusted only when all of them are present at
# the pinned version. All four are symbolic links to one binary that reads its own
# name, which is why the whole set either works or none of it does — the completeness
# check is against a partial *install*, not a partial build.
TOOLS=(mcopy mdir minfo mtype)

# The query flags resolve the install prefix and the three values that *are* the pin,
# then exit. They exist so another build derives the pin from this script rather than
# restating it: a second copy of the version or the checksum is a second pin, and two
# pins drift.
case "${1:-}" in
    --print-prefix)
        echo "${FERROSYS_MTOOLS_PREFIX:-$HOME/.cache/ferrosys/mtools/$VERSION}"
        exit 0
        ;;
    --print-version) echo "$VERSION"; exit 0 ;;
    --print-sha256)  echo "$TARBALL_SHA256"; exit 0 ;;
    --print-url)     echo "$URL"; exit 0 ;;
esac

PREFIX="${1:-${FERROSYS_MTOOLS_PREFIX:-$HOME/.cache/ferrosys/mtools/$VERSION}}"

# Caching fast path: the install is complete only when *every* tool reports the
# pinned version. A cancelled build that installed only some tools is not trusted.
complete=1
for t in "${TOOLS[@]}"; do
    if ! { [ -x "$PREFIX/bin/$t" ] \
           && "$PREFIX/bin/$t" --version 2>&1 | grep -qF "$t (GNU mtools) $VERSION"; }; then
        complete=0
        break
    fi
done
if [ "$complete" = 1 ]; then
    echo "mtools $VERSION already present at $PREFIX"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "Fetching mtools $VERSION"
curl -fsSL -o src.tar.gz "$URL"
echo "$TARBALL_SHA256  src.tar.gz" | sha256sum -c -

tar -xzf src.tar.gz
cd "mtools-$VERSION"

# The three disabled features are hardware this project has none of — an X11 password
# prompt, a daemon that talks to a physical floppy drive over a socket, and OS/2
# extended-density disks — and each would otherwise make the build depend on what the
# host happens to have installed.
./configure \
    --prefix="$PREFIX" \
    --without-x \
    --disable-floppyd \
    --disable-xdf >/dev/null
make -j"$(nproc)" >/dev/null

# `install-links` rather than `install`: it installs the one binary and the symbolic
# links that give it its names, and stops there. The full target also installs manual
# and info pages through `install-info`, which is a tool a minimal runner need not
# have — and a gate that fails because a documentation directory was missing has said
# nothing about FAT.
make install-links >/dev/null

echo "Installed to $PREFIX/bin:"
for t in "${TOOLS[@]}"; do
    printf '  %s\n' "$("$PREFIX/bin/$t" --version 2>&1 | head -1)"
done
