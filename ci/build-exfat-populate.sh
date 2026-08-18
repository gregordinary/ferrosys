#!/usr/bin/env bash
# Build `exfat-populate`, the one thing exfatprogs cannot do: put a tree into an exFAT
# volume.
#
# The exFAT foreign-image gate needs a populated volume this crate did not write.
# `mkfs.exfat` formats an empty one and `fsck.exfat` judges it; neither fills one, and
# this family has no mtools. relan/exfat's `libexfat` is the second complete
# implementation of the format, and `ci/exfat-populate.c` is the command line it does not
# ship — every on-disk decision stays the library's.
#
# Only `libexfat.a` is built from that release. The five tools beside it in the tarball —
# `mkexfatfs`, `exfatfsck`, `dumpexfat`, `exfatlabel`, `exfatattrib` — answer roles
# `exfatprogs` already fills for these gates, and a second tool in a role is a second
# opinion nothing reads. What this pin is for is the role nothing else fills.
#
# The build needs a C compiler and nothing else: no libfuse, and at run time no
# `/dev/fuse`, no `fusermount3`, no loop device, no kernel, and no root. That is why the
# library rather than the FUSE binary is what is pinned here — the mount adapter in the
# same project would put a device and a setuid helper between a gate and a runner.
#
# The build is idempotent, so CI caches the prefix and rebuilds only when the pin changes.
#
# Usage: build-exfat-populate.sh [PREFIX]
#   PREFIX defaults to $FERROSYS_EXFAT_POPULATE_PREFIX, else
#   ~/.cache/ferrosys/exfat-populate/<ver>.
# On success the binary is in $PREFIX/bin; prepend that to PATH before the tests.
set -euo pipefail

VERSION="1.4.0"
TARBALL_SHA256="241575fa93104406a47e79e53e4d907bae69886f11621f70a45276c62b75bf69"
URL="https://github.com/relan/exfat/releases/download/v${VERSION}/exfat-utils-${VERSION}.tar.gz"

# The query flags resolve the install prefix and the three values that *are* the pin,
# then exit. They exist so another build derives the pin from this script rather than
# restating it: a second copy of the version or the checksum is a second pin, and two
# pins drift.
case "${1:-}" in
    --print-prefix)
        echo "${FERROSYS_EXFAT_POPULATE_PREFIX:-$HOME/.cache/ferrosys/exfat-populate/$VERSION}"
        exit 0
        ;;
    --print-version) echo "$VERSION"; exit 0 ;;
    --print-sha256)  echo "$TARBALL_SHA256"; exit 0 ;;
    --print-url)     echo "$URL"; exit 0 ;;
esac

PREFIX="${1:-${FERROSYS_EXFAT_POPULATE_PREFIX:-$HOME/.cache/ferrosys/exfat-populate/$VERSION}}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The binary names the library release it was linked against, which is the pin the gates
# assert. It is passed in below rather than written into the source, so there is one copy
# of the version in this project rather than two that could disagree.
MARKER="exfat-populate (relan/exfat) $VERSION"

# The source is part of what is installed, so an edit to it invalidates the cache the way
# a moved pin does. Without this the fast path would keep handing back a binary built from
# a file that has since changed, and the version it reports would still be right — which is
# the shape of a stale artifact that reads as a fresh one. CI expresses the same rule by
# hashing this script and that source into its cache key.
if [ -x "$PREFIX/bin/exfat-populate" ] \
    && [ ! "$here/exfat-populate.c" -nt "$PREFIX/bin/exfat-populate" ] \
    && "$PREFIX/bin/exfat-populate" --version 2>/dev/null | grep -qF "$MARKER"; then
    echo "exfat-populate against relan/exfat $VERSION already present at $PREFIX"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "Fetching relan/exfat $VERSION"
curl -fsSL -o src.tar.gz "$URL"
echo "$TARBALL_SHA256  src.tar.gz" | sha256sum -c -

tar -xzf src.tar.gz
cd "exfat-utils-$VERSION"

# `configure` is run for `libexfat/config.h`, which carries the feature-test macros and
# the endianness the library's byte accessors are built on; the makefiles it writes for
# the five tools are then never used, since only the library directory is built.
#
# libublio is an optional dependency that exists for systems without block devices, and
# is absent here on purpose: with it, the library goes through a userspace block cache
# whose write-back is its own, and what a gate wants from this build is the library's
# plain pread/pwrite against a file.
./configure --prefix="$PREFIX" >/dev/null
make -C libexfat -j"$(nproc)" >/dev/null

mkdir -p "$PREFIX/bin"
# `-Wall -Wextra` without `-Werror`: this file is compiled by whatever compiler each of
# two runner architectures has, and a warning one of them adds is not a reason for a gate
# to be unbuildable. What a warning here is, is something to fix.
cc -O2 -Wall -Wextra \
    -DEXFAT_POPULATE_LIBEXFAT_VERSION="\"$VERSION\"" \
    -I libexfat \
    -o "$PREFIX/bin/exfat-populate" \
    "$here/exfat-populate.c" \
    libexfat/libexfat.a

echo "Installed to $PREFIX/bin:"
printf '  %s\n' "$("$PREFIX/bin/exfat-populate" --version)"
