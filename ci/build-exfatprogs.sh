#!/usr/bin/env bash
# Build the pinned exfatprogs the exFAT host-tool gates run against.
#
# `mkfs.exfat` is the exFAT family's geometry baseline and `fsck.exfat` is its hard
# checker, so both decide whether an image this crate wrote is acceptable. A checker's
# strictness and a formatter's geometry defaults are version- and build-dependent, and a
# newer checker can reject an image an older one accepted — which would turn a distro
# upgrade into a phantom regression in this crate. CI builds one exact upstream release
# from a sha256-pinned source tarball with fixed configure flags rather than taking the
# runner's rolling package. The build is idempotent, so CI caches the prefix and rebuilds
# only when the pin changes.
#
# Usage: build-exfatprogs.sh [PREFIX]
#   PREFIX defaults to $FERROSYS_EXFATPROGS_PREFIX, else ~/.cache/ferrosys/exfatprogs/<ver>.
# On success the tools are in $PREFIX/sbin; prepend that to PATH before the tests.
set -euo pipefail

VERSION="1.4.2"
TARBALL_SHA256="a8cbb4a5f002d49bc60c093030b26f5f36d9716e133118bdb0c311d6a3909fdc"
URL="https://github.com/exfatprogs/exfatprogs/releases/download/${VERSION}/exfatprogs-${VERSION}.tar.gz"

# Every tool a gate runs, so a cache is trusted only when all of them are present at
# the pinned version. `tune.exfat` is what pins the one field `mkfs.exfat` takes from the
# clock, so that two formats at the same parameters compare byte for byte; `dump.exfat`
# reads a volume's geometry back without mounting it, which is what holds this crate's
# planner against the baseline's field by field; and `exfatlabel` reads a volume label the
# same way — each an independent opinion on something the formatter wrote.
TOOLS=(mkfs.exfat fsck.exfat tune.exfat dump.exfat exfatlabel)

# The query flags resolve the install prefix and the three values that *are* the pin,
# then exit. They exist so another build derives the pin from this script rather than
# restating it: a second copy of the version or the checksum is a second pin, and two
# pins drift.
case "${1:-}" in
    --print-prefix)
        echo "${FERROSYS_EXFATPROGS_PREFIX:-$HOME/.cache/ferrosys/exfatprogs/$VERSION}"
        exit 0
        ;;
    --print-version) echo "$VERSION"; exit 0 ;;
    --print-sha256)  echo "$TARBALL_SHA256"; exit 0 ;;
    --print-url)     echo "$URL"; exit 0 ;;
esac

PREFIX="${1:-${FERROSYS_EXFATPROGS_PREFIX:-$HOME/.cache/ferrosys/exfatprogs/$VERSION}}"

# What each tool answers its version with. Every binary in the suite takes `-V` and
# prints one line naming the *suite* and its release, so there is one marker for all of
# them rather than a probe table — and a banner cannot say which tool produced it.
# Running the tool is what establishes that it is there; the banner establishes only
# which release it came from.
#
# The first line of stdout, specifically. `mkfs.exfat` follows its version with the
# libblkid it linked against, which is the host's and not this pin's, and `fsck.exfat`
# writes a usage message to stderr and exits 16 because `-V` alone is not a complete
# command line for it.
MARKER="exfatprogs version : $VERSION ("
banner() { "$1" -V 2>/dev/null | head -1 || true; }

# Caching fast path: the install is complete only when *every* tool is present and from
# the pinned release. A cancelled build that installed only some tools is not trusted.
complete=1
for t in "${TOOLS[@]}"; do
    if ! { [ -x "$PREFIX/sbin/$t" ] && banner "$PREFIX/sbin/$t" | grep -qF "$MARKER"; }; then
        complete=0
        break
    fi
done
if [ "$complete" = 1 ]; then
    echo "exfatprogs $VERSION already present at $PREFIX"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "Fetching exfatprogs $VERSION"
curl -fsSL -o src.tar.gz "$URL"
echo "$TARBALL_SHA256  src.tar.gz" | sha256sum -c -

tar -xzf src.tar.gz
cd "exfatprogs-$VERSION"

# --disable-shared links the suite's own library into each binary, so an installed tool
# runs from a prefix on PATH alone and needs no library search path set beside it. It is
# part of the pin rather than a convenience: a tool that resolves `libexfat` at run time
# can resolve a *different* build of it than the one this script produced.
#
# libblkid is not optional here and there is no flag to drop it, which is the one part
# of this build the pin does not cover. It probes the destination for a filesystem
# signature and decides whether to demand `--force`; it reads nothing the gates compare
# and writes nothing at all, so what varies with it is which invocations are refused
# rather than which bytes come out. The gates format a fresh file every time and so
# never reach that path.
./configure \
    --prefix="$PREFIX" \
    --disable-shared >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null

echo "Installed to $PREFIX/sbin:"
for t in "${TOOLS[@]}"; do
    printf '  %s\n' "$(banner "$PREFIX/sbin/$t")"
done
