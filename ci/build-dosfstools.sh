#!/usr/bin/env bash
# Build the pinned dosfstools the FAT host-tool gates run against.
#
# `fsck.fat` is the FAT family's hard checker and `mkfs.fat --invariant` is its
# byte-equality baseline, so both decide whether an image this crate wrote is
# acceptable. A checker's strictness and a formatter's geometry defaults are
# version- and build-dependent, and a newer checker can reject an image an older one
# accepted — which would turn a distro upgrade into a phantom regression in this
# crate. CI builds one exact upstream release from a sha256-pinned source tarball
# with fixed configure flags rather than taking the runner's rolling package. The
# build is idempotent, so CI caches the prefix and rebuilds only when the pin changes.
#
# Usage: build-dosfstools.sh [PREFIX]
#   PREFIX defaults to $FERROSYS_DOSFSTOOLS_PREFIX, else ~/.cache/ferrosys/dosfstools/<ver>.
# On success the tools are in $PREFIX/sbin; prepend that to PATH before the tests.
set -euo pipefail

VERSION="4.2"
TARBALL_SHA256="64926eebf90092dca21b14259a5301b7b98e7b1943e8a201c7d726084809b527"
URL="https://github.com/dosfstools/dosfstools/releases/download/v${VERSION}/dosfstools-${VERSION}.tar.gz"

# Every tool a gate runs, so a cache is trusted only when all of them are present at
# the pinned version. `fatlabel` reads and writes a volume label without mounting,
# which is the independent check on the label the formatter writes.
TOOLS=(mkfs.fat fsck.fat fatlabel)

# The query flags resolve the install prefix and the three values that *are* the pin,
# then exit. They exist so another build derives the pin from this script rather than
# restating it: a second copy of the version or the checksum is a second pin, and two
# pins drift.
case "${1:-}" in
    --print-prefix)
        echo "${FERROSYS_DOSFSTOOLS_PREFIX:-$HOME/.cache/ferrosys/dosfstools/$VERSION}"
        exit 0
        ;;
    --print-version) echo "$VERSION"; exit 0 ;;
    --print-sha256)  echo "$TARBALL_SHA256"; exit 0 ;;
    --print-url)     echo "$URL"; exit 0 ;;
esac

PREFIX="${1:-${FERROSYS_DOSFSTOOLS_PREFIX:-$HOME/.cache/ferrosys/dosfstools/$VERSION}}"

# What each tool answers its version with. There is no flag the three agree on:
# `fatlabel` has `--version`, `mkfs.fat` prints its banner as the last line of
# `--help`, and `fsck.fat` prints one only when it starts a check — so it is given
# something to fail on, and the banner it prints first is the answer.
banner() {
    local tool="$1"
    case "$(basename "$tool")" in
        fatlabel) "$tool" --version 2>&1 ;;
        fsck.fat) "$tool" -n /dev/null 2>&1 || true ;;
        *)        "$tool" --help 2>&1 ;;
    esac
}

# Caching fast path: the install is complete only when *every* tool reports the
# pinned version. A cancelled build that installed only some tools is not trusted.
complete=1
for t in "${TOOLS[@]}"; do
    if ! { [ -x "$PREFIX/sbin/$t" ] && banner "$PREFIX/sbin/$t" | grep -qF "$t $VERSION ("; }; then
        complete=0
        break
    fi
done
if [ "$complete" = 1 ]; then
    echo "dosfstools $VERSION already present at $PREFIX"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "Fetching dosfstools $VERSION"
curl -fsSL -o src.tar.gz "$URL"
echo "$TARBALL_SHA256  src.tar.gz" | sha256sum -c -

tar -xzf src.tar.gz
cd "dosfstools-$VERSION"

# --without-iconv removes the one build-time dependency whose presence could vary
# between a runner and a developer's machine, so the pin covers the whole build and
# not just the source. It costs nothing the gates use: an image `mkfs.fat` writes at
# these parameters is byte-identical with and without it, verified against a build
# that has it.
#
# The Atari check stays off, matching the variant this project puts out of scope, and
# the compatibility symlinks (`mkdosfs`, `dosfsck`) stay off so `PATH` carries exactly
# the three names the gates call.
./configure \
    --prefix="$PREFIX" \
    --without-iconv >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null

echo "Installed to $PREFIX/sbin:"
for t in "${TOOLS[@]}"; do
    printf '  %s\n' "$(banner "$PREFIX/sbin/$t" | grep -F "$t $VERSION (" | head -1)"
done
