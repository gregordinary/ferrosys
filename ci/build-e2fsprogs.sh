#!/usr/bin/env bash
# Build the pinned e2fsprogs the host-tool test gates run against.
#
# The host-tool gates (e2fsck, the dumpe2fs differential comparison, the resize2fs
# matrix) treat e2fsprogs as ground truth, and its geometry defaults and e2fsck
# strictness are version- and build-dependent. CI builds one exact upstream release
# from a sha256-pinned source tarball with fixed configure flags, rather than a
# rolling distro package that can re-baseline the gates silently. The build is
# idempotent, so CI caches the prefix and rebuilds only when the pin changes.
#
# Usage: build-e2fsprogs.sh [PREFIX]
#   PREFIX defaults to $FERROSYS_E2FSPROGS_PREFIX, else ~/.cache/ferrosys/e2fsprogs/<ver>.
# On success the tools are in $PREFIX/sbin; prepend that to PATH before the tests,
# and point MKE2FS_CONFIG at ci/mke2fs.conf so mke2fs reads the pinned defaults.
set -euo pipefail

VERSION="1.47.0"
TARBALL_SHA256="0b4fe723d779b0927fb83c9ae709bc7b40f66d7df36433bef143e41c54257084"
URL="https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v${VERSION}/e2fsprogs-${VERSION}.tar.gz"

# Every tool a gate runs, so a cache is trusted only when all of them are present at
# the pinned version. debugfs backs the fidelity gate alongside the others.
TOOLS=(mke2fs e2fsck dumpe2fs resize2fs debugfs)

# The query flags resolve the install prefix and the three values that *are* the pin,
# then exit. They exist so another build derives the pin from this script rather than
# restating it: a second copy of the version or the checksum is a second pin, and two
# pins drift.
case "${1:-}" in
    --print-prefix)
        echo "${FERROSYS_E2FSPROGS_PREFIX:-$HOME/.cache/ferrosys/e2fsprogs/$VERSION}"
        exit 0
        ;;
    --print-version) echo "$VERSION"; exit 0 ;;
    --print-sha256)  echo "$TARBALL_SHA256"; exit 0 ;;
    --print-url)     echo "$URL"; exit 0 ;;
esac

PREFIX="${1:-${FERROSYS_E2FSPROGS_PREFIX:-$HOME/.cache/ferrosys/e2fsprogs/$VERSION}}"

# Caching fast path: the install is complete only when *every* tool reports the
# pinned version. A cancelled build that installed only some tools is not trusted.
complete=1
for t in "${TOOLS[@]}"; do
    if ! { [ -x "$PREFIX/sbin/$t" ] && "$PREFIX/sbin/$t" -V 2>&1 | grep -qF "$t $VERSION "; }; then
        complete=0
        break
    fi
done
if [ "$complete" = 1 ]; then
    echo "e2fsprogs $VERSION already present at $PREFIX"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "Fetching e2fsprogs $VERSION"
curl -fsSL -o src.tar.gz "$URL"
echo "$TARBALL_SHA256  src.tar.gz" | sha256sum -c -

tar -xzf src.tar.gz
cd "e2fsprogs-$VERSION"

# --disable-nls keeps tool output locale-independent, so the gates read the same
# strings on every runner. The three e2scrub install dirs are set to `no` so
# `make install` stays inside the prefix -- they otherwise target system paths
# (/etc/cron.d, /usr/lib/udev, systemd units) and need root. The default static
# internal libs make the installed tools relocatable from the cache prefix with no
# runtime library path.
./configure \
    --prefix="$PREFIX" \
    --disable-nls \
    --with-udev-rules-dir=no \
    --with-crond-dir=no \
    --with-systemd-unit-dir=no >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null

echo "Installed to $PREFIX/sbin:"
for t in "${TOOLS[@]}"; do
    printf '  %s\n' "$("$PREFIX/sbin/$t" -V 2>&1 | head -1)"
done
