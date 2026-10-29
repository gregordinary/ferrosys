#!/usr/bin/env bash
# Build `codec-reference`, the reference decoders and encoders the decoder differential holds
# the crate's LZVN, LZFSE and LZBITMAP decoders to.
#
# Apple's lzfse project is the reference implementation of LZVN and LZFSE, and libzbitmap is
# the decoder of LZBITMAP the crate's is read against. `ci/codec-reference.c` is the command
# line neither ships: one stream in, what the library made of it out. Every decision about a
# stream stays the library's.
#
# Both are pinned to a commit, since neither publishes release tarballs past it: lzfse's last
# commit is the pin, and libzbitmap's last commit is its pin. Each tarball is checked against
# its SHA-256 before it is unpacked.
#
# The build needs a C compiler and nothing else. It is idempotent, so CI caches the prefix
# and rebuilds only when the pin or the program changes.
#
# Usage: build-codec-reference.sh [PREFIX]
#   PREFIX defaults to $FERROSYS_CODEC_REFERENCE_PREFIX, else
#   ~/.cache/ferrosys/codec-reference/<ver>.
# On success the binary is in $PREFIX/bin; prepend that to PATH before the tests.
set -euo pipefail

LZFSE_REV="e634ca58b4821d9f3d560cdc6df5dec02ffc93fd"
LZFSE_SHA256="ca98aa6644d44500e3315858daa747ce15bd06d49e3edb12a5458e5525e8ebdb"
LZFSE_URL="https://github.com/lzfse/lzfse/archive/${LZFSE_REV}.tar.gz"
LIBZBITMAP_REV="574abeae25b25c3319b9b6a9225cc7464e08ae88"
LIBZBITMAP_SHA256="844f544b9770851ca6faddbc970f121950db4db380446346744854241ad6c64c"
LIBZBITMAP_URL="https://github.com/eafer/libzbitmap/archive/${LIBZBITMAP_REV}.tar.gz"

# The version is the two revisions, shortened: it names the cache directory and is what the
# binary's banner reports, which is the pin the gates assert.
VERSION="lzfse ${LZFSE_REV:0:12}, libzbitmap ${LIBZBITMAP_REV:0:12}"
DIR="${LZFSE_REV:0:12}-${LIBZBITMAP_REV:0:12}"

# The query flags resolve the install prefix and the pin, then exit, so the gates derive the
# pin from this script rather than restating it.
case "${1:-}" in
    --print-prefix)
        echo "${FERROSYS_CODEC_REFERENCE_PREFIX:-$HOME/.cache/ferrosys/codec-reference/$DIR}"
        exit 0
        ;;
    --print-version) echo "$VERSION"; exit 0 ;;
esac

PREFIX="${1:-${FERROSYS_CODEC_REFERENCE_PREFIX:-$HOME/.cache/ferrosys/codec-reference/$DIR}}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MARKER="codec-reference ($VERSION)"

# The program's source is part of what is installed, so an edit to it invalidates the cache
# the way a moved pin does.
if [ -x "$PREFIX/bin/codec-reference" ] \
    && [ ! "$here/codec-reference.c" -nt "$PREFIX/bin/codec-reference" ] \
    && "$PREFIX/bin/codec-reference" --version 2>/dev/null | grep -qF "$MARKER"; then
    echo "codec-reference against $VERSION already present at $PREFIX"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "Fetching lzfse ${LZFSE_REV:0:12} and libzbitmap ${LIBZBITMAP_REV:0:12}"
curl -fsSL -o lzfse.tar.gz "$LZFSE_URL"
curl -fsSL -o libzbitmap.tar.gz "$LIBZBITMAP_URL"
sha256sum -c - <<EOF
$LZFSE_SHA256  lzfse.tar.gz
$LIBZBITMAP_SHA256  libzbitmap.tar.gz
EOF
tar -xzf lzfse.tar.gz
tar -xzf libzbitmap.tar.gz
lzfse="lzfse-$LZFSE_REV/src"
zbm="libzbitmap-$LIBZBITMAP_REV"

mkdir -p "$PREFIX/bin"
# `-Wall -Wextra` without `-Werror` over this program alone, as `exfat-populate` is built:
# two runner architectures' compilers each add warnings of their own. The libraries are
# compiled with their own warnings off, and their headers are system headers to this program,
# since what they warn about is theirs.
objs=()
for f in "$lzfse"/lzfse_decode.c "$lzfse"/lzfse_decode_base.c "$lzfse"/lzfse_encode.c \
    "$lzfse"/lzfse_encode_base.c "$lzfse"/lzfse_fse.c "$lzfse"/lzvn_decode_base.c \
    "$lzfse"/lzvn_encode_base.c "$zbm"/libzbitmap.c; do
    o="$(basename "$f" .c).o"
    cc -O2 -w -DNDEBUG -I "$lzfse" -I "$zbm" -c "$f" -o "$o"
    objs+=("$o")
done
cc -O2 -Wall -Wextra \
    -DCODEC_REFERENCE_LZFSE="\"${LZFSE_REV:0:12}\"" \
    -DCODEC_REFERENCE_LIBZBITMAP="\"${LIBZBITMAP_REV:0:12}\"" \
    -isystem "$lzfse" -isystem "$zbm" \
    -o "$PREFIX/bin/codec-reference" \
    "$here/codec-reference.c" "${objs[@]}"

echo "Installed to $PREFIX/bin:"
printf '  %s\n' "$("$PREFIX/bin/codec-reference" --version)"
