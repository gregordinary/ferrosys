#!/usr/bin/env bash
# Build the pinned btrfs-progs the btrfs host-tool gates run against.
#
# `mkfs.btrfs` is the btrfs family's baseline, `btrfs check` is its hard checker, and
# `btrfs inspect-internal dump-tree` is what renders an image item by item. All three
# decide whether an image this crate wrote is acceptable, or what an image it must read
# looks like. CI builds one exact upstream release from a sha256-pinned source tarball
# with fixed configure flags rather than taking the runner's rolling package. The build
# is idempotent, so CI caches the prefix and rebuilds only when the pin changes.
#
# The pin carries more weight in this family than in the others. ext4's on-disk defaults
# have been stable for a decade and FAT's are frozen by a specification nobody edits;
# btrfs moves its *defaults* between releases, and this pin is one of them — v6.19 turned
# `block-group-tree` on by default and says so in `mkfs.btrfs`'s own output. So what the
# gates compare against is a release, not a format, and the release is written here once.
#
# Usage: build-btrfs-progs.sh [PREFIX]
#   PREFIX defaults to $FERROSYS_BTRFS_PROGS_PREFIX, else ~/.cache/ferrosys/btrfs-progs/<ver>.
# On success the tools are in $PREFIX/bin; prepend that to PATH before the tests.
set -euo pipefail

VERSION="7.1"
TARBALL_SHA256="d1f55cc2971398c9142eaa79d203e63d586a3b4b867f956664a1d68322cd4e34"
URL="https://www.kernel.org/pub/linux/kernel/people/kdave/btrfs-progs/btrfs-progs-v${VERSION}.tar.xz"

# Every tool a gate runs, so a cache is trusted only when all of them are present at the
# pinned version. `btrfs` is the multiplexer behind `check`, `inspect-internal dump-tree`
# and `dump-super`, and `subvolume`; `mkfs.btrfs` is the baseline, including the `-r` form
# that fills an image from a directory; `btrfstune` is the suite's own answer to changing
# a built image's identity; `btrfs-image` produces the metadata-only dump the fixtures
# want; and `btrfs-corrupt-block` is what damages a structure so the checker can be
# watched rejecting it.
TOOLS=(mkfs.btrfs btrfs btrfstune btrfs-image btrfs-corrupt-block)

# The query flags resolve the install prefix and the three values that *are* the pin,
# then exit. They exist so another build derives the pin from this script rather than
# restating it: a second copy of the version or the checksum is a second pin, and two
# pins drift.
case "${1:-}" in
    --print-prefix)
        echo "${FERROSYS_BTRFS_PROGS_PREFIX:-$HOME/.cache/ferrosys/btrfs-progs/$VERSION}"
        exit 0
        ;;
    --print-version) echo "$VERSION"; exit 0 ;;
    --print-sha256)  echo "$TARBALL_SHA256"; exit 0 ;;
    --print-url)     echo "$URL"; exit 0 ;;
esac

PREFIX="${1:-${FERROSYS_BTRFS_PROGS_PREFIX:-$HOME/.cache/ferrosys/btrfs-progs/$VERSION}}"

# What each tool answers its version with. Four of the five take `--version` and name
# themselves ahead of the suite — `mkfs.btrfs, part of btrfs-progs v7.1` — except the
# multiplexer, which is the suite and prints `btrfs-progs v7.1` alone. The substring
# every one of them contains is therefore the suite and its release, which is what this
# marker is.
#
# `btrfs-corrupt-block` has no version flag at all and no banner carrying one. What holds
# it to the pin is where it comes from: it is installed below out of the same build tree
# as the four that do answer, and the gates check that it resolves to the same directory
# one of them does. That is a weaker check than a banner and it is named as one.
MARKER="btrfs-progs v$VERSION"
VERSIONED=(mkfs.btrfs btrfs btrfstune btrfs-image)
banner() { "$1" --version 2>/dev/null | head -1 || true; }

# The marker at the *end* of the line rather than anywhere in it. Upstream ships point
# releases beside their parents and `v7.1` is a prefix of `v7.1.1`, so a substring match
# accepts a release this is not pinned to. Every banner here ends at the version, which
# is what makes the anchor available.
pinned() { case "$(banner "$1")" in *"$MARKER") return 0 ;; *) return 1 ;; esac; }

# Caching fast path: the install is complete only when *every* tool is present, and every
# tool that can say so is from the pinned release. A cancelled build that installed only
# some tools is not trusted.
complete=1
for t in "${TOOLS[@]}"; do
    [ -x "$PREFIX/bin/$t" ] || { complete=0; break; }
done
if [ "$complete" = 1 ]; then
    for t in "${VERSIONED[@]}"; do
        pinned "$PREFIX/bin/$t" || { complete=0; break; }
    done
fi
if [ "$complete" = 1 ]; then
    echo "btrfs-progs $VERSION already present at $PREFIX"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "Fetching btrfs-progs $VERSION"
curl -fsSL -o src.tar.xz "$URL"
echo "$TARBALL_SHA256  src.tar.xz" | sha256sum -c -

tar -xf src.tar.xz
cd "btrfs-progs-v$VERSION"

# Every flag here removes something the host would otherwise decide.
#
#   --disable-zstd, --disable-lzo   Two compression libraries the suite links when it
#                                   finds them, so an identical tarball can produce tools
#                                   that differ by what the machine had installed. This
#                                   crate writes no compressed extent, and a gate that
#                                   never asks for one is a gate whose answer must not
#                                   depend on whether the library was there.
#   --disable-zoned                 The one option whose default is *detection* rather
#                                   than a value: configure reads the build machine's
#                                   kernel headers and switches itself on or off. A pin
#                                   with a detected component is not a pin.
#   --disable-libudev               Multipath device resolution, from a library whose
#                                   presence varies by distribution. The gates format
#                                   files, never devices.
#   --disable-convert               Drops the ext2 and reiserfs readers `btrfs-convert`
#                                   needs, and with them a dependency on another suite's
#                                   headers — the one this project already pins for a
#                                   different family and at a different version.
#   --disable-python                The language bindings, and the interpreter that
#                                   builds them.
#   --disable-documentation         The manual pages, and the documentation generator
#                                   that renders them.
#   --disable-backtrace             What a crashing tool prints, which comes from the C
#                                   library rather than from this tarball.
#   --disable-shared                Links the suite's own libraries into each binary, so
#                                   an installed tool runs from a prefix on PATH alone
#                                   and needs no library search path beside it. A tool
#                                   that resolves its library at run time can resolve a
#                                   *different* build of it than this script produced.
#   --with-crypto=builtin           The provider of the checksum algorithms — crc32c
#                                   among them, which is what every metadata block in
#                                   every image these gates read is checksummed with.
#                                   Left to its default it is still `builtin`; written
#                                   down it stays that way when the default moves.
#
# Three mandatory dependencies have no flag to drop them and are the part of this build
# the pin does not cover: libblkid, libuuid, and zlib. What varies with the first is
# which *invocations* are refused — it probes the destination for an existing filesystem
# signature and demands `--force` when it finds one — rather than which bytes come out,
# and the gates format a fresh file every time and so never reach that path. The second
# supplies the random UUIDs `mkfs.btrfs` generates, which no gate here compares against
# anything. The third is read only where a tool decompresses an extent, which is a thing
# no image these gates build contains.
#
# One detection has no flag either and is worth naming rather than leaving to be found:
# configure looks for `linux/fsverity.h` and reports `fsverity support: yes` when it is
# there. It reaches `btrfs receive` and the help banner's feature list, and nothing that
# formats, checks, or dumps — so what varies with it is a command no gate runs.
./configure \
    --prefix="$PREFIX" \
    --disable-zstd \
    --disable-lzo \
    --disable-zoned \
    --disable-libudev \
    --disable-convert \
    --disable-python \
    --disable-documentation \
    --disable-backtrace \
    --disable-shared \
    --with-crypto=builtin >/dev/null
make -j"$(nproc)" >/dev/null

# `udevdir=` empties the one install path this suite does not derive from its prefix.
# Left alone, `make install` writes two rules files into the *system's* udev directory —
# an absolute path outside PREFIX that a build needs root to create, which is the one
# thing this project exists not to need. Emptying the variable skips the block entirely.
make install udevdir= >/dev/null

# `btrfs-corrupt-block` is built by default and installed by nothing: upstream keeps it
# out of the install set because it exists to damage a filesystem. That is exactly the
# role the tier needs it for — a checker that has never been watched rejecting anything
# has not been calibrated — so it is installed here beside the tools that carry it there.
install -m755 btrfs-corrupt-block "$PREFIX/bin/btrfs-corrupt-block"

echo "Installed to $PREFIX/bin:"
for t in "${VERSIONED[@]}"; do
    printf '  %s\n' "$(banner "$PREFIX/bin/$t")"
done
printf '  %s (no version of its own; pinned by the prefix it came out of)\n' \
    "btrfs-corrupt-block"
