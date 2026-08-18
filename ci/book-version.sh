#!/usr/bin/env bash
# The guide asks a reader to depend on the version the crate is.
#
# A `0.x` requirement resolves only within its minor, so `ferrosys = "0.4"` in the guide is
# a reader pinned to a release the crate has moved off the moment the minor changes. The
# two move together and nothing else makes them: the guide is prose, and prose does not
# fail to compile.
#
#   ci/book-version.sh    check every dependency line in the guide against Cargo.toml
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

want="$(sed -n 's/^version *= *"\([0-9]*\.[0-9]*\)\.[0-9]*".*/\1/p' "$root/Cargo.toml" | head -1)"
if [ -z "$want" ]; then
    echo "no version in Cargo.toml to hold the guide to" >&2
    exit 1
fi

wrong=0
while IFS=: read -r file line text; do
    case "$text" in
        *"\"$want\""*) ;;
        *)
            printf '  %s:%s asks for a version the crate is not (%s)\n' \
                "${file#"$root/"}" "$line" "$want" >&2
            printf '      %s\n' "$text" >&2
            wrong=1
            ;;
    esac
done < <(grep -rn 'ferrosys *= *\("[0-9]\|{ *version\)' "$root/book/src" || true)

if [ "$wrong" != 0 ]; then
    echo >&2
    echo "The guide names a version the crate is not. Both move at once." >&2
    exit 1
fi
echo "the guide asks for $want, which is what the crate is"
