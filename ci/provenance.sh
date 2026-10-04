#!/usr/bin/env bash
# No tracked file names another implementation's internals.
#
# The rules and the reasoning are in ci/provenance.txt; the scanner is ci/provenance.py,
# which is Python because whether an identifier is this crate's own or somebody else's
# routine depends on what the tree defines, and no grep knows that.
#
#   ci/provenance.sh            check every tracked file
#   ci/provenance.sh --list     print the rules without running them
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/ci/provenance.py" "$@"
