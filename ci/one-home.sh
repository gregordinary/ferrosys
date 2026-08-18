#!/usr/bin/env bash
# One home per concept: fail when a shared primitive is spelled out a second time.
#
# The rules and the reasoning are in ci/one-home.txt; the scanner is ci/one-home.py, which
# is Python because whether a *test* may open-code a rule depends on the rule, and no grep
# tells a test module from the code beside it.
#
#   ci/one-home.sh            check the tree against every rule
#   ci/one-home.sh --list     print the rules without running them
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/ci/one-home.py" "$@"
