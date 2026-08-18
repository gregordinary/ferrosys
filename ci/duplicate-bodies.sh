#!/usr/bin/env bash
# Fail when a function body is the same code as another one, unless the pair is recorded.
#
# The baseline and the reasons are in ci/duplicate-bodies.txt; the scanner is
# ci/duplicate-bodies.py, which explains the calibration.
#
#   ci/duplicate-bodies.sh            check the tree against the baseline
#   ci/duplicate-bodies.sh --bless    rewrite the baseline from what is found now
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/ci/duplicate-bodies.py" "$@"
