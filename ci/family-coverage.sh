#!/usr/bin/env bash
# Every page that names one filesystem family names all of them.
#
# The surfaces, the spellings, and the reasoning are in ci/family-coverage.py.
#
#   ci/family-coverage.sh            check the pages against the families the crate defines
#   ci/family-coverage.sh --list     print the surfaces and the spellings without checking
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/ci/family-coverage.py" "$@"
