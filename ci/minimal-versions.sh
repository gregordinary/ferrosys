#!/usr/bin/env bash
# Check the workspace against the oldest release each direct dependency admits.
#
# A requirement's floor is a promise to every consumer: `serde = "1.0.229"` says any serde
# from 1.0.229 up builds this crate, and a consumer whose own lockfile already holds the
# floor is given exactly that release. Every other gate reads the lockfile, which moves
# forward with each `cargo update` while the floors stay where they were written — so code
# can come to use an item a floor's release does not have, and the whole suite stays green
# over a requirement no consumer can build against.
#
# This resolves each direct dependency of the workspace to the lowest version its
# requirement admits, with everything beneath them resolved to the newest as usual, and
# type-checks every target with every feature against that graph. Resolving that way is
# nightly-only (`-Z direct-minimal-versions`), so it runs under the nightly the public API
# gate pins. It works on a copy of the tree, so the committed lockfile is never the one
# rewritten.
#
#   ci/minimal-versions.sh        resolve to the floors and check the workspace there
set -euo pipefail

# The nightly CI installs for the public API gate. Override to use a different one.
NIGHTLY="${FERROSYS_API_NIGHTLY:-nightly}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="${CARGO_TARGET_DIR:-$root/target}/minimal-versions"
copy="$work/tree"

# A fresh copy every run, with modification times kept: cargo judges freshness by them, so
# an unchanged file in a rewritten copy is still an unchanged file, and a warm run rebuilds
# only what changed. The fuzz package is its own workspace and not a member of this one.
rm -rf "$copy"
mkdir -p "$copy"
tar -C "$root" --exclude=target --exclude=crates/ferrosys/fuzz \
    -cf - Cargo.toml Cargo.lock rust-toolchain.toml crates \
    | tar -C "$copy" -xpf -

cd "$copy"
cargo "+$NIGHTLY" update -Z direct-minimal-versions --quiet
CARGO_TARGET_DIR="$work/target" \
    cargo "+$NIGHTLY" check --workspace --all-features --all-targets --quiet
