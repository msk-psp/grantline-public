#!/usr/bin/env bash
# Only lockfile registry crates belong in the public image, never unrelated cache entries.
set -euo pipefail
output="$1"
mkdir -p "$output"
awk '/^name = / { name=$3; gsub(/"/, "", name) } /^version = / { version=$3; gsub(/"/, "", version) } /^source = "registry\+/ { print name "-" version }' rust/Cargo.lock |
while IFS= read -r crate; do
  for source in "${CARGO_HOME:?}/registry/src/"index.crates.io-*/"$crate"; do
    [ -d "$source" ] || continue
    find "$source" -type f \( -iname 'license*' -o -iname 'copying*' -o -iname 'notice*' \) -exec cp --parents --target-directory="$output" {} +
  done
done
