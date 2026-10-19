#!/usr/bin/env bash
# Build the browser WASM from the same lockfile as the SSR crate.
set -euo pipefail
cd "$(dirname "$0")/.."
expected="$(awk '/^name = "wasm-bindgen"$/ { found=1; next } found && /^version =/ { gsub(/"/, "", $3); print $3; exit }' rust/Cargo.lock)"
if [ "$(wasm-bindgen --version)" != "wasm-bindgen $expected" ]; then
  echo "Install wasm-bindgen-cli $expected using cargo install --locked --version $expected wasm-bindgen-cli" >&2
  exit 1
fi
cargo build --manifest-path rust/ui/Cargo.toml --target wasm32-unknown-unknown --no-default-features --features hydrate --release --locked
wasm-bindgen rust/target/wasm32-unknown-unknown/release/grantline_ui.wasm --out-dir rust/pkg --target web
