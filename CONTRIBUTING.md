# Contributing

Use Rust **1.99.0**, the matching wasm-bindgen CLI, Node for browser contract
checks and Python **3.11+** for verification scripts. Python is not an application
runtime and no editable package install is needed.

## Build and check

```bash
cargo +1.99.0 build --locked --manifest-path rust/Cargo.toml
cargo +1.99.0 fmt --manifest-path rust/Cargo.toml --all --check
cargo +1.99.0 clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings
cargo +1.99.0 test --manifest-path rust/Cargo.toml --locked --workspace
python3 tests/test_privacy_gate.py
python3 tests/test_native_distribution.py
python3 scripts/check_rust_parity.py
python3 scripts/check_rust_core.py
python3 scripts/check_rust_s3.py
```

Build the WASM bundle and run the browser/provider suites described in the
[Rust guide](rust/README.md#check-the-boundary). Provider scripts create disposable
Docker services; use fictional fixtures and never substitute production endpoints.
The [operations guide](docs/rust-operations.md) covers sessions, approvals, recovery
and deployment. `Dockerfile` is the native release build; `Dockerfile.rust` is a
compatibility symlink for existing build consumers. Generated `rust/pkg` and
`rust/target` are ignored.

## Test reference

Only the dependency closure of the offline differential suites remains under
[tests/reference](tests/reference/README.md). The scripts explicitly opt into that
import path. It has no web/CLI/approval application, does not resolve service
credentials, and is excluded from the image. Preserve the independent comparison
while extending native permission semantics.

## Source map

| Concern | Source |
|---|---|
| Grant identity, coverage and convergence | `rust/src/model.rs`, `rust/src/planner.rs` |
| Service catalogs, probes and writers | `rust/src/postgres/`, `rust/src/clickhouse/`, `rust/src/s3/` and their parent modules |
| Observation, snapshots and routes | `rust/src/engine.rs`, `rust/src/snapshot.rs`, `rust/src/graph.rs` |
| Native server, sessions and approval flow | `rust/src/console.rs`, `rust/src/auth.rs`, `rust/src/workflow.rs` |
| Leptos pages, map and four locales | `rust/ui/src/` |
| Shared icons and logo licenses | `rust/ui/assets/` |
| Requirements and recorded boundaries | `docs/prd/` |

## Local privacy checks

Enable the repository's hooks once per clone:

```bash
git config --local core.hooksPath .githooks
python3 scripts/privacy_gate.py --tracked
```

The `pre-commit` hook checks staged text and author/committer identities. The
`pre-push` hook checks outgoing commit messages, identities and changed text,
including intermediate commits that add then remove a value. These checks run
locally; GitHub Actions runs the distribution, native and image tests without a
privacy scan. Run `python3 tests/test_privacy_gate.py` locally when changing the
scanner or hooks.

Use a GitHub noreply author address. Keep real configuration, service credentials,
operational identities and patient data outside the repository. Hooks require
Python 3 and must be enabled in each clone; they do not replace review of binary
assets or PR descriptions.

Tests should reproduce a concrete mistake, and unread scopes must remain unknown.
The console is read-only by default. Native writes require explicit credentials,
a reviewed plan hash and the documented adapter scope. Add a PRD before major
workflow changes; narrow bug fixes belong with their regression check.

## Local approval playground

```bash
cargo +1.99.0 run --locked --manifest-path rust/Cargo.toml -- playground --port 8423
```

Open `http://127.0.0.1:8423/demo`. Requester/reviewer roles, the inbox and PR are
fictional, process-local and reset on restart. See the
[playground contract](rust/README.md#run-the-native-approval-playground).
