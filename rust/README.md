# Grantline — Rust + Leptos migration

Experimental **R1 + R2 foundation**, alongside the supported Python console.
This binary runs natively with no Python process or external credentials.
The target is a complete Rust backend and Leptos UI, delivered in
[six stages](../docs/prd/006-rust-leptos.md).

## Run the offline CLI

Install [Rust with rustup](https://rust-lang.org/tools/install/) and run from
the repository root:

```sh
cargo build --manifest-path rust/Cargo.toml --locked
rust/target/debug/grantline-rs -c grantline.toml plan
rust/target/debug/grantline-rs -c grantline.toml plan --json
rust/target/debug/grantline-rs -c examples/demo/grantline.toml graph --subject achen
rust/target/debug/grantline-rs -c examples/demo/grantline.toml history --since 2026-08-25
```

`plan` reads PostgreSQL/ClickHouse JSON fixtures and produces SQL previews,
diagnostic levels/entities and per-identity/service counts. No credentials are
resolved. Native service connections and S3 IAM parsing are R3, so the bundled
config's S3 provider is explicitly **unobserved**, not empty.
`plan --observed FILE.jsonl` imports a saved observation for any configured service; a service
missing from its header remains unread. Unsupported command generation is
reported per candidate. This CLI has no `apply` or `--write` command.

`-c` defaults to `grantline.toml`; no subcommand defaults to `plan`. Config and
intent paths resolve against the config directory, including `~/` paths.
Other legacy config sections may be present, but `env_file`, production auth,
notifications and writer settings are not activated by these offline commands.
`plan` and `graph` write no snapshots. Saving one is explicit:

```sh
rust/target/debug/grantline-rs -c grantline.toml snapshot --directory /tmp/grantline-rust-history --json
```

Snapshots use the Python JSONL format and preserve source, grantor and unread
subjects. Files do not overwrite previous runs (including same-second saves);
Unix files have mode 0600 and new directories 0700. Failure notes redact URI
passwords. Importing and saving retains the original observation time and user;
it never represents an old snapshot as a fresh service read or restores IAM.

`history` lists the configured `snapshots` directory. Compare files with
`--from A --to B` (names in that directory or absolute paths), or choose the run
at/before a date or `7d`, `2w`, `12h` with `--since`. Missing services/scopes
produce revealed/obscured entries, not false grants/revokes. Malformed records,
missing/duplicate headers and ambiguous timestamps are rejected explicitly.

`graph --json` exports edges, kinds, names, teams and literal environment labels.
Use `--subject NAME`, `--resource RESOURCE`, `--depth NODE` and `--limit N` to
inspect paths. Paths stop at cycles and report truncation at the output/work
budget. Graph service patterns use `glob` syntax; invalid patterns are rejected.
Normalized fixtures may add `"routes": [["demo-user", "group:demo", "member"]]` JSON
metadata for structural policy hops. Existing snapshots contain no observer
node-kind/policy-route metadata, and the output marks that limitation.

## Run the native approval playground

From the repository root:

```sh
cd rust
cargo run --locked -- demo
```

Open **http://127.0.0.1:8423/demo**. Choose **Use requester**, create a sample
request, then choose **Use reviewer** and open **Review request**. Approve to
see a simulated PR, or deny to finish without a PR. No GitHub login is needed.

The server binds only to IPv4 loopback. Host and POST Origin must match
`127.0.0.1:<port>` or `localhost:<port>`. Demo roles use a separate HttpOnly,
SameSite=Strict cookie. Any local visitor can switch these fictional roles;
this is not production authentication. The simulated inbox contains local
approval links; never use real credentials or shared hosting with this app.

State is memory-only (at most 100 requests) and resets on restart. The port can
be changed with `--port 8424`. The existing Python console and playground use
their own ports and are unaffected.

## What is implemented

- Grant identity excludes source/grantor metadata; S3 prefixes normalize before
  comparison. Instance names remain distinct even when their adapter kinds match.
- Service-specific privilege coverage; S3 Write does not imply Read, and a
  PostgreSQL database grant does not imply table privileges.
- Grant/revoke decisions respect managed subjects, declared systems and unread
  scopes. `parity` accepts development fixtures on stdin; it generates no commands.
- Native approval checks actor-bound tokens, independent reviewers, all required
  approvals, immutable plan content and terminal decisions.
- Leptos SSR components render accessible forms with escaped dynamic content;
  Axum handles the HTTP workflow. No browser JavaScript or WASM is needed for R1.
- R2 loads TOML intent, reads offline observations, explains drift and produces
  fixture SQL previews, interoperable snapshots and authorization graphs.

## What remains

Live observation, probes, native service adapters and writes, production authentication,
durable approvals, real Slack/GitHub writers, all existing console pages,
WASM map interactions, four-language UI and release images are later stages.
S3 policy document command generation/coalescing belongs to R3; R2's identity
groups are display summaries, not grouped executable commands. Approval, a
simulated PR and effective IAM access are separate states. This experimental app
never changes live access and is not ready to replace a production deployment.

## Check the boundary

From the repository root (Python is used only as a development oracle):

```sh
cargo fmt --manifest-path rust/Cargo.toml --check
cargo clippy --manifest-path rust/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path rust/Cargo.toml --locked
cargo build --manifest-path rust/Cargo.toml --locked
python3 scripts/check_rust_parity.py
python3 scripts/check_rust_core.py
```

The checks cover canonical grants, coverage, convergence actions, diagnostic
levels/entities, deterministic fixture explanations, PG/CH SQL previews,
Python/native snapshot round trips, history and graph structure/paths. Python's
arbitrary choice among equally covering grants is compared by the requested
atom, not the incidental wording naming one covering grant. Live observation,
S3 command coalescing, performance and production integration remain unverified.
