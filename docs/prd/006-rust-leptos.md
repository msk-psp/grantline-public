# PRD 006 — Rust + Leptos migration

Decision: **accepted, staged implementation** (2026-10-15). Supersedes the
unscheduled Dioxus proposal in [PRD 004](004-port-to-rust.md). The target is a
complete Rust backend and Leptos UI; Python remains the reference until parity
and live validation permit replacement. This is a distribution and maintenance
decision, not a claim that a language change removes network or SVG latency.

## R1 — Native core and approval playground {#R1}

Status: merged in PR #15; local checks and all six CI checks passed. Acceptance:

- Native Rust grant identity/canonicalization, privilege coverage and convergence
  decisions match the Python reference on shared fictional fixtures.
- Unread scopes never produce grants/revokes; unmanaged subjects and undeclared
  systems never produce revokes. S3 Write does not imply Read.
- An Axum server renders Leptos components with no Python child process. SSR
  HTML forms are sufficient here; WASM hydration is deliberately a later step.
- A loopback-only playground supports fictional requester/reviewer roles,
  simulated Slack inbox, approval/denial and a simulated code PR. Reject self
  approval, invalid tokens, stale plans and repeated decisions. No external
  credential, IAM, Slack or GitHub write adapter is configured in this stage.
- Rust tests, formatting, Clippy, Python differential checks, Python regression
  tests and a real browser exercise establish the boundary of completion.

The parity interface compares permission decisions, not diagnostic messages or
adapter commands. It is a test interface, not a replacement production plan CLI.
Playground identities and role switching provide no production authentication.
State is disposable, private to the process and erased when it exits.

## Remaining stages

| Stage | Implementation | Acceptance before promotion | Status |
|---|---|---|---|
| R2 | Typed config/intent, snapshots, findings, graph and offline plan CLI | Fixture decisions, diagnostics, PG/CH SQL previews, snapshot round trips and graph paths match Python; S3 commands/coalescing remain R3 | Implemented offline |
| R3 | PostgreSQL, ClickHouse and S3 native adapters, probes and writers | Existing regression cases ported; separately authorized live read/probe and reversible write validation per adapter | Pending |
| R4 | Production sessions/OIDC, durable approval store, Slack signatures/DMs, code writer and GitHub PRs | Requester binding, all approvers, callback replay, immutable plan and repo scope verified end to end; approval/PR/applied access reported separately | Pending |
| R5 | All console pages, Leptos hydration and interactive permission map | Repeated hover highlight/dimming, matrix scrolling, accessible dark mode, logs and four locales verified in browser | Pending |
| R6 | Release image, migration/rollback and operating guide | Reproducible native/WASM builds, upgrade of persisted state, image smoke tests and explicitly authorized rollout | Pending |

## R2 — Offline CLI and data contracts {#R2}

Status: implemented offline; verification commands below and current PR checks
record the boundary. The native CLI loads the existing TOML config and intent,
resolving paths against the config directory. PostgreSQL/ClickHouse fixtures
support observation, fact findings and native command previews. A Python JSONL
snapshot can supply observations for any configured instance, including S3.
Unimplemented adapters and unread files become explicit unread scopes; they
must never look like an empty service. A snapshot missing a configured system
also leaves that system unread. No environment credential is resolved in R2.

Acceptance: compare native intent loading, grant/revoke decisions, diagnostic
levels/entities, fixture SQL previews, snapshots and graph structure/routes
against Python. Snapshot import preserves source/grantor and unread subjects;
comparison distinguishes changed permissions from visibility changes. Saving
uses a private, non-overwriting JSONL file, retaining Python format compatibility.
Graph traversal must terminate on cycles and preserve distinct routes/bridges,
policy hops, node kinds and literal environment identifiers.

The default plan is read-only; snapshot writes are explicit. Snapshot import
reconstructs an observation for comparison, never restores IAM state. Native
PostgreSQL/ClickHouse connections, S3 IAM parsing and S3 document command
generation/coalescing are R3. A candidate without a supported command must say
so; identity/service grouping is display grouping, not execution coalescing.

R1 alone does not support production observation, apply, SSO, real Slack or real
PR creation. It does not replace the existing console. No release or production
rollout is authorized by this document. Add shared cases before changing semantics;
keep Python as a development-only oracle until all stages pass.

## Next action

Review R2, then implement R3: file-backed S3 IAM interpretation and document
commands/coalescing first, followed by native PostgreSQL/ClickHouse/S3 service
connections and separately authorized live verification. Each stage needs its
own reviewable change and acceptance evidence before advancing.

## R1 validation boundary

Local native checks: `cargo fmt --check`, Clippy with `-D warnings`, 8 Rust
tests (5 domain + 3 HTTP), and a locked native build passed. The differential
check passed 172 scenarios including 1,062 coverage pairs. Existing Python
regression tests passed 36/36; the map hover test and Ruff also passed.
The browser exercised requester switching, request creation, reviewer switching
and approval into a simulated PR, plus denial without a PR. No external Slack,
GitHub or IAM adapter ran. Full UI parity, production integration and performance
remain separate verification work. See the native guide for reproducible commands
and the PR checks for the current Linux result.

## R2 validation boundary

Native checks cover TOML path resolution and safe errors, missing providers,
read-only planning, SQL quoting/privilege validation, private snapshot collisions,
unknown scope/service comparisons, metadata and graph cycles/route limits.
The Python differential suite covers 174 plan/diagnostic/SQL cases, bundled
PG/CH fixtures, existing demo snapshots in both languages, history and four graph
scenarios including observer/environment declaration order. Comparison retains
source/grantor metadata and diagnostic entities; when several wider grants
cover one request, the incidental choice of a covering grant is not compared.

Run `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked` and `cargo build --locked` inside `rust/`, then both
`scripts/check_rust_parity.py` and `scripts/check_rust_core.py` from the root.
The existing Python suite and privacy gate still apply. Live service reads,
S3 policy coalescing, writes, production auth/Slack/GitHub, full console pages,
WASM, performance and production deployment are outside this verification.
