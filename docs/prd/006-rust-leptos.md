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
| R2 | Typed config/intent, snapshots, findings, graph and offline plan CLI | Fixture decisions, diagnostics, PG/CH SQL previews, snapshot round trips and graph paths match Python; S3 commands/coalescing remain R3 | Merged in PR #16 |
| R3 | PostgreSQL, ClickHouse and S3 native adapters, probes and writers | Existing regression cases ported; separately authorized live read/probe and reversible write validation per adapter | R3a merged; R3b ClickHouse reads implemented; other readers/probes/writers pending |
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

Review R3b's ClickHouse catalog reader, then implement the PostgreSQL reader
with isolated local adapter tests; S3 network readers follow. Probes/writers and separately
authorized production/staging verification follow. Each
review unit needs acceptance evidence before advancing; R3 is not yet complete.

## R3 — Native adapter migration {#R3}

Status: R3a merged in PR #17; R3b ClickHouse reads implemented.
The first review unit implements S3 file/dir
planes, effective policy observation, group/inline routes and identity-scoped
document previews. Plan commands remain previews; no IAM file, shared managed
policy or live service is changed. Existing Python regressions are the oracle.

Acceptance: preserve policy-over-native precedence, exact Deny subtraction,
literal prefix-listing capabilities, conservative unread scopes, cross-plane
identity drift and missing-policy diagnostics. Merge all previewed changes for
one identity into one final document. Directory-backed inherited policy changes
must be blocked rather than presented as per-user writes to a shared policy.
Malformed source documents must never look like an empty service; output must
not include credentials or read environment credentials. Native connections,
probes and actual writers require a subsequent review unit and separately
authorized live verification.

R3a adds one structured final document preview per identity, combining both
grant and revoke candidates. This is preview coalescing, not an implemented
writer. Credentials never enter document output. A simulated transformation is
re-evaluated and blocked unless it produces exactly the intended normalized
grant set; prefix-List writes and capability writes are unsupported. Original
policy documents are required, so imported snapshots cannot generate them.

Safety differences from the Python oracle: missing/incomplete policies obscure
discovery and prefix capabilities too; empty attached policies still shadow
native actions; malformed trees and conflicting policy route names stay unread;
cancelled allows do not leave identity-to-policy graph paths. Native action
revokes remove equivalent original `/*` spellings. These guards are tested
separately from unchanged Python semantics.

Validation: run the native checks and all three `scripts/check_rust_*.py` suites.
The S3 suite compares 27 fictional policy/action cases and two IAM-tree scenarios
against Python, with the documented conservative unknown-scope extension. Five
native S3 tests cover malformed/remote inputs, source immutability, credential
non-disclosure, merged documents, unrepresentable revokes, shared policies,
empty policy precedence, deny routes, cross-plane drift and snapshot boundaries.

### R3b — ClickHouse catalog observation

Implement opt-in `--live` observation for native ClickHouse adapters using only
the configured `url_env` read credential. Offline commands, snapshots imported
with `--observed`, admin credentials and all actual writers remain separate.
Queries are fixed catalog/visibility reads with bounded rows, bytes and time;
credentials travel in headers and redirects are refused. A failed query or
incomplete result makes the whole instance unread, rather than an empty set.

Preserve global/database/table scopes and user/role inheritance. Column grants,
partial revokes and wildcard prefixes that cannot be represented must obscure
affected subjects and role dependants. Require complete catalog visibility
before planning. Use isolated HTTP failure tests and a disposable local official
ClickHouse container to verify the actual SQL and read-only observer behavior.
Production/staging reads, probes, writes and PostgreSQL/S3 network adapters are
outside this review unit.

R3b uses header credentials, verified TLS, no redirects/environment proxy,
bounded named JSON rows and a per-instance total deadline. It requires global
SHOW ACCESS/SHOW DATABASES before catalog planning and never falls back to
`admin_url_env`. The server reader uses readonly=2, allowing query limits while
still rejecting writes. A missing/failed/truncated catalog query discards all
partial grants. Native ClickHouse type/kind must agree.

Role-to-role memberships are preserved. Column/partial/parameterized scopes
obscure the subject and transitive role dependants. SHOW GRANTS batches detect
prefix wildcards erased by the 26.6 catalog; they conservatively obscure the
entire instance. These safety boundaries exceed the Python observer, which
coarsens column rows, ignores partial-revoke flags and omits role-to-role edges.
Catalog requests are not an atomic snapshot or a target-user access probe.

Validation includes loopback HTTP failures and actual SQL against an isolated
official ClickHouse 26.6.2.160 container, pinned by multi-platform digest. The
test verifies a reader-profile POST write refusal and removes the container.
Positive HTTPS/private-CA integration, other server versions, performance and
production/staging validation remain unverified.

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
