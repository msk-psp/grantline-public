# PRD 006 — Rust + Leptos migration

Decision: **accepted, staged implementation** (2026-10-15). Supersedes the
unscheduled Dioxus proposal in [PRD 004](004-port-to-rust.md). The target is a
complete Rust backend and Leptos UI; Python remains the reference until parity
and live validation permit replacement. This is a distribution and maintenance
decision, not a claim that a language change removes network or SVG latency.

## R1 — Native core and approval playground {#R1}

Status: implemented and locally verified; review pending. Linux validation is
tracked by the PR's Rust native CI check. Acceptance:

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
| R2 | Typed config/intent, snapshots, findings, graph and complete plan CLI | Fixture output including diagnostics, restore semantics and command grouping matches Python | Pending |
| R3 | PostgreSQL, ClickHouse and S3 native adapters, probes and writers | Existing regression cases ported; separately authorized live read/probe and reversible write validation per adapter | Pending |
| R4 | Production sessions/OIDC, durable approval store, Slack signatures/DMs, code writer and GitHub PRs | Requester binding, all approvers, callback replay, immutable plan and repo scope verified end to end; approval/PR/applied access reported separately | Pending |
| R5 | All console pages, Leptos hydration and interactive permission map | Repeated hover highlight/dimming, matrix scrolling, accessible dark mode, logs and four locales verified in browser | Pending |
| R6 | Release image, migration/rollback and operating guide | Reproducible native/WASM builds, upgrade of persisted state, image smoke tests and explicitly authorized rollout | Pending |

R1 alone does not support production observation, apply, SSO, real Slack or real
PR creation. It does not replace the existing console. No release or production
rollout is authorized by this document. Add shared cases before changing semantics;
keep Python as a development-only oracle until all stages pass.

## Next action

Review R1, then implement R2 against the existing fixture suite. Each
stage needs its own reviewable change and acceptance evidence before advancing.

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
