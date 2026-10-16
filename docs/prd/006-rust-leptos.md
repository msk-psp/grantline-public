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
| R3 | PostgreSQL, ClickHouse and S3 native adapters, probes and writers | Existing regression cases ported; separately authorized live read/probe and reversible write validation per adapter | R3a–R3e2 merged; R3e3 S3 List/HEAD probes implemented; writers pending |
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

Review R3e3's S3 read-only subject-signed List/HEAD probes and isolated server
evidence. The next review unit is a native writer for local S3 IAM documents,
using existing grouped previews, explicit opt-in, stale-source guards and
reversible fixture validation. Other writers and separately authorized
production/staging verification follow. Each
review unit needs acceptance evidence before advancing; R3 is not yet complete.

## R3 — Native adapter migration {#R3}

Status: R3a merged in PR #17; R3b merged in PR #18; R3c merged in PR #19; R3d merged in PR #20; R3e1 merged in PR #22; R3e2 merged in PR #23; R3e3 S3 List/HEAD probes implemented.
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

### R3c — PostgreSQL catalog observation

Implement native PostgreSQL 16+ observation behind the existing `--live` opt-in,
using only `dsn_env`. Maintain offline/import isolation and existing grant,
snapshot and graph contracts. Scope is DB/schema/table/default-table ACLs and
role membership. No probe/writer, production connection, UI or deployment change.

A maintenance transaction reads role kinds, membership options and DB ACLs.
Separate repeatable-read, read-only transactions read each configured target DB.
Preserve implicit PUBLIC/owner ACLs, raw role names, source/grantor metadata,
nested membership and creator-specific per-schema defaults. Frozen ACL detection
uses zero cardinality instead of array equality, which misses dimensional empty
ACLs on the actual server. Unread/excluded DBs must discard partial per-DB data
and obscure table/schema/default scopes. A maintenance or total-deadline failure
must discard all instance grants. DB filters must not make skipped DBs look empty.

Only a named explicit TCP reader is accepted; no PG environment, admin/probe,
service-file or options fallback. TLS verifies certificates and upgrades prefer
to require; plaintext needs explicit disable. Catalog SQL has a fixed search path,
server statement/lock/idle limits, 10,000-row/16-MiB query caps, 128-DB and
100,000-grant bounds and a configurable total deadline. Error bodies/DSNs are
withheld. These client safeguards do not provision a least-privilege DB role or
isolate memory from a malicious wire peer.

Column ACLs obscure a schema's table scopes; global table defaults obscure that
DB's default scopes. Unsupported resource identifiers obscure their DB/cluster.
Superuser/predefined-role privileges and membership INHERIT/SET restrictions,
including transitive dependants, remain unknown. Grant/admin options are findings.
These conservative boundaries and raw-name/frozen-ACL fixes exceed Python parity.
Sequence/function/type ACLs, effective RLS/owner powers and user login/data access
are not claimed. Per-connection snapshots are not cluster-atomic.

Acceptance: native lint/tests and existing Python differential/regression suites;
isolated invalid DSN/deadline/config cases; actual official PostgreSQL 17.11 tests for
catalog visibility, metadata, defaults, memberships, frozen/column/global scopes,
DB exclusions/connect failures, partial-query discard, graph/snapshot contracts,
TLS downgrade refusal and write refusal. The test uses only disposable loopback
Docker resources. Positive TLS/private-CA integration, other versions/platforms,
performance, production/staging and actual probes/writers remain unverified.

### R3d — Remote S3 IAM observation

Implement all three existing remote plane shapes under `--live`: JSON GET,
SeaweedFS Filer IAM-tree GETs and SigV4 IAM Query List/Get calls. Reuse the native
S3 policy evaluator, findings, graph and snapshot contracts. Scope excludes probes,
actual writers, AWS effective-permission claims, production access and UI changes.

Use only explicit per-plane reader variables and preserve remote-source priority;
no local/admin/probe/AWS environment fallback. Require valid HTTP(S) endpoints,
verified TLS, no redirects/proxies, bounded per-plane time/requests/bytes/items.
Credentials must not reach output, snapshots or document previews. Remote sources
cannot produce merged write previews. Filer reads discard raw credential fields.

Require complete Filer directory and IAM marker pagination, path/name checks and
strict JSON/XML envelopes. A listed file failure or incomplete collection obscures
the plane. Optional absent Filer directories/index can be empty only under the
complete-tree visibility assumption. IAM user-specific policy errors, boundaries
and unknown native actions obscure that subject; shared collection errors obscure
the whole plane. Preserve direct vs inherited routes and empty-policy precedence.

Actual-server validation must include user inline/managed and group inline/managed
policies. Extend the shared tree merger for identity `policy_names` and top-level
`groupInlinePolicies`, which the Python reference omits, instead of silently
coarsening native-action projections. Query API follows returned ARNs/default
versions, rather than inventing names or accepting the first page only.

Acceptance: isolated three-provider HTTP tests, signature oracle, source/credential
isolation, truncation/errors/caps, unknown-scope decisions, graph/snapshot and a
digest-pinned official SeaweedFS 4.48 container. Verify a separate IAM gateway with
server read-only mode rejects a real write. Existing Rust/parity/Python/Node/lint
and privacy checks must pass. Custom CA/positive TLS, other versions/platforms,
performance and production/staging access remain unverified. Sequential reads
are not atomic and do not prove target-user data access.

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


### R3e1 — PostgreSQL read-only ACL probes

Scope: native `probe` CLI, three-state results, exact baseline disagreements,
PostgreSQL fixed privilege inquiry SELECTs and optional explicitly mapped subject
TCP credentials. It does not read application rows or execute permission writes.
Default reader evaluations say "not a login". Mapped subject credentials must
verify session/current user; missing credentials, identity mismatch, connection/
SQL/null failures and unsupported targets are unknown with redacted reasons.
No reader/admin fallback occurs for a configured subject credential.

Use observed atoms only, not intent expansion. `--live` is mandatory for network
activity. `--observed` can accompany `--live` for stale-baseline checks, unlike
plan/graph/snapshot source selection. Service filters apply before observation.
Keep unread baseline scopes visible. Enforce 1,000 selected atoms, 128 connection
groups, DB inclusion/exclusion, verified TLS and inherited read-only session/
transaction limits. The probe deadline is separate from observation and discards
partial results. Savepoints isolate per-atom SQL errors. Unsupported PUBLIC,
default resources, wildcards and ALL remain unknown.

Acceptance evidence: Rust format/clippy/tests/build, existing differential suites,
and `scripts/check_rust_postgres.py --docker` for definite allow/deny, nested vs
non-inherited role ACLs, quoted names, stale baseline findings, failed query
recovery, actual subject TCP login/identity mismatch, missing credentials, offline
isolation, deadlines and redaction. The disposable server uses trust auth; SCRAM,
positive TLS and production/staging verification are not claimed. ACLs do not
establish schema traversal, RLS/data availability or SET ROLE behavior. Readers
and probes are read-only; ClickHouse/S3 probes and writers remain subsequent units.


### R3e2 — ClickHouse read-only ACL probes

Scope: connect the existing tri-state native probe CLI to ClickHouse, resolving
ACLs with SHOW GRANTS WITH IMPLICIT FINAL. Observer mode is not a login. Explicit
probe_url_env overrides url_env without fallback on failure; probe_url_envs maps
subject credentials and takes precedence over both. Subject HTTP login requires
exact currentUser() identity, followed by server-resolved ACLs. Missing/bad
credentials, mismatched identity and service/parse failures are unknown and
never use admin credentials. No data rows, writes, SET ROLE or impersonation.

FINAL flattens all granted roles, including non-default roles. Results therefore
do not claim role activation or session/data access. Direct MEMBER is obtained
from a separate plain SHOW GRANTS; FINAL removes membership rows on the tested
server. Do not use CHECK GRANT INSERT with forced readonly=2: it can return0 even
when the stored ACL contains INSERT. Keep this regression in the real-server test.

Strict parsing preserves exact global/DB/table vs named-object scope, recipient
identity and quoted names. Any unresolved REVOKE, columns, prefix wildcard,
unknown grammar/escape or incomplete payload makes the subject unknown rather
than using partial permissions. Exact known rights or ALL can allow; absence
can deny only SELECT/INSERT/OPTIMIZE/TRUNCATE/dictGet. Other supported privilege
groups remain unknown without exact coverage; group expansion is deferred.
Unknown requested resources/privileges never inherit an ALL allow.

Enforce explicit --live, source/service/subject filters, <=1,000 atoms and128
subjects, shared verified-TLS/header/proxy/redirect safeguards, 10,000-row/16MiB
responses, 64KiB statements, 1KiB identifiers, 10,000 parsed permissions/roles and
server scan/result/time limits. One probe
deadline spans all subject requests and discards partial outcomes. Observation
has a separate deadline. Fixed metadata queries only; SHOW has no LIMIT syntax.

Acceptance: native fmt/clippy/tests/build and existing differential suites;
check_rust_clickhouse.py HTTP failure/identity/credential isolation, timeout after
an earlier success, subject cap and redaction; isolated official ClickHouse
26.6.2.160 for inherited/global/table ACLs, direct membership, partial/column
unknowns, quoted identifiers, restricted/missing subjects, actual SHA256 password
login, wrong credentials/identity, non-default roles and readonly INSERT semantics.
No production/staging access or deployment. Writers remain next;
positive TLS/private CA, live row-policy/session behavior remain unverified.

### R3e3 — S3 read-only data-plane samples

Scope: existing tri-state probe CLI, explicitly mapped subject SigV4 credentials,
ListObjectsV2 with max-keys=1 and HEAD metadata of one in-scope object. The data
endpoint and credentials are independent of IAM/Filer observation. No secrets
are extracted from IAM documents; no reader/admin/AWS environment fallback.
The operator binds keys to subjects; no STS identity check is claimed.

An optional normalized-resource-to-object map permits HEAD without List access.
Reject out-of-prefix samples and traversal before network activity. Preserve
encoded Unicode, spaces, plus and percent characters, including SeaweedFS
form-encoded listing spaces (`+` versus literal `%2B`). A successful sample is
not a prefix-wide effective-access proof. Empty scopes and inability to select
an object leave Read unknown. Only concrete bucket/prefix List/Read atoms have
an evaluator; Write/Admin/capabilities/roles/unresolved wildcards remain unknown.
No object-body GET or write verb is issued by native probes.

Allow requires a validated scoped listing or HEAD metadata. Deny requires an
explicit S3 AccessDenied error with HTTP403. Invalid credentials/signatures,
token/region errors, generic HEAD403/404, malformed XML, service/transport errors
and redirects remain unknown. No response body, sample key or credential enters
diagnostics. HTTPS uses verified roots; proxies/redirects are disabled; custom
CA bundles are explicitly unsupported.

Bounds: <=1,000 atoms/128 subjects, 512 requests, 1MiB per response, 16MiB total
and one 1–120-second adapter deadline independent of observation. Request/total
byte/deadline exhaustion discards earlier partial results. Reuse a listing only
within the same subject/resource. Offline probes never resolve credentials.

Acceptance: native fmt/clippy/tests/build and all three differential suites;
check_rust_s3_probes.py independent HTTP signature/session-token/encoding oracle,
scope/cache isolation, explicit samples, auth/denial/error distinctions,
deadline/request/byte limits, no credential fallback and redaction; disposable
official SeaweedFS 4.48 for actual SigV4 List/HEAD, read-only subjects without
List, empty/ambiguous/auth failures and independent server-side write refusal.
Existing S3 readers and PostgreSQL/ClickHouse server regressions remain green.
Positive TLS/private CA, AWS integration, writes and production/staging access
remain unverified or pending. No deployment is part of this unit.
