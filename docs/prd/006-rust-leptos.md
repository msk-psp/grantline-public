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
| R3 | PostgreSQL, ClickHouse and S3 native adapters, probes and writers | Existing regression cases ported; separately authorized live read/probe and reversible write validation per adapter | R3a–R3e3 merged; R3f merged; R3g1 merged; R3g2 merged; R3g3 membership writer merged in PR #28; R3g4 merged in PR #29; R3h1/R3h2 merged in #31; R3h3 merged in #32; conditional remote JSON writer implemented; protocol-specific tree/IAM writes remain explicitly unsupported |
| R4 | Production sessions/OIDC, durable approval store, Slack signatures/DMs, code writer and GitHub PRs | Requester binding, all approvers, callback replay, immutable plan and repo scope verified end to end; approval/PR/applied access reported separately | Implemented in this stack; isolated verification, operational promotion pending |
| R5 | All console pages, Leptos hydration and interactive permission map | Repeated hover highlight/dimming, matrix scrolling, accessible dark mode, logs and four locales verified in browser | Implemented in this stack; isolated verification, operational promotion pending |
| R6 | Release image, migration/rollback and operating guide | Reproducible native/WASM builds, upgrade of persisted state, image smoke tests and explicitly authorized rollout | Implemented in this stack; native image/state migration checked locally, operational promotion pending |

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

### R7 — Python workflow parity and observation performance {#R7}

Status: implemented and locally/isolated validated (2026-10-19); stacked PR
integration and remote CI remain separate. Compatibility covers the represented
permission workflows under the native authenticated/reviewed-write contract,
not acceptance of legacy bearer links or implicit approval-time IAM execution.

- [x] Bounded parallel service reads, deterministic merges and one shared, refreshable
  observation cache. Concurrent readers share a complete generation; failures stay
  unknown, and explicit snapshots/writer previews never use cached authorization.
- [x] Verified private CA configuration for native HTTP/S3 and PostgreSQL clients;
  private `env_file` compatibility without changing process environment after
  worker threads start. Existing environment values retain precedence.
- [x] Native drift `notify` CLI, subject/resource detail and inheritance paths,
  historical comparisons, recorded recent-change routes and map detail navigation,
  retaining four locales. Invalid or missing history is never interpreted as
  a grant removal.
- [x] PostgreSQL and ClickHouse command coverage and S3 Filer identity writes
  equivalent to Python's represented resources, with explicit scope, reviewed
  plan binding, original-state preservation and uncertain outcomes retained.
  Unrepresentable/negative/ambiguous ACLs remain unknown; compatibility never
  means silently accepting them or removing a stale-plan check.
- [x] Differential, isolated TLS/network/write and browser tests plus the same
  latency benchmark used to identify sequential observation. No production
  endpoints, production IAM changes, real Slack messages or GitHub policy publication were used
  for this implementation's verification.

Execution evidence and the exact remaining scope are recorded in the workspace
task `grantline-rust-parity-complete`; each acceptance item is marked complete
only after its tests run.

Next: merge the main-integration PR first, then retarget/merge the parity PR.
Operational cutover, real provider authentication and effective target access
remain separate authorized acceptance; merging these source changes is not deployment.

PR #38 collects the already-merged #34–#37 feature-branch stack into main;
merge it before the R7 parity follow-up.
R1–R6 software paths are implemented within their explicit adapter contracts.
After stack CI and review, authorize a separate isolated operational pilot using
real configured OIDC/Slack/GitHub identities and read-only service comparisons.
A release publication and production/staging traffic switch require separate
operator action. Unsupported protocol/object scopes remain refused, never
silently simulated or treated as empty access.

## R3 — Native adapter migration {#R3}

Status: R3a merged in PR #17; R3b merged in PR #18; R3c merged in PR #19; R3d merged in PR #20; R3e1 merged in PR #22; R3e2 merged in PR #23; R3e3 merged in PR #24; R3f merged in PR #25; R3g1 merged in PR #26; R3g2 merged in PR #27; R3g3 membership writer merged in PR #28; R3g4 merged in PR #29; R3h1/R3h2 integrated into main in PR #31; R3h3 merged in PR #32; conditional remote JSON writer implemented.
The first review unit implements S3 file/dir
planes, effective policy observation, group/inline routes and identity-scoped
document previews. Plan commands remain previews; R3f adds a separate explicit
local-file application path. Shared managed policies and live services are not
written by this unit. Existing Python regressions are the oracle.

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

### R3f — Local S3 IAM file application and conditional restore

Status: implemented for one explicitly selected local monolithic file on Unix.
`apply` defaults to a file-free dry-run; `--write --expect PLAN_ID` must match
config/intent bytes, selected path, source bytes/metadata and grouped previews.
Read no other service/plane, network or imported snapshot. Filesystem write
permission is the local credential. Remote IAM and shared group trees are refused.

Reuse exact normalized-grant preview validation and require full final-intent
convergence, refusing a covering-grant removal that would lose intended narrower
access. Preserve credentials, account
metadata and unrelated identities. New identities have no keys. Emit recursive
native prefix actions with `/*`; bare prefix actions do not authorize descendants
on SeaweedFS. This is a correction to new preview output, not a reinterpretation
or automatic repair of untouched source actions. Unknown source fields/bindings,
incomplete policies, duplicate JSON keys, non-integral/out-of-range numbers,
unsafe permissions/parents, symlinks/hardlinks/FIFOs and oversize inputs are refused.

Use a private persistent sidecar OS lock for cooperating writers. Stage in the
same directory, retain POSIX mode/owner/group, sync a 0600 backup of exact original
bytes, recheck source/inputs, atomically replace and sync directory. Conditional
restore requires the exact applied digest/target/owner/mode and itself saves a
private backup. Readers see complete old/new documents. Backup contains keys;
never print its contents or commit it. Explicit JSON service_reload_verified=false
separates file replacement from service application. No reload or network write.

Acceptance: Rust36 tests, format/Clippy/build; stale source/config/intent/mode/inode
and foreign-plan refusals, credential/account/unmanaged preservation, policy JSON
and new-identity file changes, duplicate/unknown schemas, permissions, path/link
and lock guards, in-operation mutation refusal, concurrent readers and exact
conditional rollback/redo. Existing differential suites and Python36 tests pass.
check_rust_s3_writer.py bounds FIFO rejection and verifies before/apply/restore
on official isolated SeaweedFS4.48: actual native-action prefix access/revocation,
sibling denial, unchanged keys and no accidental List/PUT/DELETE authorization.
Policy JSON transformation is model-tested; its service loading is unverified.

Limits: 4MiB source/config/intent, 32MiB backup, 1,000 changes. This is not a CAS
against unrelated editors. ACL/xattr/SELinux, network filesystems, power-loss/fault
injection, Windows, operational reload and production/staging writes are unsupported
or unverified. PostgreSQL/ClickHouse/remote S3 writers remain subsequent units.

### R3g1 — Transactional PostgreSQL ordinary-table ACL writer

Merged in PR #26. This unit's table-only boundary is extended by R3g2 below.

Scope: one explicitly selected PostgreSQL 16+ database and existing ordinary tables.
`apply --system NAME --live` reads only the named `admin_dsn_env` and previews a
fresh native plan. It never falls back to reader, probe or ambient PG credentials.
`--write --expect PLAN_ID` binds config/intent bytes, endpoint and authenticated
session, server start, catalog object identities, ACLs and generated statements.
Only exact table privileges are supported; role/schema/database/default changes,
ALL/wildcards, PUBLIC/owner/privileged targets, column grants, delegation chains,
views, partitions and inheritance fail closed. Config must select one literal DB.
No caller SQL or SET ROLE is accepted. Other adapters are not contacted.

A write uses one READ COMMITTED transaction. It takes NOWAIT ACCESS EXCLUSIVE
locks on the affected ordinary tables in sorted order, re-reads the catalog and
matches the reviewed identifier before any GRANT/REVOKE. All changes use fixed
quoted native SQL with RESTRICT, followed by exact direct-ACL postconditions and
an empty remaining plan before COMMIT. Failure before COMMIT rolls everything
back. A COMMIT transport failure has an uncertain outcome and must be inspected
before retry. The lock can briefly block application queries; this first writer
is intended for controlled maintenance, with no concurrent role/schema/catalog
administrators. Relation locks do not freeze cluster-wide role or namespace DDL.

Acceptance: disposable official PostgreSQL tests preview immutability, grant and
revoke, a separately reviewed inverse plan, stale inputs/catalog/connection,
unsupported scopes, identifier quoting, statement failure after an earlier grant,
lock contention, timeouts and credential redaction. Existing readers/probes and
S3 apply/restore must retain their boundaries. No object data is read or written.
A successful receipt proves direct catalog ACL changes committed, not subject
login, effective application access, deployment or general backup restoration.

R3g1 validation: Rust unit/integration checks and the three Python differential
suites, unchanged PostgreSQL reader/probe checks, and the isolated 17.11 writer
fixture. The fixture checks a warning-only ineffective GRANT, an event-trigger
SQL error and a delayed statement after an earlier successful GRANT: all leave
original direct ACLs intact. Execution logs and PR/CI state live in the task
handoff, not in this specification. Production, COMMIT network-loss ambiguity and
concurrent role/namespace administrators remain unverified.

### R3g2 — Single-database schema and database ACL writes

Merged in PR #27. Role changes are introduced separately by R3g3 below.

Extend the same reviewed writer to existing `schema:DB.NAME` USAGE/CREATE and
`db:DB` CONNECT/CREATE/TEMPORARY atoms, alongside ordinary-table ACLs in the same
transaction. TEMP aliases, ALL/wildcards, PUBLIC/owner/privileged targets,
non-owner grantors/delegation and cross-database changes remain refused. Role and
default-privilege writes remain later units. No object creation, data SQL or role
switching is executed. Explicit admin credentials, `--live`, `--write --expect`,
TLS rules, bounded inputs and unknown-scope refusal remain unchanged.

Bind schema/database object OIDs, ownership and raw ACL state to a versioned
plan ID. All writes acquire a nonblocking transaction advisory lock with reserved
keys `(1196576334, 1)` in the connected database before observation; this
serializes this writer version's table/schema/DB plans. Existing affected-table
NOWAIT ACCESS EXCLUSIVE locks remain. There is no SQL LOCK SCHEMA/DATABASE
substitute here: advisory locking does not exclude raw SQL or older writers.
Use a controlled maintenance window without external role/namespace/database
administration; this unit must not claim cluster-wide serialization or CAS.

Apply fixed quoted GRANT/REVOKE RESTRICT, verify exact direct ACL atoms across
all three object kinds including grantor/grant option, unchanged object
identities/ownership/non-ACL catalog state and an empty remaining plan, then
COMMIT once. PUBLIC defaults and unrelated grants stay intact. A warning-only
ineffective grant, SQL error or timeout must roll back all mixed-scope changes.
COMMIT connection-loss outcomes remain unknown and require inspection before retry.

Acceptance: official disposable PostgreSQL verifies all supported privileges,
quoted schema/subject identifiers, DB/schema/table mixed plans and reviewed
inverse restoring semantic ACLs. Reject stale schema OID/name/owner/ACL and DB
owner/ACL, other-DB grants, delegation, privileged/owner/PUBLIC targets and
unsupported scope/privilege. Verify mixed-scope SQL-error, timeout and warning
rollback plus advisory lock contention/release, existing table locks, credential
redaction and reader/S3 regressions. No operational writes are authorized.

R3g2 implementation retains the existing read/plan/core semantics and write
credential boundaries. The reviewed-ID format advances to v2: IDs from the
ordinary-table-only writer must be previewed again. The fixture uses official
PostgreSQL 17.11, covers PUBLIC's preserved effective defaults, the special
`pg_database_owner` owner of the public schema, and quoted schema/subject/database
names. Exact run results and PR/CI evidence are recorded in the task handoff.
The initial Docker readiness check now verifies TCP, avoiding the image's
temporary initialization server that accepts only local socket connections.

### R3g3 — Explicitly scoped PostgreSQL role membership writer

Membership changes are cluster-wide, unlike object ACLs. Default off: the adapter
must name literal `membership_write_roles`. This list authorizes membership in
those roles and their existing cluster-wide privileges; database selection does
not constrain those privileges. Role plans must connect to/select `postgres` as
a fixed coordinator and contain no object ACL changes. This version's role
writers then share the existing postgres-local transaction advisory lock; object
writers in other DBs, older writers and raw SQL do not participate. Deployments
without a postgres database are unsupported for this unit. No operational writes
are authorized by the specification.

Only existing non-login group roles are assignable, to existing ordinary roles
or accounts. Fixed options are `ADMIN FALSE, INHERIT TRUE, SET TRUE`, with explicit
`GRANTED BY` the authenticated writer. The writer must directly hold ADMIN OPTION
on the target group. Revoke only a single canonical edge granted by that writer,
with RESTRICT. Do not edit options, borrow another grantor or use SET ROLE.
Validate opted-in declared edges even if the MEMBER atom already exists, refusing
ambiguous grantors/options instead of treating them as a proven canonical grant.
Unchanged memberships outside the write allowlist remain read-only.

Reject self/writer changes, login groups, PUBLIC/predefined/privileged or owner
endpoints/ancestors, unsafe membership options/delegation in their ancestor paths,
and changes affecting the writer's own INHERIT/SET role ancestry. Detect ownership across
DBs using role ownership dependencies in pg_shdepend. This is not an audit of all
role ACLs/RLS/application behavior: the operator must review the allowlisted
role's existing privileges. Bind roles/OIDs, exact membership options/grantors,
owner-role IDs, config and session to plan-ID v3. Compare the complete expected
membership set, all direct object ACLs and unchanged other catalog state before
one COMMIT. Failure/timeout rolls back the entire role plan; COMMIT uncertainty
still needs inspection. No role creation, attributes, ADMIN grants, default
privileges or cluster-wide effective-access guarantee.

Acceptance: official isolated PostgreSQL verifies canonical grant/revoke and
reviewed inverse, quoted names, NOINHERIT account behavior with explicit options,
actual inherited SELECT/SET ROLE and cluster-wide scope, stale roles/OIDs/options/
grantors/admin rights, owner/privilege ancestry and allowlist/coordinator/mixed
scope refusal, advisory contention/release, multi-command SQL failure and blocked
grant timeout rollback. Existing object writer, readers/probes, S3 and core
regressions must retain their boundaries.

R3g3 validates cluster ownership from shared dependencies, binds each separate
privilege attribute (not just their combined privileged classification), and
retains unchanged object writer behavior. Isolated tests use a non-superuser
writer with direct ADMIN OPTION and no INHERIT/SET access to administered groups.
They verify actual cross-database SELECT, nested groups and SET ROLE for a
NOINHERIT account, and roll back both a later cycle error and a later blocked
membership insertion. Evidence and CI/PR results belong in the task handoff.

### R3g4 — Creator-bound PostgreSQL default table privileges

Implement schema-specific table defaults for the authenticated creating role only,
behind a literal `default_write_scopes = ["default:demo.app@creator"]` allowlist.
The selected DB, existing schema and creator must match exactly; never SET ROLE,
borrow a grantor, create roles/schemas or edit global defaults. Require default-only
change plans, exact supported table privileges and ordinary existing recipients;
reject PUBLIC, predefined, privileged and creator/schema/database-owner targets,
grant options or non-creator grantors. Validate allowlisted declared defaults even
when the binary grant is already held. Unchanged defaults outside the write
allowlist remain read-only; changes to other creators are refused. Use a separate
scope/credential per creator. Global table defaults stay unread.

Use the existing explicit admin credential, reviewed plan ID and database-local
transaction advisory lock. Bind the complete pg_default_acl catalog including
all object types, raw ACLs, row OIDs, creator/schema/role identities and session to
a new plan format. Verify the exact expected default ACL atoms, unchanged unrelated
default rows, object ACLs, roles/memberships/ownership and an empty remaining plan
before COMMIT; errors/timeouts roll back all commands. Bind local default-row
ownership through those rows separately from other shared ownership dependencies,
so a creator without existing owned objects can add/remove its defaults without
masking unrelated ownership changes. The membership guard still reconstructs the
complete owner-role set. Default row removal and recreation are storage changes,
not semantic inverse failures.

Defaults affect future relations (including views/foreign tables), never existing
objects. They belong to the role actually creating an object, not its members.
Schema-specific defaults add to global defaults and cannot subtract global grants.
Receipts must flag future-object scope without claiming effective access. Review
inverse intent separately; inverse defaults do not remove ACLs on objects created
while the default was active. No global/function/sequence/type/schema default writer.

Acceptance: isolated official PostgreSQL with a non-superuser creator verifies
exact grantor/options, quoted identifiers, actual future-object SELECT/INSERT and
revoke/inverse behavior; existing objects and other schemas/creators/DBs unchanged;
stale default row/creator/schema identities, flags, unrelated default types, grant
options/global/default-off/mixed scope refusal, later SQL error and blocked later
statement rollback. Existing object and role writers, readers and core suites must
pass. PR/CI evidence belongs in HANDOFF; no operational deployment is authorized.

References: PostgreSQL 17 [ALTER DEFAULT PRIVILEGES](https://www.postgresql.org/docs/17/sql-alterdefaultprivileges.html)
and [pg_default_acl](https://www.postgresql.org/docs/17/catalog-pg-default-acl.html).

### R3h1 — Single local ClickHouse table ACL writer

Implement one direct SELECT or INSERT grant/revoke per invocation on an existing
UUID-backed Memory/MergeTree table in an Atomic database. Require literal
`clickhouse_write_tables = ["table:demo.events"]`, explicit `admin_url_env`,
`--live`, and separately `--write --expect PLAN_ID`. The named HTTP(S) URL must
include the authenticated user; do not fall back to readers/probes/ambient auth.
Require a direct exact-table GRANT OPTION for the authenticated writer. Recipients
must already exist in local_directory; refuse self/writer-role ancestors,
colliding users/roles, column/partial/delegated/broad/parameterized recipient ACLs,
wildcards, ALL, role/database/global changes and multiple planned changes.

Reuse the bounded read-only catalog HTTP path. Read full principal IDs/storage,
role memberships and raw direct grants, selected database/table UUIDs/DDL and
server UUID/user/version. Bracket observer interpretation with equal catalog
reads; bind these non-secret states, input bytes and fixed quoted SQL to plan-ID.
Refresh and compare immediately before the only POST statement. Use no session,
role switching, redirects, proxies, retry, ON CLUSTER or REPLACE OPTION.

ClickHouse ACL writes have no multi-statement transaction here. After dispatch,
transport/error/timeout or post-check failure must report outcome unknown and
require inspection, never automatic retry or rollback. Compare the exact expected
raw ACL rows, unchanged identities/table definitions/memberships and convergence.
A successful result confirms only this server's direct catalog state, not effective
access, cross-node replication or a concurrent-admin compare-and-swap. Require a
controlled interval with no other ACL/identity/table administration. Undo needs
newly reviewed inverse intent; no general restore or batching guarantee.

Acceptance: isolated HTTP credential/scope/error/timeout/redirect/post-check
boundaries and digest-pinned official ClickHouse grant/revoke/inverse on ordinary
users and roles, actual SELECT/INSERT and denial, quoted identifiers, no-op,
stale input/ACL/subject/table UUID/session refusal, unsupported broad/delegated/
column/partial and multi-change refusal. Preserve reader/probe and other writer
regressions. No production/staging access or rollout is authorized.

References: ClickHouse [GRANT](https://clickhouse.com/docs/sql-reference/statements/grant),
[REVOKE](https://clickhouse.com/docs/sql-reference/statements/revoke),
[system.grants](https://clickhouse.com/docs/operations/system-tables/grants).

### R3h2 — Explicit ClickHouse database ACL scopes

Extend the single-statement writer to exact `db:demo` SELECT/INSERT scopes behind
an independent, default-empty `clickhouse_write_databases = ["db:demo"]` allowlist.
This authorizes every existing and future table/relation name and engine within
that DB, not a frozen table list. Existing DB must be Atomic with a nonzero UUID;
bind all currently contained table UUIDs/engines/DDL, including empty-DB semantics.
Table-only authorization must never authorize DB scope or vice versa. Preserve
R3h1's ordinary-table restrictions for table-only targets. Named system/global/
prefix wildcard/dropped database scopes and role membership writes stay refused.

Require authenticated writer's direct exact-scope GRANT OPTION. Recipients may
retain ordinary direct DB SELECT/INSERT only for allowlisted DB scopes. Reject
all partial revokes, delegation and unmodelled direct privileges. Reject unions
of held and declared direct DB/table scopes for the same recipient, DB and leaf
privilege: broadening can coalesce table grants; narrowing or partial revocation
can erase retained rights. Do not treat these as reversible one-atom edits.
One invocation still changes at most one atom. Bound snapshot format v2 includes
all configured DB scopes and current contained objects; old preview IDs expire.
Receipt/text must disclose future-table scope and keep effective access false.

Retain full raw ACL postconditions, pre-dispatch refresh, bounded HTTP reads and
explicit uncertainty after a dispatched failure. No ON CLUSTER, automatic retry,
compensating SQL, multi-statement transaction or external-admin lock is added.
Inverse intent requires a fresh review and removes that direct database grant,
not data or permissions from alternative role paths.

Acceptance: official isolated ClickHouse verifies DB SELECT/INSERT grant/revoke/
inverse, empty DB and future-table access, other-DB denial, quoted DB and roles,
retained unrelated direct ACLs and role-based residual access, stale same-name DB
recreation/table set/DDL/ACL/input/session, unsupported scopes/overlap/partial/
authority/default-off refusal. Extend HTTP failure tests to DB statements; all
R3h1 and reader/probe regressions must pass. No production/staging rollout.

References: [wildcard GRANT](https://clickhouse.com/docs/sql-reference/statements/grant#wildcard-grants)
and [partial REVOKE](https://clickhouse.com/docs/sql-reference/statements/revoke#partial-revokes).

### R3h3 — Canonical ClickHouse role memberships

Reuse default-empty `membership_write_roles = ["analytics_reader"]` for exact
role names, independent of object ACL allowlists. One existing `role:name` MEMBER
atom per invocation; no role creation, ADMIN/REPLACE/ON CLUSTER or SET DEFAULT ROLE.
Require authenticated writer's direct ADMIN OPTION on that exact role; inherited
ADMIN or global ROLE ADMIN alone is insufficient. Recipients and target/ancestor
roles must be UUID-backed local_directory principals. Refuse writer/its ancestor
recipients, self/cycles, noncanonical existing edge options, and target role chains
with delegation or unsupported privileges. Role chains may carry ordinary exact
table/DB SELECT/INSERT; membership authorizes their current and future privileges,
including descendant accounts of a recipient role, not a frozen resource list.

For account recipients require DEFAULT ROLE ALL with empty lists/exceptions.
Bind full non-secret default-role/grantee policies plus raw role UUID/default/admin
rows when membership authorization is configured; never read authentication data.
Canonical new rows have ADMIN=0, default=1. Fresh inverse intent/review restores
the exact membership row without altering direct ACLs or default-role policy.
Bind all raw ACLs, principals, memberships, policies, session and input bytes;
refresh before dispatch, compare exact expected state and convergence afterward.
Keep one POST and uncertain outcome after dispatch failures; no retries,
compensation, transaction/CAS or effective-access guarantee.

Acceptance: isolated HTTP single POST and error/timeout/redirect/post-check
uncertainty; official digest-pinned server account/role/nested membership actual
SELECT and denial, INSERT and denial, quoted names, grant/revoke and both inverses,
retained unrelated rights/alternate paths, no-op, stale UUID/role ACL/edge/default
policy/source/session rejection. Refuse default-off, wildcards, missing/wrong-kind
roles, writer/cycles, admin edges, noncanonical defaults, inherited/global-only
authority, unsafe role chains and multiple/mixed changes. Preserve R3h1/R3h2,
reader/probe/core/privacy regressions; no production/staging access or deployment.

References: [role GRANT](https://clickhouse.com/docs/sql-reference/statements/grant#assigning-role-syntax),
[REVOKE](https://clickhouse.com/docs/sql-reference/statements/revoke),
[role metadata](https://github.com/ClickHouse/ClickHouse/blob/v26.6.2.160-stable/src/Storages/System/StorageSystemRoleGrants.cpp),
[default-role policy](https://github.com/ClickHouse/ClickHouse/blob/v26.6.2.160-stable/src/Storages/System/StorageSystemUsers.cpp).

## Final implementation stack — R3i through R6

User authorized completion as stacked PRs on 2026-10-16. Implement the remaining
production software paths and isolated verification; deployment and operational
credential/permission changes remain separate. Do not auto-merge stacked branches.

### R3i — Conditional remote JSON IAM writer

Explicit enforced-plane admin_url_env/admin_auth_env and conditional_write=true.
GET requires a strong ETag; bind endpoint, config/intent, credential identity,
revision and original/candidate bytes. Use existing strict local IAM transformer.
One If-Match PUT, 412 conflict, exact post-read; other dispatched errors unknown.
Private original-byte backup before dispatch and conditional restore only against
the applied-byte digest, never blind compensation. No service reload/effective
access claim. IAM Query and shared Filer group trees remain read-only because
those protocols do not provide this single-document conditional-write contract.
Server must implement If-Match correctly; the flag is an operator contract, not
proof of server correctness. Existing local SeaweedFS write/access tests plus
remote HTTP conflict/recovery/failure injection establish the bounded contract.

### R4 implementation units

R4a: explicit loopback-only trusted proxy mode and direct OIDC authorization-code
flow with state, nonce, PKCE, verified issuer/audience/signature, private expiring
sessions and CSRF. No demo authentication accepted by production routes.
R4b: private durable versioned approval store, all independent approvers, immutable
source/patch digest, exact requester identity binding, replay/expiry guards and
audit events. Signed Slack callbacks and authenticated per-approver DMs; native
GitHub scoped branch/commit/PR publication with no IAM application. Fail closed
and record uncertain external outcomes; no automatic re-publication after errors.

### R5 implementation unit

Leptos console routes for map, accounts/resources, services, matrix, changes,
history and approvals, with typed Rust API data. Native/WASM UI build, functional
hover/dimming without layout oscillation, logs with levels/entities, scroll-safe
matrix and dark selects. English/Korean/Japanese/Chinese; preserve service and
environment proper names. Keep Python as oracle, never runtime proxy/subprocess.

### R6 implementation unit

Non-root native image with WASM/assets, locked reproducible builds, CI smoke
checks and release gating. Versioned durable state import/backup, migration dry
run and reversible upgrade procedure. Document explicit limits and Python/Rust
cutover; no release publication or operational rollout in this task.

## R5 — Native Leptos console

The native `serve` command now renders the login, map, accounts, resources,
services, matrix, changes, snapshot history, request and approval pages.
`grantline-ui` shares typed SSR and WASM components; run
`scripts/build_rust_ui.sh` with the lockfile-matching wasm-bindgen CLI.
The browser only calls authenticated native APIs. It cannot execute IAM writes.
Live catalog loading reports unknown on failure; approval/history pages do not
wait for service observation. Immutable full patches are available on the scoped
approval detail route; list summaries omit full source documents.

English, Korean, Japanese and Simplified Chinese labels preserve configured
environment identifiers and source diagnostics. Repeated resource hover uses
fixed geometry and independent upstream/downstream traversal, excludes sibling
resources, dims unrelated nodes and supports keyboard selection. Matrix sticky
cells have opaque backgrounds within a clipped scroll region. Log levels and
entity chips remain structured. Large maps/tables have explicit display caps.

Validation: workspace Rust tests/Clippy, SSR/API/static asset contract, signed
OIDC and durable Slack/GitHub loopback tests, release WASM build, and Chrome
checks for repeated hover, dimming, matrix scrolling, themes, official icons and
four locale transitions. Real operational SSO, Slack, GitHub and IAM services
were not contacted. R6 supplies distribution and migration instructions.

## R6 — Native distribution and private upgrade

`Dockerfile.rust` pins official Rust 1.99 and Debian base digests, builds locked
native/WASM artifacts and runs UID 10001 without Python/Node. A separately
explicit read-only public fixture preview permits container networking; it
refuses live services or authenticated modes. Release publication depends on
reference/privacy, native adapter/WASM/auth/workflow/migration tests and native
image smoke tests. Existing Python Dockerfile remains an explicit rollback path.

The copy-only `migrate` CLI defaults to dry-run. Write requires stopped source
writers, `--write --offline`, bounded private inputs, a new destination and an
atomic publication with a semantic-hash manifest. Legacy tokens/commands/code
plans are discarded; scoped historical archives confer no approval authority.
Pending/approved native records need a new review; crashed publication and
notification dispatches become unknown and never automatically retry. Original
source state is retained for rollback. Snapshot JSONL remains compatible.

[Operating guide](../rust-operations.md) and fictional configuration cover OIDC,
trusted proxy boundaries, independent Slack identities, exact GitHub account
and repository scope, private volumes, migration, shadow comparison and rollback.
The four READMEs now start from native console build and distinguish published
images, merging, operational validation and actual IAM application.

Isolated contract tests and official service/container checks establish software
behavior, not a completed operational deployment. Real SSO/workspace/repository,
service reload/effective access, published multiarchitecture release and traffic
cutover remain separately authorized deployment acceptance checks.

## R8 — Precise PostgreSQL column observation {#R8}

Status: implemented; isolated verification complete, PR checks in progress. Column ACLs use
`column:database.schema.table.column`, preserving subject, privilege, grantor and
grant options without turning a column grant into a table grant. A column ACL
must not obscure sibling table ACLs in the schema. Table privileges cover their
exact child columns; the reverse never applies. Fixed read-only
`has_column_privilege` probes support SELECT/INSERT/UPDATE/REFERENCES; column
writes remain refused. Excluded/unread databases also obscure column scopes.

Acceptance: isolated official PostgreSQL exercises inheritance, PUBLIC, quoted
names, allowed and denied columns, table siblings, snapshot round trips and
reader/write isolation. The active CI baseline is official PostgreSQL 18.6 with
a runtime major-version assertion, plus the pinned pg_duckdb PostgreSQL 18
reader/probe distribution check. Older 17.11 results above are historical.
No production ACL change is part of this stage.

## R9 — Retire the Python service {#R9}

Status: planned after R8. Remove the Python application, package entry point,
legacy container and application-only CI. Keep only the modules needed by the
existing offline differential suites under `tests/reference`, and keep native
provider/image/privacy verification scripts. The reference is test-only and is
excluded from container builds. Default and release containers use Rust/Leptos.
Keep the `Dockerfile.rust` path compatible with existing consumers.

Next action: finish the R8 isolated verification and stack the R9 cleanup PR.
PostgreSQL special roles and ClickHouse negative/parameterized grants retain
their existing unknown semantics; retiring Python does not establish parity for
those unsupported scopes. Operational rollout and live comparisons are separate.
