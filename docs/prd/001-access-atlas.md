# PRD 001 — grantline (proposed name: Grantline)

Historical proposal; [PRD 003](003-scope.md) defines current scope and status.

One place to **see** who can access what across heterogeneous data systems, and to
**converge** each system toward a declared intent — using each system's own native
permission commands.

## Problem

Permissions live scattered across PostgreSQL, ClickHouse, and S3-compatible object
stores, each with a different permission model. Answering "who can access what?"
means logging into every system and translating three vocabularies by hand. Worse,
what operators *believe* is granted (code, runbooks, tribal knowledge) drifts from
what servers actually enforce, and the drift is invisible until an incident.

## Non-goal (the most important design decision)

**This tool is not an authorization plane.** It does not sit in the request path,
does not evaluate policies, and does not replace SpiceDB/OpenFGA-style engines.
Each target system already enforces access natively; copying that state into a new
engine creates a second source of truth that *will* diverge. Instead, the tool
reads native state, diffs it against declared intent, and emits/applies **native
commands** (`GRANT`/`REVOKE`, IAM config PUT). Enforcement stays where it is.

## Functional requirements

- **F1 — Access matrix (web).** A single web page showing subjects × resources
  across all connected systems, with access grades (none / read / write / admin)
  visually distinguished, plus per-cell drift badges.
- **F2 — Intent vs. actual diff.** Intent is a declarative file (TOML). Observed
  state is read live from each system. The diff is shown side by side on the web
  page and in the CLI.
- **F3 — Convergence with named revokes.** Permissions are additive: removing a
  line from intent does not remove it from the server. The plan must *enumerate
  every revoke by name* (`extra = observed − intent`). Revokes apply only to
  subjects listed in `managed_subjects`; drift on unmanaged subjects is reported
  but never auto-revoked.
- **F4 — Native command generation.** For every planned change, the exact native
  command is shown before anything is applied: SQL for PostgreSQL/ClickHouse, an
  identity-config mutation for S3.
- **F5 — Adapters.** PostgreSQL (roles, memberships, DB/schema/table grants,
  default privileges), ClickHouse (users, roles, db-scoped grants), S3-compatible
  storage (identities, bucket/prefix actions, IAM policies). Adding a system means
  implementing one small interface: `observe()`, `grant_cmd()`, `revoke_cmd()`,
  `apply()`.
- **F6 — Implicit defaults surfaced.** Adapters must know each system's hidden
  defaults and report them as observed grants. Concretely: PostgreSQL grants
  `PUBLIC` both `CONNECT` **and `TEMPORARY`** on every database when `datacl` is
  NULL — the adapter materializes these (via `acldefault()`) so revoking only
  `CONNECT` cannot silently leave temp-table creation behind.
- **F7 — Findings.** Beyond the grant diff, the tool reports conditions that
  native catalogs hide:
  - *Frozen ACL* — an owner whose relacl is an empty array has locked itself out;
    report with the recovery `GRANT`.
  - *Stale ClickHouse grants* — db-scoped grants surviving `DROP DATABASE`
    (ClickHouse has no `DENY`; stale grants revive if the name returns).
  - *S3 dual auth planes* — identities present in only one of static config /
    dynamic IAM (may authenticate nowhere; fails as a misleading 403).
  - *Policy shadowing* — an S3 identity with both native actions and an IAM
    policy: the policy wins; the matrix shows what is **enforced**, not written.
  - *Default privileges on a group role* — `ALTER DEFAULT PRIVILEGES` binds to
    the creating role; declaring it for a group covers nothing its members make.
  - *Naming drift* — synonymous role suffixes across systems (`_read` vs
    `_reader`) that make auditing impossible.
- **F8 — Audit log.** Every applied change appends who / when / which native
  command / success to an append-only JSONL log.
- **F9 — "Could not check" is a fact.** A scope the observer cannot read (a
  database it cannot connect to, an IAM endpoint that is down) is returned as
  an *unobserved scope*, never silently skipped: the diff plans neither grants
  nor revokes inside it (both would be guesses), affected intent grants are
  reported as *unverified*, and the matrix shows `?` — distinct from `—`
  ("no access"). Losing this distinction makes an audit unfalsifiable.
- **F10 — Dual-plane S3 with policy-aware writes.** The S3 adapter models each
  auth plane (static config file, dynamic IAM endpoint) as a separate config
  block with its own endpoint *and* credentials — keys are paired to their
  plane. `enforced` names the plane the gateway actually consults: effective
  grants and all writes go there. For a policy-bearing identity, grant/revoke
  mutates the policy document (the plan shows an old→new unified diff); the
  shadowed native action list is never edited, because changing dead config
  and reporting "access narrowed" would be a lie.

## Non-functional requirements

- **N1 — Read-only by default.** `plan` and `serve` never write. `apply` without
  `--write` is a dry-run; `--write` additionally asks for confirmation (skippable
  with `--yes` for automation).
- **N2 — Two-phase plan → apply.** All native commands are printed before any is
  executed.
- **N3 — Credential separation.** Observation uses read-only credentials; admin
  credentials are resolved only inside `apply --write`. All credentials come from
  environment variables named in config — never from code or config values.
- **N4 — Verify on the real auth path.** Validation must ride the same path real
  users take (TCP + password, not a local `trust` socket that skips password
  checks). Phase 1 documents this; phase 2 adds login-path probes.
- **N5 — Minimal footprint.** Core runs on the Python standard library alone; the
  demo needs zero infrastructure and zero third-party packages.

## Technology choice

Python ≥ 3.11, standard library only for the core (`tomllib` for intent/config,
`http.server` for the web UI, `urllib` for ClickHouse's HTTP interface, `json`
for S3 config planes). Rationale: adapters are thin SQL/HTTP/JSON glue where a
framework adds nothing; ops teams can run a zero-dependency tool anywhere Python
exists; and the web UI is a single server-rendered read-only page. The only
optional dependency is `psycopg` (extra: `grantline[postgres]`) for the live
PostgreSQL adapter. If the UI later needs interactivity (filters, approval
flows), that is the moment to introduce a framework — not before.

## Phases

**Phase 1 (this draft)**
- Normalized grant model; TOML intent; convergence diff with named revokes.
- Adapters: PostgreSQL (live via optional psycopg + fixture), ClickHouse (live
  via stdlib HTTP + fixture), S3 (config-file planes — the static file *is* the
  SSOT in SeaweedFS-style deployments).
- Web matrix (read-only, server-rendered), CLI `plan` / `serve` / `apply`,
  JSONL audit log, all F7 findings, bundled fixture demo.

**Phase 2 (done)**
- PostgreSQL multi-database observation and apply: one maintenance connection
  enumerates `pg_database`, memberships, and db-level ACLs; each target
  database (config `databases` / `exclude_databases` fnmatch patterns) gets
  its own connection for schema ACLs, table grants, default-privilege ACLs
  (keyed on database × schema × *creating role*), and frozen-ACL facts.
  A database the observer cannot enter becomes an unobserved scope (F9).
  `apply` routes each command to the database it belongs to — `GRANT … ON
  DATABASE` from anywhere, schema/table/default statements inside their DB —
  over autocommit connections, so statements that refuse transaction blocks
  (e.g. `CREATE DATABASE`, should a future version plan one) also run.
- S3 dynamic IAM plane promoted to read/write (F10): per-plane config blocks
  with paired endpoint+credentials, `enforced` plane selection, HTTP GET/PUT
  of the identities document (SeaweedFS-style config object) via stdlib
  urllib, policy-document writes with old→new diffs in the plan, cross-plane
  identity findings kept.
- Unobserved-scope model (F9) wired through diff, CLI, and web matrix.

**Phase 3 (historical status; current scope and limitations are in PRD 003)**
- ✅ Login-path verification probes (N4): `probe` asks each service as the
  subject. S3 is the real path (the subject's key, SigV4, the real endpoint);
  PostgreSQL is server-evaluated (`has_*_privilege`, labelled as not a login);
  ClickHouse resolves effective `SHOW GRANTS`; PostgreSQL and ClickHouse optionally
  verify subject logins when subject-specific credentials are configured. Neither reads data. Verdicts that
  contradict the table become findings. Also in the console (`/s/<subject>/probe`).
  The first live run found four bucket-wide grants the table over-claimed —
  which led to the SeaweedFS IAM-tree plane source (identities + groups + policies
  merged; native actions only when no policy exists).
- ✅ Snapshot history: `history` lists runs and compares any two (`--since 7d`,
  `--from/--to`), with the same unknown-vs-revoked rule as F8.
- ✅ Multiple instances per system type: the config section name is the
  instance, `type` the dialect; dialect logic asks `model.kind_of()`.
- ✅ Grantor on the model (PRD 003 F1's known gap) — "what did I grant".
- ✅ Portable identity source: the AWS-IAM-compatible query API (`iam_url_env`,
  POST form, SigV4 "iam") that SeaweedFS's gateway and AWS both answer — chosen over
  vendor admin APIs to keep compatibility. SeaweedFS's own tree is also read live
  (`filer_url_env`) or from a mirror (`dir`); only those carry the secrets probes need.
- ✅ Approval flow and notifications: `request` routes a change to the approvers the
  config names (`[approvals] admin` always, `[[approvals.rules]]` per team), one
  tokened link each, Slack DM/channel when a bot token is set; the stored command
  runs when the last approver says yes. `notify` posts what moved since the previous
  run.

## Success criteria (testable)

1. `python3 tests/test_diff.py` and `python3 tests/test_phase2.py` pass:
   named-revoke enumeration, implicit-default revocation, managed-subject
   filtering, group-role default-priv lint, naming drift; unobserved scopes
   plan neither grants nor revokes and are distinguished from "no access";
   policy-shadowed identities observe (and write) through the policy;
   per-database command routing.
2. `python3 -m grantline plan` on the bundled fixtures reports exactly 7 changes
   (3 grants — one an S3 policy diff — and 4 revokes including both implicit
   `PUBLIC` privileges), 1 unverified intent grant in the unreachable `hr`
   database, and 9 findings covering every F7 category plus F9.
3. Copying the fixtures, `apply --write --yes`, then `plan` again prints
   `Converged` — the loop actually converges.
4. Each applied change produces one JSONL audit entry with timestamp, OS user,
   system, native command, and success flag.
5. `apply` without `--write` modifies nothing (fixture files byte-identical).
6. `GET /` on `serve` returns the matrix with drift badges and all findings,
   renders `?` (not `—`) for intent grants in unobserved scopes, shows the
   S3 policy diff in the plan section, and reflects fixture edits on the next
   refresh (no cache).
7. No hostname, credential, or organization-specific value appears anywhere in
   the repository.
