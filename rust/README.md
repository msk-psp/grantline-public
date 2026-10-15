# Grantline — Rust + Leptos migration

Experimental **R1 + R2 + R3a/R3b/R3c/R3d/R3e1 foundation**, alongside the supported Python console.
This binary runs natively with no Python process. Commands are offline by default;
native PostgreSQL/ClickHouse catalogs and remote S3 IAM require explicit `--live`
and configured reader endpoints/credentials.
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

`plan` reads PostgreSQL/ClickHouse JSON fixtures and local S3 IAM files/directories.
It produces SQL previews, diagnostic levels/entities and per-identity/service
counts. Without `--live`, no environment credentials are resolved or service contacted.
The bundled S3 file provider is now observed. Remote providers require `--live`.
`plan --observed FILE.jsonl` imports a saved observation for any configured service; a service
missing from its header remains unread. Unsupported command generation is
reported per candidate. This CLI has no `apply` or `--write` command.

### Read a native ClickHouse catalog

Use the existing configuration shape, with the reader URL supplied in the named
environment variable outside the repository (including its HTTP/HTTPS port).
URL user/password values must be percent-encoded. Paths for a reverse proxy are
preserved; query strings and fragments are rejected. Standard HTTP/HTTPS default
ports apply when omitted. The client moves credentials from URL userinfo to
ClickHouse headers, refuses redirects and does not use environment proxies.

```toml
[adapters.warehouse]
type = "clickhouse"
url_env = "GRANTLINE_CH_URL"
read_timeout_seconds = 30
```

```sh
rust/target/debug/grantline-rs -c /path/to/grantline.toml plan --live --json
rust/target/debug/grantline-rs -c /path/to/grantline.toml graph --live --subject demo-user --json
rust/target/debug/grantline-rs -c /path/to/grantline.toml snapshot --live --json
```

The reader needs global `SHOW ACCESS`, `SHOW DATABASES` and catalog SELECT on
`system.grants`, `system.role_grants` and `system.databases`. Provision it through
the owner of the service. Use a server-enforced `readonly=2` profile so bounded
per-query settings can be applied. The client requests `readonly=2` and sends
only catalog reads, never GRANT/REVOKE or arbitrary SQL. `admin_url_env`, probe
credentials and `env_file` are not resolved. `--observed` conflicts with `--live`.
This is catalog observation, not a target user's login/data-access probe.

The whole instance remains unknown if visibility cannot be established or any
query fails, has invalid/incomplete JSON, or exceeds 10,000 rows / 16 MiB. The
total observation deadline is 30 seconds by default (`1..120` configurable).
Queries cap execution, scan and result size; they never accept partial results.
Responses and transport errors are withheld from diagnostics to prevent echoing
credentials. HTTPS uses verified rustls certificates with bundled Mozilla roots;
private CA configuration and positive HTTPS integration are not yet covered.

Column grants, partial revokes, parameterized/ambiguous scopes and their role
dependants remain unknown. GRANT/ADMIN delegation is reported separately because
grant atoms do not model it. On older servers, `system.grants` can erase prefix
wildcard information: bounded `SHOW GRANTS` batches check for it, and any prefix
wildcard makes the instance unread. Global, DB, table and nested-role permissions
remain distinct. Catalog reads across requests are not an atomic transaction;
writer/probe support is still pending.

### Read native PostgreSQL catalogs

PostgreSQL **16+** uses only the explicitly named `dsn_env` reader. Put a libpq
key/value DSN or PostgreSQL URI in that environment variable, outside the repo.
Specify one TCP host, user and maintenance database; Unix sockets, multi-host,
`hostaddr`, service files and caller-supplied `options` are unsupported. `PG*`
environment credentials, `admin_dsn_env`, probe credentials and `env_file` are
never consulted. Database names are passed through the driver's config API.

```toml
[adapters.database]
type = "postgres"
dsn_env = "GRANTLINE_PG_DSN"
databases = ["*"]
exclude_databases = ["scratch_*"]
read_timeout_seconds = 30
```

Use the same `plan/graph/snapshot --live` commands as above. TLS is required by
default (including `sslmode=prefer`) and verifies the host certificate with
bundled Mozilla roots. `sslmode=disable` explicitly permits plaintext, for
example on the disposable loopback test server. Libpq `verify-full` spelling,
private CA/client certificates and positive TLS integration are not supported
in this unit; there is no certificate-verification bypass.

The reader should have catalog SELECT and CONNECT to the maintenance/target
DBs, without data or write grants. Provision it through the service owner.
Each connection runs a repeatable-read, read-only transaction with a fixed
`pg_catalog` search path, statement/lock/idle limits and a total per-instance
client deadline (`1..120` seconds). Read-only session defaults are requested,
not a replacement for server-side least privilege. Only fixed catalog SELECTs
are issued. No arbitrary SQL, login probe, GRANT/REVOKE or data query runs.

The observer materializes implicit PUBLIC DB permissions and owner ACLs,
retains grantor/source metadata, nested role memberships and schema-specific
default table privileges keyed by creating role. Empty table ACLs produce the
owner-lockout finding using `cardinality(relacl)=0`; PostgreSQL can store an
empty ACL with array dimensions that make equality to `'{}'` false. Raw role
names come from catalog joins, avoiding the quoting introduced by `regrole`.

An unread/excluded DB obscures its table/schema/default scopes and discards any
partial rows from that DB. A maintenance failure, total deadline or catalog cap
failure at the cluster level obscures the entire instance. Limits are 10,000
rows/16 MiB per query, 128 DBs and 100,000 aggregate grants. The protocol driver
may buffer an individual wire message before the row byte check; this is not a
memory-isolation boundary against a malicious server.

Unrepresentable dotted/`@`/wildcard resource components obscure the affected DB
(or the cluster for DB identifiers). Column ACLs obscure table scopes in their
schema. Global default table ACLs obscure all default scopes in that DB.
Superusers, predefined roles and memberships with disabled INHERIT/SET options,
including their dependants, remain unknown. Delegation options get findings;
MEMBER and grant atoms do not model them. These safeguards intentionally exceed
the Python reader. The target is DB/schema/table/default-table ACLs and role
memberships; sequence/function/type ACLs, effective RLS, owner powers, target-user
login/data access and a cluster-wide atomic snapshot are not represented.

### Verify PostgreSQL ACLs (R3e1)

`probe --live` checks observed atoms using fixed `has_*_privilege` and
`pg_has_role(..., 'MEMBER')` queries. Without `--live`, all probes are unknown
and no network credentials are resolved. It never reads application rows or
executes DML, DDL, GRANT, REVOKE or SET ROLE. Checking an INSERT/DELETE privilege
is a SELECT of ACL metadata, not an attempted write.

```sh
rust/target/debug/grantline-rs -c /path/to/grantline.toml probe --live --system database --subject demo-user --json
rust/target/debug/grantline-rs -c /path/to/grantline.toml probe --live --observed /path/to/baseline.jsonl --system database --json
```

The first command observes the selected services before checking their atoms.
The second uses the saved baseline and only contacts the configured probe
connections: it can expose grants that were revoked after the snapshot. No
candidate is invented from intent, wildcard expansion or an empty observation.
`--system` filters services before observation; `--subject` filters observed atoms.
Probe selection is capped at 1,000 atoms and 128 connection groups per adapter.
An unread baseline remains visible in `unobserved`; an empty probe list proves
no access outcome. All CLI results are informational; an unknown/deny verdict
does not make the process exit nonzero. Inspect `summary` and `findings` in CI.

By default the named reader asks the server about a subject's ACLs. Results say
**server-evaluated, not a login**: they do not prove that subject can authenticate.
To verify an actual subject TCP login as well, explicitly map its DSN:

```toml
[adapters.database.probe_dsn_envs]
"demo-user" = "GRANTLINE_DEMO_USER_DSN"
```

The connection must report both `session_user` and `current_user` as that exact
subject before any allow/deny is reported. A missing/bad mapped credential or
identity mismatch remains unknown; it never falls back to the reader or admin.
The same TCP/TLS/DSN restrictions apply as for observation. Database selection
and exclusions are honored; schema/table checks use their own DB and a subject
CONNECT check logs into the target DB. Reader CONNECT checks use its maintenance DB.

`allow`/`deny` mean a definite ACL evaluator result; connection, auth, SQL, null,
and unsupported cases are **unknown**. PUBLIC, default ACL resources, wildcard
resources and composite `ALL` requests have no evaluator in this unit. Quoted
identifiers are handled as exact parameters, not executable SQL. Savepoints keep
one missing role/object from poisoning later checks. Each probe adapter has a
separate total deadline using `read_timeout_seconds`; an expired deadline discards
partial results. Observation has its own deadline. Both use read-only transactions,
fixed catalog search paths and existing statement/lock limits.

The findings compare definite outcomes with the exact saved/observed grant
atoms, as in Python. ACL checks do not establish schema traversal, RLS outcomes,
row availability, owner DDL powers, SET ROLE behavior or end-to-end data access.
Subject login is subject to the server's authentication configuration (the
isolated integration server uses trust authentication). ClickHouse/S3 probes,
writes and production/staging validation remain pending.

### Read remote S3 IAM sources

Each S3 plane can name exactly one remote reader. It takes precedence over a
local file/dir; an unread remote source never falls back to that local data.
Use `plan/graph/snapshot --live`; offline commands and `--observed` never resolve
remote credentials or contact the service. The timeout is per plane (`1..120`
seconds, default 30).

```toml
[adapters.object-store]
type = "s3"
enforced = "dynamic"
read_timeout_seconds = 30

[adapters.object-store.planes.dynamic]
filer_url_env = "GRANTLINE_FILER_URL"
# filer_auth_env = "GRANTLINE_FILER_READER_TOKEN" # optional bearer
```

Choose one of these shapes per plane:

| Source | Reader fields | Behavior |
|---|---|---|
| JSON config | `url_env`, optional `auth_env` bearer | GET one complete identities document with actions/policies |
| SeaweedFS Filer | `filer_url_env`, optional `filer_auth_env` bearer | GET `/etc/iam/` identities, groups, managed policies and policy index |
| SeaweedFS IAM Query | `iam_url_env`, `iam_key_env`, `iam_secret_env`, optional `iam_session_token_env` | SigV4 POST of fixed List/Get operations, service `iam`, region `us-east-1` |

URLs use HTTP(S) without userinfo, query or fragment; reverse proxy prefixes
are retained. IAM endpoint paths use unescaped ASCII path characters. Credentials
stay in headers, never URL parameters/output/snapshots. `admin_*`, probe and
ambient AWS credentials are not consulted. Redirects and environment HTTP proxies
are disabled. HTTPS verifies certificates against bundled Mozilla roots; custom
`ca_bundle_env` is explicitly unsupported rather than ignored. Plain HTTP requires
an explicitly configured HTTP URL. Positive TLS/private CA integration remains
unverified.

Filer listing pagination follows `ShouldDisplayLoadMore` and `LastFileName`,
checks directory/entry paths, ordering and duplicates, and requires listed files
to be readable JSON. Missing optional groups/policies directories or the policy
index can be empty; a missing identities directory or listed file is a failure.
This assumes the reader has visibility over the complete IAM tree. Native actions,
user inline/managed policies and group inline/managed policies share the existing
policy evaluator. Empty attached policies still shadow native actions. Missing
managed documents obscure their users. Raw Filer credential fields are discarded.

IAM lists paginate using `IsTruncated`/`Marker` and fetch actual attached ARNs and
default policy versions. User policy failures, permissions boundaries and users
without policies stay unknown: IAM does not return SeaweedFS native actions. A
bootstrap account can be listed while its attached-policy API returns 404; that
subject stays unknown without discarding other observed users. Collection/group
failures obscure the whole plane. XML DTDs, duplicate fields and malformed/incomplete
collections are rejected. Direct and inherited policy routes remain distinct.

Limits are 4 MiB per response, 64 MiB total, 512 requests per plane and 10,000
items per collection. A timeout/cap/partial collection cannot become empty access.
Remote IAM is read-only: no merged document preview, PUT or policy mutation is
available. The server must also enforce its own read/write separation. Sequential
requests are not an atomic snapshot. These are SeaweedFS identity-policy reads,
not AWS effective-access evaluation (SCPs, resource policies, role/session policies,
permission boundaries and target-user login/data access are not established).

### S3 IAM files and previews

Existing `[adapters.NAME]` sections with `type = "s3"`, `enforced = "dynamic"`
and `[adapters.NAME.planes.dynamic] file = "iam.json"` work unchanged. A plane
can instead use `dir = "iam-mirror"`, containing `identities/`, optional
`groups/`, `policies/` and `policies.json`. Paths follow the selected config.
Only the enforced plane supplies grants. Other readable planes identify accounts
that exist where the gateway does not consult them. Unread/invalid planes remain
unknown and their source contents are not included in errors.

IAM policy takes precedence over native actions. Exact Deny pairs are subtracted;
unsupported conditions, negative policies and overlapping denies remain unknown.
Bucket discovery and `StringLike s3:prefix` listings are observation-only
capabilities, never recursive object grants. Group and inline policy routes are
retained; unknown identities and identities with cancelled allows do not expose
misleading membership paths. Malformed trees or conflicting policy route names
remain unread. An attached empty policy still shadows native actions.

JSON `s3_previews` contains one final `before`/`after` document per identity,
combining all grant/revoke candidates. It contains policy or action data, never
the identity's credential records. `changes` indexes refer to the report's
permission candidates. `creates_identity` marks a new identity; credentials
would still need separate provisioning. These documents are review previews,
not shell commands or applied changes. Text output prints the same documents.

Directory trees are read-only: no per-user preview may rewrite a group's shared
policy or turn inherited grants into an inline copy. Unsupported capabilities,
prefix-List writes and transformations that cannot reproduce the requested
normalized grants exactly are blocked with a reason. Snapshots lack original
policy documents, so imported observations generate no S3 document previews.

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
- R3a interprets local S3 IAM planes and produces grouped document previews,
  with conservative policy evaluation, missing-policy and cross-plane diagnostics.
- R3b reads native ClickHouse catalogs through an explicit reader with `--live`.
- R3c reads PostgreSQL 16+ catalogs with per-DB unread scopes and read-only transactions.
- R3d reads remote S3 JSON/Filer/IAM sources with bounded collections and no write preview.

## What remains

Probes and native writes, production authentication,
durable approvals, real Slack/GitHub writers, all existing console pages,
WASM map interactions, four-language UI and release images are later stages.
Live S3 document writes and all probe paths remain in R3. Approval, a
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
python3 scripts/check_rust_s3.py
python3 scripts/check_rust_clickhouse.py --docker
python3 scripts/check_rust_postgres.py --docker
python3 scripts/check_rust_s3_network.py --docker
```

The checks cover canonical grants, coverage, convergence actions, diagnostic
levels/entities, deterministic fixture explanations, PG/CH SQL previews,
Python/native snapshot round trips, history and graph structure/paths. Python's
arbitrary choice among equally covering grants is compared by the requested
atom, not the incidental wording naming one covering grant. S3 checks add native
actions, policy precedence, Deny, prefix capabilities, IAM trees, document grouping
and unchanged source files. Rust additionally marks capabilities unknown when a
policy is incomplete/missing, keeps empty attached policies authoritative and
blocks previews that cannot exactly realize the requested grant set. Those safety
boundaries intentionally exceed the Python oracle. Production/staging observation,
actual writers, performance and production integration remain unverified. The ClickHouse
suite uses loopback HTTP failure scenarios and a disposable official 26.6.2.160
server pinned by multi-platform image digest. It checks actual SQL, nested roles,
unsupported scopes, stale grants, visibility and a server-refused POST write;
the container is removed afterwards. `--docker-context NAME` selects an explicit
local Unix-socket context; remote Docker hosts are refused. Without `--docker`,
only the HTTP protocol suite runs.

The PostgreSQL suite checks missing/invalid DSNs, stalled authentication deadlines,
offline/import isolation, secret redaction and a digest-pinned official PostgreSQL
17.11 server. It verifies PUBLIC/owner ACLs, raw quoted names and grantors, nested
roles, per-DB failures/exclusions, frozen ACLs, global/column/default boundaries,
graphs, snapshots, TLS downgrade refusal and read-only DDL failure. Its disposable
container is removed afterwards; no production/staging server is contacted.

The S3 network suite checks three loopback HTTP readers, SigV4 against the Python
oracle, Filer/IAM pagination, malformed/failed/truncated responses, source and
credential isolation, visibility boundaries, graph paths and snapshots. Its
immutable official SeaweedFS 4.48 image verifies actual IAM signatures, user/group
inline and managed policies, Filer storage and server-enforced IAM write refusal.
Only task-owned containers/fixtures are created and removed. The Python reference
omits some policy attachment types; those cases have independent server assertions.
