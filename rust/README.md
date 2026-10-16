# Grantline — Rust + Leptos migration

Experimental **R1 + R2 + R3a/R3b/R3c/R3d/R3e1/R3e2/R3e3/R3f/R3g1/R3g2/R3g3/R3g4/R3h1/R3h2 foundation**, alongside the supported Python console.
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
reported per candidate. Explicit `apply` writes have separate boundaries below;
`plan` never applies its previews.

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
read-only probes below resolve ACLs separately; R3h1 adds the narrow writer below.

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
isolated integration server uses trust authentication). Native writes and
production/staging validation remain pending.

### Verify ClickHouse ACLs (R3e2)

Use the same `probe --live --system warehouse --subject demo-user --json` command.
Without `--observed`, the selected services are observed first; with
`--observed`, only probe requests use the saved atoms. Offline mode never resolves
network credentials. Native ClickHouse probes resolve the ACLs with
`SHOW GRANTS FOR <subject> WITH IMPLICIT FINAL` using `url_env`, or a separately
named `probe_url_env`. Missing explicit probe credentials never fall back.
`admin_url_env` is never consulted.

```toml
[adapters.warehouse]
type = "clickhouse"
url_env = "GRANTLINE_CH_READER_URL"
# probe_url_env = "GRANTLINE_CH_PROBE_URL" # optional dedicated ACL observer
read_timeout_seconds = 30

[adapters.warehouse.probe_url_envs]
"demo-user" = "GRANTLINE_CH_DEMO_USER_URL" # optional actual subject HTTP login
```

Observer mode needs permission to SHOW GRANTS for the named user/role (normally
SHOW USERS / SHOW ROLES, or SHOW ACCESS). Its results explicitly say **not a login**.
The dedicated observer credential is useful with a saved baseline, independently
of catalog-reader visibility. A subject mapping takes precedence over both
observer credentials. It must pass `SELECT currentUser() AS user LIMIT 1` with
an exact identity match before any verdict; bad/missing credentials, identity
mismatches and HTTP failures are unknown, without fallback. The integration test
uses a real SHA256-password subject login.

`FINAL` resolves all granted roles, including ones not enabled by default. This
is a server-resolved ACL statement even after verifying a login; it is not proof
of role activation, effective session restrictions, row policies or data access.
`MEMBER` uses a separate plain SHOW GRANTS and means a **direct role grant**,
not transitive membership or activation. No SET ROLE or EXECUTE AS is attempted.
`CHECK GRANT INSERT` is deliberately not used: `readonly=2` can make it return 0
for a stored INSERT grant. All requests remain read-only.

The parser accepts only complete GRANT statements for the exact subject, handles
quoted identifiers and keeps global/DB/table scopes separate from named engine
or external-source scopes. Unresolved REVOKE, column grants, prefix wildcards,
unknown grammar/escapes or partial responses make that subject unknown. No
partially parsed permissions produce an allow. Exact supported privilege or ALL
coverage can allow; absence can deny SELECT, INSERT, OPTIMIZE, TRUNCATE and dictGet.
For other supported groups (ALTER/CREATE/DROP/SHOW/ALL), and concrete
SHOW ACCESS/DATABASES/TABLES/COLUMNS/USERS/ROLES, ALTER UPDATE/DELETE and
CREATE/DROP TABLE/DATABASE operations, absent exact coverage remains unknown because
privilege-group expansion is not implemented. Unsupported resources/privileges
remain unknown. Wildcards in requested resource names are not expanded.

The shared HTTP client preserves explicit URL/TLS/header-credential/proxy/redirect
safeguards and the 10,000-row / 16 MiB response limit. Queries have server scan,
result and execution limits; SHOW grammar has no LIMIT clause. Each parsed
statement is limited to 64 KiB, identifiers to 1 KiB and parsed permissions/roles
to 10,000 each. A single `read_timeout_seconds` deadline spans
all probe subjects and discards partial results on expiry, separately from
observation. Selection is capped at 1,000 atoms and 128 subjects per adapter.
Services and subject filters, summary, findings and exit status follow the
PostgreSQL probe contract. No data, grants, roles or service config are changed.

Run `python3 scripts/check_rust_clickhouse.py --docker` for HTTP failure guards,
identity/credential isolation, partial-result deadlines, real inherited/scoped
ACLs, partial/column unknowns, password login, default-role distinctions and
independent server-side write refusal. Positive TLS integration, custom CA,
production/staging connections remain unverified; the narrow R3h1 writer is described below.

### Verify S3 List/Read samples (R3e3)

Use `probe --live --system object-store --subject demo-user --json`, optionally
with `--observed /path/to/baseline.jsonl`. Service/subject selection, informational
exit status and saved-baseline findings follow the probe contract above. Only
observed atoms are checked. Offline mode performs no network activity.

S3 uses the data endpoint, separately from the IAM/Filer observer. Explicitly map
each subject's access key and secret through named environment variables:

```toml
[adapters.object-store]
type = "s3"
enforced = "dynamic"
endpoint_env = "GRANTLINE_S3_DATA_ENDPOINT"
probe_region = "us-east-1"
read_timeout_seconds = 30

[adapters.object-store.probe_credentials."demo-user"]
key_env = "GRANTLINE_DEMO_USER_KEY"
secret_env = "GRANTLINE_DEMO_USER_SECRET"
# session_token_env = "GRANTLINE_DEMO_USER_TOKEN" # optional temporary credential

# Optional full bucket-relative key, useful when the subject cannot List.
[adapters.object-store.probe_objects]
"bucket:example/team" = "team/sample.txt"
```

Keep the existing `planes` configuration for observation. IAM document secrets,
reader/admin credentials and ambient AWS credentials are never used for probes.
The operator must bind each key to the correct subject; no STS identity lookup
verifies that mapping. Config stores variable names, not secret values.

`List` issues SigV4 ListObjectsV2 with `max-keys=1`, `encoding-type=url` and an
exact directory prefix. `Read` HEADs the configured sample, or one listed key;
it never downloads an object body. List and Read share the sampled listing for
the same subject/scope. An empty listing can allow List but leaves Read unknown.
One readable object does not establish access to every object in the prefix.
Explicit samples must remain inside the requested prefix; sampled names never
appear in output. Use normalized resource names in `probe_objects`.

Only concrete `bucket:name[/prefix]` List/Read atoms are supported. Write, Admin,
capabilities, roles and unresolved wildcard scopes remain unknown; no write
verb is sent. Existing grant normalization removes trailing `*` and `/` before
selection. Listings accept percent encoding and SeaweedFS form-style `+` spaces
(literal plus is `%2B`). Paths preserve spaces, `+`, `%` and Unicode, while traversal
segments are rejected. Path-style DNS buckets only: access points, virtual-host
routing, S3 Express and version-specific probes are not implemented.

Allow requires a valid scoped XML listing or a successful HEAD with object
metadata. Deny requires HTTP 403 with explicit S3 `AccessDenied`; invalid keys,
signatures/tokens/regions, generic HEAD 403/404, malformed/partial XML, redirects
and transport/service failures remain unknown. A HEAD 403 alone cannot distinguish
an unreadable object from a nonexistent object when List is unavailable.

Each adapter has one `read_timeout_seconds` deadline (1–120 seconds), at most
1,000 atoms, 128 subjects, 512 requests, 1 MiB per response and 16 MiB total.
Deadline/aggregate/request exhaustion discards earlier partial results. HTTPS
uses verified bundled roots; redirects and environment proxies are disabled.
Custom `ca_bundle_env` is explicitly unsupported. Errors do not expose raw
responses, credentials or sample keys. Positive TLS/private CA and AWS deployment
integration remain unverified; the actual server test uses isolated SeaweedFS.

Run `python3 scripts/check_rust_s3_probes.py --docker` for independent SigV4
HTTP checks, error/scope/budget guards, credential isolation and official
SeaweedFS List/HEAD, explicit samples and independent write refusal.

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

### Apply one ClickHouse table ACL (R3h1)

Opt in to one direct SELECT or INSERT grant/revoke on an existing UUID-backed
Memory/MergeTree table in an Atomic database:

```toml
[adapters.ch]
type = "clickhouse"
admin_url_env = "GRANTLINE_CH_WRITER"
clickhouse_write_tables = ["table:demo.events"]
read_timeout_seconds = 30
```

The named HTTP(S) URL must include an explicit authenticated user. Credentials
travel only in headers; redirects and environment proxies are disabled. Reader,
probe and ambient credentials never supply the writer. Use a direct endpoint for
one server, with no concurrent ACL/identity/table administration. Global visibility
requires SHOW ACCESS/SHOW DATABASES plus the catalog reads for users, roles,
role_grants, grants, databases and tables. The writer additionally needs a **direct
exact-table GRANT OPTION** for the selected privilege; inherited/broader authority
is deliberately insufficient. No user/role creation or role switching occurs.

```sh
rust/target/debug/grantline-rs -c /path/to/grantline.toml apply --system ch --live --json
rust/target/debug/grantline-rs -c /path/to/grantline.toml apply --system ch --live --write --expect PLAN_ID_FROM_PREVIEW --json
```

Intent uses `table:demo.events` with exact SELECT or INSERT. A single invocation
may change **at most one permission atom**; two privileges or a simultaneous grant
and revoke need separate intent/preview reviews. Declare existing memberships and
other direct ACLs you want to retain for managed subjects. Unchanged declared
memberships remain read-only; any planned membership change is refused. Recipients
must exist in local_directory, with unambiguous names/UUIDs, and cannot be the
writer or a role in its ancestry. Broad/delegated/column/partial/parameterized or
unsupported direct recipient ACLs refuse the plan, except exact opt-in DB scopes
described below. Table-only config does not authorize DB scopes; R3h2 below adds an independent
DB opt-in. No global/role writes, ALL,
ON CLUSTER, REPLACE OPTION, views, Distributed/Replicated tables or replicated
access storage. Legacy prefix wildcard grants can refuse the whole observation.

Plan-ID v2 (fresh preview required for older IDs) binds input bytes, non-secret endpoint, authenticated user/server UUID,
full principal IDs/storage and raw direct grants/role edges, database IDs and all
allowlisted table UUIDs/engines/DDL. Allow at most 128 combined table/DB scope entries and 1000 intent grants. Catalog reads bracket the existing observer
and must agree. All read queries retain row/byte/scan/time caps and readonly=2.
The state and input files are refreshed immediately before a single bounded POST
with readonly=0. The post-check requires exact expected raw ACLs, unchanged other
bound metadata and convergence. No data query or session impersonation is issued
by the writer. A successful receipt keeps `effective_access_verified=false` and
confirms this observed server's direct ACL state only.

**No multi-statement transaction or automatic rollback exists here.** Any dispatch
error/timeout/HTTP exception or post-check failure reports **outcome unknown**;
inspect direct ACLs before retrying or preparing an inverse. The writer never
retries, follows a write redirect or sends compensating SQL. Even success is not
a catalog compare-and-swap or a cross-node replication guarantee. Use controlled
administration; external changes can occur between reads and the statement.
Undo requires newly reviewed inverse intent. Data inserted while INSERT was
active is not undone by revoking that permission.

Run `python3 scripts/check_rust_clickhouse_writer.py --docker` for HTTP failure
injection and official ClickHouse 26.6.2.160 grant/revoke/inverse and actual
SELECT/INSERT/denial checks. Other versions, positive TLS/private CA, production,
concurrent administration and crash/restart around dispatch are unverified.
See [GRANT](https://clickhouse.com/docs/sql-reference/statements/grant),
[REVOKE](https://clickhouse.com/docs/sql-reference/statements/revoke) and
[system.grants](https://clickhouse.com/docs/operations/system-tables/grants).

### Apply one ClickHouse database ACL (R3h2)

DB scopes use a separate, default-empty allowlist. A table entry never grants
permission to rewrite its parent database scope, or vice versa:

```toml
[adapters.ch]
type = "clickhouse"
admin_url_env = "GRANTLINE_CH_WRITER"
clickhouse_write_databases = ["db:demo"]
```

Intent uses `resource = "db:demo"` and exact SELECT or INSERT. This generates
a quoted `GRANT SELECT ON demo.* TO ...` or a newly reviewed REVOKE, still
**one atom per invocation** with `--live --write --expect PLAN_ID`. The authenticated writer
must directly hold the same DB-scope privilege WITH GRANT OPTION. A table grant,
other DB, inherited role or global authority is not substituted for that row.
Unchanged managed memberships and unrelated direct ACLs must stay in intent.

**A DB allowlist authorizes all existing and future table/relation names and
engines in that DB**, including views and tables created after the write. It is
not a frozen list of today's Memory/MergeTree tables. Use an existing UUID-backed
Atomic database; an empty database is valid. Global/system/dropped/prefix DB
scopes, role membership changes, grant options and partial revokes stay refused.
Table-specific opt-ins retain R3h1's engine restrictions.

Before planning, bind the DB UUID and every current contained table UUID/engine/
DDL. New/dropped/recreated tables, views, schema changes or same-name DB recreation
after preview require a new plan. The CLI and JSON receipt flag
`database_changes_include_future_tables=true` for DB change plans. The row/scan/
byte/time caps, full raw ACL postconditions and outcome-unknown behavior are shared
with R3h1. There is no multi-statement rollback, automatic retry or concurrent-admin
compare-and-swap; use a direct server endpoint and controlled administration.

The union of held and declared direct DB/table grants for the same subject, DB
and SELECT/INSERT privilege must not overlap. Broadening can coalesce narrower
rows, and narrowing/revoking can erase intended rights or create partial revokes;
such transitions require separate manual reconciliation. A different privilege or
a different DB can be retained. After DB revoke, inherited role paths can still
allow access and inserted data remains. The receipt does not claim effective
access or data restoration. Review an inverse separately.

`python3 scripts/check_rust_clickhouse_database.py --docker` verifies actual
current/view/future/empty-DB SELECT/INSERT, other-DB denial, role propagation and
residual access, quoted DBs, exact inverse/data preservation, stale DB/table/DDL/
ACL/source/session and unsafe scope refusal on official ClickHouse 26.6.2.160.
It reuses the full HTTP failure/timeout/redirect/postcondition injection suite
for DB statements. See [GRANT scope](https://clickhouse.com/docs/sql-reference/statements/grant#wildcard-grants)
and [partial REVOKE](https://clickhouse.com/docs/sql-reference/statements/revoke#partial-revokes).

### Apply one ClickHouse role membership (R3h3)

```toml
[adapters.analytics]
type = "clickhouse"
admin_url_env = "GRANTLINE_CH_WRITER_URL"
membership_write_roles = ["analytics_reader"]
```

Use an existing `role:analytics_reader` resource with `privs = ["MEMBER"]` in
intent. The allowlist contains literal role names and defaults to empty. It is
independent of table/DB ACL lists; one invocation still changes at most one atom.
Preview with `apply --live --system analytics`, review the SQL and plan ID, then
run with `--write --expect PLAN_ID`. Old v2 plans require a fresh preview (v3).

The authenticated writer must directly hold ADMIN OPTION on the exact role.
Global ROLE ADMIN or inherited ADMIN alone never substitutes. New memberships
have no ADMIN OPTION and use the account's existing DEFAULT ROLE ALL policy;
accounts with explicit lists/exceptions or NONE are refused. Existing option
mismatches require manual reconciliation. Roles and recipients must already
exist in local_directory with UUIDs; writer/ancestor recipients and self/cycles
are refused. Target role chains may hold only ordinary exact table/DB SELECT or
INSERT, without delegation, global/system/column/partial/parameterized scopes.
Unchanged memberships outside the allowlist can remain declared read-only.

**The role allowlist authorizes its current and future privileges**, including
inherited privileges and propagation to accounts under a recipient role. It is
not a frozen object list; separately review the role's owners and future changes.
The CLI and JSON `membership_changes_affect_dependants` flag disclose this scope.
Inspect the role graph and ACLs before approval. Default-role/grantee policies
and full raw role UUID/default/admin rows are bound to the reviewed plan, along
with all direct ACLs, principal IDs and source/session state. Authentication
parameters are never read. Changing a role's ACL, UUID, membership options,
default-role policy or inputs invalidates an older review.

The result confirms one server's exact direct membership, unchanged other
catalog state and plan convergence. `effective_access_verified=false` remains:
other role paths or active sessions can retain access after a revoke. No session
switching, role/default-policy creation, ADMIN grants, REPLACE, ON CLUSTER,
transaction, CAS or multi-statement rollback is supported. After dispatch failure
inspect state before any retry; inverse intent requires a fresh review. Only the
membership row is undone, never inserted data or future role administration.

`python3 scripts/check_rust_clickhouse_membership.py --docker` verifies isolated
HTTP uncertainty and official 26.6.2.160 grant/revoke/inverses, real SELECT/INSERT
and denial, nested/quoted roles, retained/alternate/future privileges and unsafe
or stale-state refusal. Per `agent-query-safety`, catalog reads retain row/scan/
byte/time caps and readonly=2; writes remain a separate single POST.

### Apply PostgreSQL table, schema and database ACLs (R3g1/R3g2)

The SQL writer supports **existing ordinary tables and schemas in one database,
and ACLs on that same database**. Supported schema privileges are USAGE/CREATE;
database privileges are CONNECT/CREATE/TEMPORARY. Use canonical `TEMPORARY` in
intent; the `TEMP` alias is refused to avoid a nonconvergent plan.
It uses the existing native planner. Role changes require the separate R3g3
opt-in described below and cannot mix with object changes. Default privileges
require the separate R3g4 allowlist and a default-only change plan. Declare any already-held permissions you intend to retain
for managed subjects. Only catalogs in the selected database (and shared role/database ACLs) are observed here;
this is not a cluster-wide reconciliation or effective-access check.

```toml
[adapters.pg]
type = "postgres"
dsn_env = "GRANTLINE_PG_READER"          # existing plan/probe reader
admin_dsn_env = "GRANTLINE_PG_WRITER"   # separate, explicitly named write credential
databases = ["demo"]                   # one literal name; no exclusions/globs
```

Supply the write DSN via the named environment variable outside Git. It must
name that exact database, a user and a single TCP host. The existing reader TLS
rules apply: `sslmode=disable` is an explicit plaintext choice for a trusted local
fixture; other modes require verified TLS without downgrade. Ambient `PG*`, probe
mappings and `dsn_env` never supply writer credentials. The write role needs
permission to lock affected tables and issue the owner-originated grants/revokes;
logging in as the object owner works without requiring a superuser.

```sh
# Preview requires explicit network consent; runs a read-only transaction.
rust/target/debug/grantline-rs -c /path/to/grantline.toml apply --system pg --live --json
# Review the returned SQL and identifier, then apply exactly the current plan.
rust/target/debug/grantline-rs -c /path/to/grantline.toml apply --system pg --live --write --expect PLAN_ID_FROM_PREVIEW --json
```

The identifier binds input bytes, non-secret endpoint, authenticated session,
server start, database/schema/table/role object identities, catalog ACL state and fixed
quoted SQL. Passwords are not included in the identifier or receipt. A server
restart, a changed object/ACL/role, another login or changed input requires a new
preview. The R3g4 plan-ID format is v4; older IDs need a fresh preview after upgrading. Dry-run and no-op calls create no files and commit no ACL changes.
Only exact supported object privileges are accepted. ALL, PUBLIC/owner/privileged targets,
column privileges, non-owner grantors, grant options, views, partitions and
inheritance are unsupported. These conservative restrictions can refuse the
whole plan even when only one candidate would be unsafe.

Writing first takes a nonblocking transaction advisory lock with reserved keys
`(1196576334, 1)` in the connected database. This serializes all plans from this
writer version, including schema/DB-only plans. It then takes sorted
`ACCESS EXCLUSIVE NOWAIT` locks on affected tables in the same READ COMMITTED
transaction, refreshes the reviewed state and executes generated GRANT/REVOKE
with RESTRICT. Exact table/schema/database ACLs, including grantor/grant option,
object identities/ownership and the remaining plan are checked before COMMIT.
A pre-commit failure rolls everything back. **Table locks briefly block table
queries**, so use a controlled maintenance window. Advisory locks are cooperative:
raw SQL, older writers and other catalog administrators do not participate.
Neither this advisory lock nor relation locks freeze role/namespace/database
administration. Concurrent administrators are outside this unit's guarantee.
See PostgreSQL's [advisory locking](https://www.postgresql.org/docs/17/explicit-locking.html#ADVISORY-LOCKS)
and [LOCK documentation](https://www.postgresql.org/docs/17/sql-lock.html).

A commit transport error is reported as **outcome unknown**: inspect the catalog
before any retry. A successful receipt reports a committed direct ACL transaction
and `effective_access_verified=false`. Test subject access separately with `probe`.
To undo, edit intent, preview the inverse and review its new identifier. The S3
`restore` command does not restore PostgreSQL; inverse intent does not restore
ACL NULL/array storage representation, role state or database data. The official
fixture tests full mixed-scope rollback on SQL errors, timeouts and ineffective
warning-only grants, stale schema/database identity/ownership/ACL refusal,
cooperative lock contention/release, and a reviewed inverse. Direct ACL revocation
does not remove privileges inherited from PUBLIC or roles and does not terminate
existing sessions. This receipt still does not prove effective access. Production writes,
network loss during COMMIT and general disaster recovery are unverified.

### Apply creator-specific default table privileges (R3g4)

Default off. Authorize exact existing `default:database.schema@creator` resources:

```toml
[adapters.pg-defaults]
type = "postgres"
admin_dsn_env = "GRANTLINE_PG_CREATOR"
databases = ["demo"]
default_write_scopes = ["default:demo.app@app_creator"]
```

The named DSN must authenticate as **app_creator** in **demo**. The creator may
hold CREATE on the schema without owning it, and must be an ordinary role; no SET ROLE, borrowed identity or superuser fallback occurs.
Intent uses `resource = "default:demo.app@app_creator"` and exact table privileges
such as `privs = ["SELECT", "INSERT"]`. Run `apply --system pg-defaults --live
--json` for a read-only preview, then separately add `--write --expect PLAN_ID`.
Plans may change defaults only; preserve existing managed object ACLs in intent.
Unchanged defaults outside the write allowlist remain read-only. Use a separate
scope/credential per creator. No role/schema creation,
PUBLIC/predefined/privileged/creator/schema-owner/database-owner recipients, ALL,
grant options or non-creator grantors are supported. Existing allowlisted declared
defaults are validated even if their binary grant is already present.

The SQL always names FOR ROLE and IN SCHEMA, uses quoted identifiers, and revokes
with RESTRICT. Global table defaults remain unread and refuse the whole writer;
sequence/function/type/schema defaults are read and bound but never changed.
Plan ID v4 binds **all raw pg_default_acl rows**, including other object types,
row OIDs, creator/schema IDs, grantors/options, inputs and authenticated session.
The same database-local advisory lock serializes participating writers. Before
COMMIT, verify exact expected table-default ACL atoms, identical unrelated raw
default rows, untouched object ACLs/memberships/roles/ownership and convergence.
Errors, unexpected side effects and timeouts before COMMIT roll everything back.
External concurrent administration remains outside this cooperative guarantee.

These defaults apply to **future relations**, including views and foreign tables,
created by the named role. Existing objects do not change. Membership in the
creator does not transfer its defaults to member-owned objects; a different
creating role needs its own intent and credential. Per-schema defaults add to
global defaults and cannot revoke a global grant. A successful receipt flags
`default_changes_future_objects_only=true` and keeps `effective_access_verified=false`;
CONNECT/schema USAGE, RLS and other access prerequisites need separate validation.

Undo with newly reviewed inverse intent. Objects created while a default was
active retain their assigned ACLs after the default is revoked. Inverse defaults
restore neither those object ACLs nor data or raw default-row OIDs. Official
PostgreSQL 17.11 tests verify actual future SELECT/INSERT, other creator/schema/DB
isolation, quoted SQL, inverse semantics, stale catalog/identity refusal and full
later-error/timeout/unexpected-side-effect rollback. Production, PostgreSQL 16,
positive TLS and COMMIT network loss remain unverified. See PostgreSQL's
[ALTER DEFAULT PRIVILEGES](https://www.postgresql.org/docs/17/sql-alterdefaultprivileges.html)
and [pg_default_acl](https://www.postgresql.org/docs/17/catalog-pg-default-acl.html).

### Apply canonical role memberships (R3g3)

Role memberships affect **the whole PostgreSQL cluster**, including privileges
in databases outside `databases`. They are disabled by default. Authorize only
reviewed, existing non-login groups with `membership_write_roles`. This list
permits their existing cluster-wide privileges; it is not a per-database ACL
allowlist or an audit of every grant/RLS policy associated with the group.

```toml
[adapters.pg-members]
type = "postgres"
admin_dsn_env = "GRANTLINE_PG_MEMBERS_WRITER"
databases = ["postgres"]
membership_write_roles = ["analytics_reader", "reporting_reader"]
```

Supply a separate named DSN for the authenticated writer in `postgres`. Role
plans must run through this fixed coordinator so this writer version's role
transactions share one advisory lock. A cluster without a database named
`postgres` is unsupported here. Object writers in other databases, raw SQL and
older versions do not participate. Use a maintenance interval without concurrent
administration. `apply --system pg-members --live` previews; adding
`--write --expect PLAN_ID` applies only that current plan. Role changes cannot be
mixed with object ACL changes. Intent uses existing `role:analytics_reader` and
`privs = ["MEMBER"]`; declare other held memberships you intend to retain.

The writer must **directly** hold ADMIN OPTION for the group. New edges always
use `ADMIN FALSE, INHERIT TRUE, SET TRUE` and `GRANTED BY` the authenticated writer.
A NOINHERIT account can therefore inherit through this explicitly configured
edge. Revokes use RESTRICT and require a single canonical edge created by that
same writer. No SET ROLE, arbitrary SQL, borrowed grantor, option editing or ADMIN
grants are performed. Existing declared edges in the write allowlist are checked
even when the binary MEMBER atom already exists; multiple grantors, delegation or
noncanonical options are refused. Unchanged memberships outside the write
allowlist remain read-only.

Self/writer changes, login groups, PUBLIC/predefined/privileged or object-owning
endpoints/ancestors and unsafe ancestor membership options are refused. Ownership
checks use shared dependencies across databases, not just the coordinator's
schemas. The writer's INHERIT/SET ancestry cannot be changed. These guards do not
prove the complete effective authority of an allowlisted role: review its ACLs,
RLS and application privileges before authorizing it.

Plan ID v4 binds role OIDs, flags, complete membership options/grantors and owner
role IDs. Exact expected memberships, untouched direct object ACLs and other
catalog state are verified before one COMMIT. JSON receipts flag
`membership_changes_cluster_wide=true` for role change plans and keep
`effective_access_verified=false`. Undo requires a newly reviewed inverse intent;
other role paths or an already active SET ROLE session can retain effective access.
The fixture checks actual inherited SELECT and SET ROLE plus multi-statement
cycle failure and blocked-GRANT timeout rollback. Production, PostgreSQL 16 and
COMMIT network-loss behavior remain unverified. See PostgreSQL's
[role GRANT](https://www.postgresql.org/docs/17/sql-grant.html) and
[REVOKE](https://www.postgresql.org/docs/17/sql-revoke.html) semantics.

### Apply or restore one local S3 IAM file (R3f)

This Unix-only writer supports an existing monolithic `file` in the selected
adapter's enforced plane. It reads only that source; other services/planes,
remote readers, environment credentials and imported snapshots are not used.
Remote IAM and directory/group policy trees remain unsupported for writes.
The filesystem's write permission is the credential, as in the Python file
adapter; no network/admin credential is inferred from read access.

```sh
rust/target/debug/grantline-rs -c /path/to/grantline.toml apply --system object-store --json
# Review the permission-only previews, then copy the returned plan_id:
rust/target/debug/grantline-rs -c /path/to/grantline.toml apply --system object-store --write --expect PLAN_ID_FROM_DRY_RUN --json
# Inspect rollback before explicitly restoring the returned private backup:
rust/target/debug/grantline-rs -c /path/to/grantline.toml restore --system object-store --backup /absolute/path/to/private-backup --json
rust/target/debug/grantline-rs -c /path/to/grantline.toml restore --system object-store --backup /absolute/path/to/private-backup --write --json
```

Dry-run creates no files. Application requires an exact match for the reviewed
config/intent bytes, selected path, source bytes/metadata and grouped previews.
Re-read immediately before replacement; an edited source, rotated key, changed
intent/config, replaced inode or changed mode invalidates the plan. Up to 1,000
changes are coalesced into one complete file replacement. Existing credentials,
account metadata and unrelated identities/fields remain intact; new identities
have no credentials. New native prefix actions use `Verb:bucket/prefix/*`, since
bare prefix paths do not authorize descendants on SeaweedFS. Existing untouched
actions are preserved; this is not a repair of historic normalization assumptions.
Re-evaluate the full resulting file against intent before writing. A candidate
plan that drops a covering grant without retaining the intended narrower access
is refused rather than temporarily removing that access; inspect `plan` and
resolve the declaration/source with its owner before retrying.

Use regular, singly linked files on a trusted local POSIX filesystem. Empty or
traversal segments in changed resource scopes are unsupported. Symlinks,
FIFOs, unsafe writable parents/ancestors, special/group/world-write source bits,
duplicate JSON keys, floats/out-of-range integers, unrecognized IAM fields and
incomplete policies are refused. Root fields are `identities`/`accounts`; identity
fields are `name`, `actions`, `policy`, `credentials`, `account`, `disabled` and
`status`. Unknown policy-binding formats require an owning IAM client. Source,
config and intent are each limited to 4 MiB; backup envelopes to 32 MiB.

Writers coordinate with a persistent, private `.FILENAME.grantline.lock` sidecar
and a nonblocking OS lock. Do not remove it while a writer may run. Staging uses
a private file in the same directory, preserves POSIX mode/owner/group, syncs
contents and backup, then atomically replaces the source and syncs its directory.
Readers see a complete old or new document. Owner/group changes are refused.
The lock coordinates cooperating Grantline writers; it is not a filesystem CAS
against unrelated editors. ACLs, extended attributes, SELinux labels, network
filesystems and power-loss/fault-injection guarantees are not supported/verified;
use this writer only for ordinary POSIX-mode-managed files.

The returned hidden backup contains **the exact original bytes, including keys**,
plus target/digest/mode metadata. It is mode 0600, not encrypted or a signed
approval artifact; keep it private and outside public version control. Retention
and deletion are separate operator actions. Rollback requires the same selected
system/path/owner/mode and exact applied-file digest. If another edit occurred,
restore refuses to overwrite it. A restore also backs up the current version,
so redo has the same conditional boundary. No-op writes create no backup.
An interrupted pre-replacement operation may leave a private backup; errors
after replacement explicitly require inspection before retrying.

`applied`/`restored` mean **local file replacement only**. No service reload,
IAM API call, Slack/GitHub action or deployment occurs. JSON explicitly reports
`service_reload_verified: false`. Effective service access requires separate
reload/readback/probe evidence. Run `cargo test --manifest-path rust/Cargo.toml`
for stale-state, permission, symlink/hardlink, duplicate/unknown JSON, lock,
credential preservation, atomic-reader and exact-restore guards;
`python3 scripts/check_rust_s3_writer.py --docker` verifies actual scoped access
before application, after application and after restoration on isolated SeaweedFS.

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
- R3e1/R3e2 probe PostgreSQL/ClickHouse ACLs, with optional explicit subject logins.
- R3e3 signs scoped S3 List/HEAD samples with explicitly mapped subject keys.
- R3f explicitly applies/restores one local S3 IAM file with stale-state guards and private backups.
- R3g1 applies one PostgreSQL ordinary-table ACL plan transactionally with explicit credentials and review.
- R3g2 extends that transaction to schema/database ACLs, with cooperative writer locking and full direct ACL postconditions.
- R3g3 adds opt-in role-only membership transactions through postgres, with canonical options and an exact grantor.
- R3g4 adds authenticated-creator, schema-specific default table privileges and future-object/rollback checks.
- R3h1 applies one exact local ClickHouse SELECT/INSERT ACL with review and explicit uncertain outcomes.
- R3h2 adds explicitly authorized DB scopes, future-relation scope disclosure and overlap/partial-revoke guards.
- R3h3 adds canonical single-role memberships with direct ADMIN authority and exact inverse checks.

## What remains

Global and other-object PostgreSQL defaults and remote S3
writers, production authentication,
durable approvals, real Slack/GitHub writers, all existing console pages,
WASM map interactions, four-language UI and release images are later stages.
Remote S3 document writes and other native writers remain in R3. Approval, a
simulated PR and effective IAM access are separate states. This experimental app
is not ready to replace a production deployment. The playground stays fictional;
CLI file application, service reload and effective access are separate states.

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
python3 scripts/check_rust_s3_probes.py --docker
python3 scripts/check_rust_s3_writer.py --docker
python3 scripts/check_rust_postgres_writer.py --docker
python3 scripts/check_rust_postgres_membership.py --docker
python3 scripts/check_rust_postgres_defaults.py --docker
python3 scripts/check_rust_clickhouse_writer.py --docker
python3 scripts/check_rust_clickhouse_database.py --docker
python3 scripts/check_rust_clickhouse_membership.py --docker
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
production writers, performance and production integration remain unverified. The ClickHouse
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

## Conditional remote JSON IAM writes

For an enforced JSON plane configure `admin_url_env`, optional `admin_auth_env`,
and `conditional_write = true`. The endpoint must implement strong ETags and
If-Match PUT atomically. `apply --live --system s3` previews; writing also needs
`--write --expect PLAN_ID`. No reader credential fallback occurs. A mode-0600
`.grantline-remote-*.backup.json` containing original credentials is saved beside
the config before dispatch; keep config and state outside version control.
`restore --live --system s3 --backup PATH` previews the inverse; add `--write`
only after review. Restore refuses changed applied bytes and uses current ETag.
412 means revision conflict. Other dispatch/post-check failures require inspection;
there is no automatic retry/compensation or service reload. Shared IAM trees and
IAM Query remain read-only. Run `python3 scripts/check_rust_remote_writer.py`.

## Native production authentication

`grantline-rs -c CONFIG serve --port 8424` starts the native console. Without auth
configuration it is a loopback-only, read-only local preview. Demo identities
are never accepted on production routes. `--live` explicitly enables configured
service reads; it does not enable permission application.

```toml
[web]
public_url = "https://grantline.example.com/"
[web.auth]
mode = "oidc"
issuer = "https://identity.example.com"
client_id = "grantline"
client_secret_env = "GRANTLINE_OIDC_CLIENT_SECRET"
allowed_subjects = ["provider-subject-id"]
```

Register the exact `PUBLIC_URL/auth/callback` URI. OIDC uses code flow, PKCE,
browser-bound one-use state and nonce, and issuer/audience/signature/expiry
verification. Subjects, not unverified email aliases, identify users. Sessions
expire after an hour and are invalidated by restart. Cookies are HttpOnly,
SameSite=Lax and Secure for HTTPS. Mutation endpoints require exact Origin plus
session CSRF. `POST /auth/logout` revokes the session.

For an existing OIDC proxy, set `mode = "proxy"` and optionally
`identity_header = "X-Forwarded-Email"`. Bind the process to loopback and make
the proxy strip/replace this header and restrict access. Each authenticated
request must retain the same proxy identity as its private session. A header
from an untrusted direct client is not authentication; do not expose the
loopback upstream. Duplicate identities and off-origin/invalid CSRF are rejected.
Run `node scripts/check_rust_oidc.mjs` for an isolated RSA-signed provider test.
