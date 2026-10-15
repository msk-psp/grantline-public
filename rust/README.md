# Grantline — Rust + Leptos migration

Experimental **R1 + R2 + R3a/R3b foundation**, alongside the supported Python console.
This binary runs natively with no Python process. Commands are offline by default;
native ClickHouse catalog observation requires explicit `--live` and a reader.
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
The bundled S3 file provider is now observed. Remote-only providers remain unread.
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
writer/probe support is still pending. PostgreSQL and S3 network readers remain
unimplemented even with `--live`.

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

## What remains

PostgreSQL/S3 live observation, probes and native writes, production authentication,
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
