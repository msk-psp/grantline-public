# Configuration and operations

## Connecting real systems

Edit `grantline.toml`. Credentials are **never** stored in config — config names
the environment variables that hold them, and observation credentials are
separate from admin credentials:

```toml
intent = "intent.toml"

[adapters.postgres]
type = "postgres"
dsn_env = "GRANTLINE_PG_DSN"              # read-only role — used by plan/serve
admin_dsn_env = "GRANTLINE_PG_ADMIN_DSN"  # only writes: apply --write, console
databases = ["*"]                     # which DBs to walk (fnmatch patterns)
exclude_databases = ["template*"]     # walking everything can be expensive
# Each target DB gets its own connection (schema/table/default-privilege ACLs
# are per-database). A DB the observer cannot enter is reported as an
# unobserved scope — shown as '?', never silently skipped. apply routes every
# command to the DB it belongs to.

[adapters.clickhouse]
type = "clickhouse"
url_env = "GRANTLINE_CH_URL"              # e.g. http://reader:password@ch-host:8123
admin_url_env = "GRANTLINE_CH_ADMIN_URL"

# Several instances of one type sit side by side — the section name is the
# instance, `type` is the adapter. Grants, pages, intent and snapshots all key
# on the instance name, so staging never merges into production.
[adapters.clickhouse-staging]
type = "clickhouse"
url_env = "GRANTLINE_CH_STAGING_URL"

# S3 has two auth planes; `enforced` names the one the gateway actually
# consults — effective grants and all writes go to that plane, the other is
# read for cross-plane identity checks. Each plane block carries its OWN
# endpoint and credentials: keys are paired to their plane, and a key from
# one plane fails against the other's endpoint as a misleading 403.
[adapters.s3]
type = "s3"
enforced = "dynamic"

[adapters.s3.planes.static]
file = "path/to/identities.json"      # file-backed plane

[adapters.s3.planes.dynamic]
url_env = "GRANTLINE_S3_IAM_URL"          # HTTP plane, observation: GET
auth_env = "GRANTLINE_S3_IAM_TOKEN"       # observation credential (optional bearer)
admin_url_env = "GRANTLINE_S3_IAM_ADMIN_URL"      # writes only: PUT
admin_auth_env = "GRANTLINE_S3_IAM_ADMIN_TOKEN"   # write credential (optional bearer)
```

Every adapter splits reading from writing the same way (`dsn_env` /
`admin_dsn_env`, `url_env` / `admin_url_env`), and there is **no fallback between
them**: a plane with no `admin_*` is read-only, and the console's run button
stays dead there. A file-backed plane is judged by the filesystem instead —
there is no second credential to withhold when the file permission *is* the
credential, so a read-only deployment of one is made by making the file read-only.

The live PostgreSQL adapter needs `pip install psycopg[binary]` (or
`pip install -e '.[postgres]'`). ClickHouse and S3 adapters are stdlib-only.

For an S3 identity that carries an IAM **policy**, the native action list is
dead config — the server ignores it. Grants/revokes therefore mutate the
policy document, and the plan shows the old→new policy as a unified diff.

Tip from the trenches: verify access on the path real users take. A local
socket with `trust` auth checks no password at all — probe over TCP with the
actual credentials.

## Credentials, and running it on a schedule

Credentials never live in the config — the config only names the environment
variable. That left the CLI unusable without a launcher script, so a config may
also name a file to read them from:

```toml
env_file = "credentials.env"   # next to the config, mode 600, outside the repository
```

```
GRANTLINE_PG_DSN=postgresql://inspector:…@host:5432/postgres?sslmode=verify-full
GRANTLINE_S3_ENDPOINT=https://s3.example
```

Variables already in the environment win, so a launcher can still override. The
file is refused if it is readable by anyone else.

`serve` records one snapshot per process, so a console left running all day leaves
one point of history. For a real cadence, run the recorder:

```bash
grantline -c ~/.config/grantline/prod.toml snapshot     # cron / systemd timer
```

## Telling the map what only you know

Three facts are not in any grant table, so the config supplies them. All of it is
optional — without it the map still draws, it just says less.

```toml
[graph]
# Which accounts are services. Nothing observable distinguishes a person's login
# from a robot's; only you know.
services = ["svc*", "airflow*", "mlflow"]

# Which instance serves which environment. Drives the prod / staging toggles.
[graph.environments]
prod = ["postgres", "clickhouse", "s3"]
staging = ["postgres-staging", "s3"]      # one store can serve both

# Account -> the person. Shown as `achen (Alice Chen)`.
[graph.people]
achen = "Alice Chen"

# Account -> team. Groups the principal column, the same way the other columns
# group by service.
[graph.teams]
achen = "sales"
```

A **bridge** is the fourth: a hop that leaves one system and continues on a
credential the server holds, which no grant table records.

```toml
[[bridges]]
from = "duckdb"            # a PostgreSQL role: its members get this reach
to = "svc-duckdb"          # an S3 identity: the key the server presents
system = "s3"
note = "DB extension -> the server's own S3 key"

[[bridges]]
from = "service:airflow"   # `service:` marks an actor that is not itself an account
to = "svc_airflow"         # ...so it never collides with a login of the same name
system = "postgres"
note = "DAG -> PostgreSQL login"
```

The first shape is the one that matters: eight people are members of a database
role, and through it they reach object storage with a key that is not theirs.
Removing them from the role is the only revoke that changes that, and the map is
where you see it.

## Intent file

```toml
managed_subjects = ["alice", "bob", "svc_etl", "PUBLIC"]

[[grants]]
system = "postgres"
subject = "alice"
resource = "role:analyst_read"   # role:X | db:X | schema:db.s | table:db.s.t
privs = ["MEMBER"]               # | default:db.s@creator | bucket:name/prefix*

[[grants]]
system = "s3"
subject = "svc_etl"
resource = "bucket:data-lake/raw/*"
privs = ["Write"]
```

## Safety model

Read [SECURITY.md](../SECURITY.md) before sharing a console or enabling writes. Shared
deployments require an authenticated reverse proxy and trusted Host configuration;
the built-in server does not validate passwords or OIDC sessions itself.

- **Read-only by default** — `plan` never writes; `apply` is a dry-run without
  `--write`, and `--write` asks for confirmation (`--yes` to skip). `serve`
  writes only what you name on the page, and only where a write credential is
  configured; a GET never changes anything (writes are POST).
- **The read path never resolves a write credential** — whether the console's
  run button is live is decided by config shape plus the *existence* of the
  environment variable (`Adapter.write_ready()`); the value is read inside
  `apply()`, at the write itself.
- **Preview → apply** — every native command is shown before execution, with no
  flag to turn it off. The console posts the previewed command back and refuses
  to run if the adapter would now emit a different one.
- **Convergence scope** — the plan revokes only for `managed_subjects`; other
  subjects are reported. A trusted operator can also explicitly name a single write.
- **Audit log** — an attempt is recorded before every write; its result appends
  `{ts, user, system, cmd, ok}` to `audit.jsonl`.

## Console sign-in

Without authentication configuration, `/login` is a local console landing page.
For a shared console, an authenticated reverse proxy owns OIDC, sessions and the
allowed users or groups. Enable the proxy identity gate in the external configuration:

```toml
[web]
trusted_hosts = ["console.example.com"]

[web.auth]
mode = "proxy"
identity_header = "X-Forwarded-Email"
login_url = "/oauth2/start"
logout_url = "/oauth2/sign_out"
```

The backend must remain reachable only by the trusted proxy, through loopback or
network isolation. The proxy must strip client-supplied identity headers and inject
one validated identity. For an ingress `auth_request` setup, use its validated
`X-Auth-Request-Email` header instead. Setting this table alone does not make a
publicly reachable backend safe: Grantline trusts the configured header.

Route `/login` and static assets to Grantline, the configured sign-in/sign-out
endpoints to the proxy, and all other console traffic through authentication.
Preserve API authentication failures as HTTP 401 rather than a 200 HTML sign-in
page. Unauthenticated page requests return to `/login`; API and write requests
fail with 401. Grantline accepts only local return paths. Restrict redirect domains
at the proxy as well.

The account appears in navigation, and new approval requests record that identity.
Signing in does not grant access to PostgreSQL, ClickHouse or S3, and approval
tokens still authorize their individual approval decisions. Sign-out clears the
proxy session; the identity provider may still have its own active session.
See OAuth2 Proxy's official [endpoints](https://oauth2-proxy.github.io/oauth2-proxy/features/endpoints/)
and [configuration](https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/).

The console has searchable inventories and an account matrix. Detail links retain
all account chips, including those behind “more.” Focusing a change field preserves
its value; changing service retains the account and clears resource/privilege fields
because they belong to that service. Editing a proposal hides the previous preview
until you preview again. Successful writes and requests redirect to a read-only
detail page, so refreshing it does not submit the operation again.

## Login and permission probes

By default PostgreSQL evaluates ACLs as the observer, and ClickHouse resolves effective
`SHOW GRANTS`. Neither default verifies the subject's authentication. Optional mappings
name environment variables containing each subject's own credentials:

```toml
[adapters.postgres.probe_dsn_envs]
alice = "GRANTLINE_ALICE_PG_DSN"

[adapters.clickhouse.probe_url_envs]
alice = "GRANTLINE_ALICE_CH_URL"
```

Run `grantline -c ~/.config/grantline/prod.toml probe --subject alice`. The probe verifies
the login identity, then asks for effective privileges. PostgreSQL requires a TCP host;
local sockets are refused. It never falls back to the observer when a configured subject
credential is missing or invalid. It performs no table read or write, so an `allow` verdict
still does not verify row-level security, data-dependent rules, or a successful upload.
Failures remain `unknown`; diagnostics never print the subject credential.

S3 uses the subject's own key against `endpoint_env`. `probe --write` additionally
uploads a probe object and attempts cleanup; if deletion is denied, it reports the object
left behind. File/HTTP planes and IAM-tree sources differ in which credentials they
expose. Keys absent from an IAM API observation yield `unknown`.

## History and approvals

`history --since 7d` compares observations; `snapshot` records one for an external timer.
The console takes one snapshot per process, even while its observation cache refreshes
in the background. Cached reads use the last complete observation; explicit refreshes and
writes read fresh. First access may still wait for the initial observation.

`request grant` / `request revoke` queue previewed operations. `[approvals] admin` and
matching `[[approvals.rules]]` choose approvers. Slack delivery is optional. Approver URLs
are bearer credentials: deliver privately; a trusted operator uses `request --links ID`.
Direct web execution is refused when approvals are enabled. See [SECURITY.md](../SECURITY.md).

Probe implementation references: [PostgreSQL privilege inquiry functions](https://www.postgresql.org/docs/current/functions-info.html)
and [ClickHouse SHOW GRANTS](https://clickhouse.com/docs/reference/statements/show#show-grants).
ClickHouse login identity checks return one row and bound execution time, following
`clickhouse-best-practices/agent-query-safety`; they do not scan data tables.
