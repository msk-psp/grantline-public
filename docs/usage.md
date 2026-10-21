# Configuration and operations

The service and CLI are native Rust. Build from the [README](../README.md) and
use `rust/target/debug/grantline-rs`, or the binary in a native container.
Detailed adapter/probe/write contracts live in the [Rust guide](../rust/README.md);
[production authentication and recovery](rust-operations.md) covers shared hosting.

## Connecting real systems

Keep configuration outside the checkout. Paths resolve relative to that file.
Observation requires `--live`; the bundled demo uses only fictional local data.

```toml
intent = "intent.toml"
env_file = "credentials.env"
audit_log = "/data/audit.jsonl"
snapshots = "/data/snapshots"

[adapters.postgres]
type = "postgres"
dsn_env = "GRANTLINE_PG_READER"
databases = ["analytics"]
exclude_databases = ["template*"]

[adapters.clickhouse]
type = "clickhouse"
url_env = "GRANTLINE_CH_READER"

[adapters.s3]
type = "s3"
enforced = "dynamic"
[adapters.s3.planes.dynamic]
filer_url_env = "GRANTLINE_FILER_READER"
```

The configuration names credential environment variables; keep their values in
the process environment or a private `0600` env file. Existing environment values
take precedence. Use service-enforced read-only observers. PostgreSQL has a native
driver and needs no Python package. Configure a CA bundle for private TLS; native
clients do not silently downgrade TLS or follow credential-bearing redirects.

S3 can read a Filer tree, IAM API, local JSON or mirrored directory. Review the
[provider-specific settings](../rust/README.md#read-remote-s3-iam-sources) before
choosing a source. Static and dynamic planes describe different authentication
sources; only the configured enforced plane determines the effective observation.

## Credentials, and running it on a schedule

```bash
rust/target/debug/grantline-rs -c /path/to/config.toml plan --live --json
rust/target/debug/grantline-rs -c /path/to/config.toml snapshot --live --json
```

Use the same explicit configuration in a scheduler. A plan does not write a
snapshot implicitly. Protect snapshot/audit directories and keep observation
credentials separate from `admin_*` write credentials. Configuring a credential
does not itself authorize an operator to change service permissions.

## Telling the map what only you know

```toml
[graph]
services = ["svc-*"]
[graph.environments]
prod = ["postgres", "clickhouse", "s3"]
staging = ["postgres-staging", "s3"]
[graph.people]
alice = "Alice Example"
[graph.teams]
alice = "Research"

[[bridges]]
from = "service:example"
to = "svc-example"
system = "s3"
note = "declared server-held credential hop"
```

Labels do not create users or permissions. Observed identities remain visible
even when they have no grants or their access is unknown. Bridges are declared
relationships, not measured logins. Environment and service names retain the
operator's spelling across the four interface languages.

## Intent file

```toml
managed_subjects = ["alice"]
[[grants]]
system = "postgres"
subject = "alice"
resource = "table:analytics.public.events"
privs = ["SELECT"]
```

A grant is identified by system, subject, resource and privilege. Grantor/source
metadata is retained for explanation. Revokes are bounded by managed subjects
and explicitly described systems; use `managed_systems` to describe an intentionally
empty system. Inspect the JSON plan and exact adapter contract before any write.

PostgreSQL column ACLs use `column:analytics.public.events.event_id`. They retain
their narrow scope and can be checked by read-only probes; native column writes
are not supported. Special roles and unsupported/ambiguous ACLs remain unknown.

## Safety model

An unread scope is unknown. It must never become an inferred denial or an
unverified grant/revoke. Native writes require explicit write credentials,
reviewed plan binding and `--write --expect PLAN_ID`. Supported scopes and recovery
guarantees differ by adapter. Approval and a code PR do not apply IAM access.
See [write/recovery boundaries](rust-operations.md#native-write-and-recovery-boundaries).

## Console sign-in

A local loopback preview is read-only. Shared deployments require configured
native OIDC or a trusted authenticated proxy. Native OIDC validates signatures,
issuer/audience, PKCE, state and nonce. Proxy deployments must strip untrusted
identity headers and isolate the backend. A second application login page is
unnecessary: the native handler completes the session after the provider returns.
See [authentication configuration](rust-operations.md#authentication-and-private-configuration).

## Login and permission probes

```bash
rust/target/debug/grantline-rs -c /path/to/config.toml probe --live --subject alice --json
```

PostgreSQL and ClickHouse probes evaluate fixed service-native ACL queries; they
do not read application rows or execute writes. Optional subject credentials
check the requested login identity. S3 probes use explicitly mapped subject keys
for bounded listing/HEAD samples. Unknown probes and an empty probe list do not
establish access. See the adapter sections in the [Rust guide](../rust/README.md).

## History and approvals

Snapshots retain the existing JSONL format and distinguish grant changes from
visibility changes. Importing a snapshot never restores permissions. The native
approval flow binds authenticated requesters/reviewers, verifies signed Slack
callbacks and publishes reviewed intent changes through a configured GitHub
writer. Native approval sessions and legacy bearer links are different contracts.
Migrate old state offline with private backups; follow the
[migration/rollback procedure](rust-operations.md#offline-state-migration-and-rollback).

## Console language

English, 한국어, 日本語 and 简体中文 are supported by `rust/ui/src/i18n.rs`.
The language selector persists the choice; browser language is used on the first
visit. Account, environment and resource names are literal identifiers.

## GPU permission map

The map uses Rust/WASM and WebGL2 for nodes and directed curves. Labels and service
icons are drawn only for visible rows. It retains the column layout and entity
colors, with instant highlight/dimming instead of per-element CSS transitions.
WebGL2 is optional: a Canvas2D fallback keeps navigation available when the context
is unavailable or lost. The renderer tries WebGL2 again when the context recovers.
JavaScript/WASM is required for the interactive map; Accounts and Resources remain
server-rendered alternatives.

Hover to trace access; click to retain a selection. Click a service instance to
expand its resources. Scroll to zoom at the pointer, Shift+scroll to pan vertically,
or drag to pan. With the map focused, use arrows to navigate, Enter/Space to select
or expand, Home/End for the first/last node, Page Up/Down to pan and Escape to reset.
The active node exposes its full name, service and position to assistive technology.
Hover also exposes its full label through the browser tooltip. Detail links retain
service, environment and language filters. Resource names remain literal.

For a repeatable scale check, build the normal native/WASM bundle, then run:

```bash
node scripts/check_rust_graph.mjs --check --port 0
node scripts/check_rust_graph.mjs --port 8426
```

Open `http://127.0.0.1:8426/?graphSize=100000`. This loopback-only, read-only fixture
uses fictional users and resources; it never reads production services. Focus the
map and press End, Enter to expand S3, then End again to reach resource 99,999.
To test search at that size, open
`http://127.0.0.1:8426/?graphSize=100000&q=resource-099999`.
The normal filter form omits the test-only `graphSize` parameter, so retain it in
the URL when testing other searches. The fixture defaults to 1,000 resources.

For local profiling, `.map-viewport` exposes `data-renderer`, `data-graph-frame`
and `data-graph-gpu`. Frame data separates CPU preparation, event-to-submit,
visible geometry, active count, draw calls and geometry/state uploads. GPU times
are asynchronous and include a frame ID; pair only matching IDs. Unsupported timer
extensions or disjoint results do not provide a GPU duration. The renderer emits
`grantline-map-frame` after each submitted update. An unchanged hover schedules
no redraw. A new uncached path walks reachable edges and allocates a byte mask;
mask upload/counting still scales with total node count. Initial graph loading,
layout, expansion and buffer upload are separate costs from steady hover.

A measured CPU/GPU time below 10 ms is a result for that fixture and device, not a
universal interaction guarantee. Browser compositing, display refresh, contention
and dense visible connections can take additional time. Test target hardware
before promoting a new image.

## Containers

`docker build -t grantline-native:local .` builds the native Rust/WASM image.
`Dockerfile.rust` remains a compatibility alias. Release publication validates
the same native image and publishes `linux/amd64` and `linux/arm64` to GHCR;
stable releases update `latest`, while pre-releases keep their version tag.
Older published tags retain their original runtime. Merging code does not release
an image. The Python test reference and verification tools are not shipped.

The image runs as UID/GID `10001:10001` and defaults to a fictional read-only demo.
Mount configuration read-only and a separate persistent private `/data` directory
for state. Prepare ownership and permissions before starting the image. For a
real configured deployment, the command is:

```bash
docker run --rm -p 127.0.0.1:8420:8420 \
  --mount type=bind,src=/path/to/config,dst=/config,readonly \
  --mount type=bind,src=/path/to/private-state,dst=/data \
  ghcr.io/msk-psp/grantline-public:v0.1.0 \
  -c /config/config.toml serve --live --host 0.0.0.0 --port 8420
```

Configure native authentication before sharing that listener. Pin a reviewed
image digest for deployment; the [operations guide](rust-operations.md) contains
the build, migration and rollback checks.
