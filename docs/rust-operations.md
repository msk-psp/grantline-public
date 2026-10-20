# Rust + Leptos operations and migration

The Rust binary and browser WASM run without Python or Node in production.
A minimal Python oracle under `tests/reference` is used only by differential
tests. It is not installed or included in the application image. Old release
artifacts and persisted-state backups remain the explicit rollback path.
The release workflow gates GHCR publication on native distribution checks,
reference regressions, native adapter tests, WASM/SSR tests and a read-only native
container smoke test. Privacy scans run locally through the contributor
[Git hooks](../CONTRIBUTING.md#local-privacy-checks), outside GitHub Actions.
It publishes amd64/arm64 only after a GitHub Release is published. Merging the
stack neither publishes a release nor deploys any service. Existing image tags
are unchanged until a release updates them; pin a version and digest.

## Build and preview

Use Rust 1.99.0 and wasm-bindgen-cli 0.2.129 (matched to `rust/Cargo.lock`):

```sh
rustup toolchain install 1.99.0 --profile minimal
rustup target add --toolchain 1.99.0 wasm32-unknown-unknown
cargo +1.99.0 install --locked wasm-bindgen-cli --version 0.2.129
RUSTUP_TOOLCHAIN=1.99.0 scripts/build_rust_ui.sh
cargo +1.99.0 build --locked --release --manifest-path rust/Cargo.toml
rust/target/release/grantline-rs -c examples/demo/grantline.toml serve
```

Open http://127.0.0.1:8424/. `rust/pkg` holds generated WASM/glue; do not commit
it. Mount it separately or set `GRANTLINE_UI_DIR`/`web.assets` when relocating a
binary. Build the release image with `docker build -f Dockerfile.rust -t
 grantline-native:local .` and run it bound to the host loopback:

```sh
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -p 127.0.0.1:8420:8420 grantline-native:local
```

The default command exposes only the bundled fictional fixture preview,
with `--public-preview` explicit and authenticated mutations disabled. That flag
requires local mode without `--live`; do not use it with private datasets.
Local/proxy listeners otherwise require loopback. `--live` enables configured
read adapters, not automatic IAM application. Approval/PR creation also does
not apply IAM. Unsupported or unread scopes are unknown, never “no access”.
Display caps: 1000 map nodes, 500 grant/finding rows, 150 matrix rows/columns,
100 visible approval summaries and 100 recent snapshots (1000 stored files).
Use filters or offline CLI for larger inventories. One process owns an approval
store; replicas cannot share it as concurrent writers.

## Authentication and private configuration

Keep config, intent checkout, snapshots, approvals and original-byte IAM backups
outside this public repository and the container image. Use mode 0700 state
directories and 0600 files, owned by UID/GID 10001 in the image. Mount a private
writable state volume; keep config and intent mounts read-only where practical.
The container root can remain read-only. Native DB protocols do not launch
Python drivers. Network commands and `serve` load the optional private `env_file`
(mode 0600, relative to config) once, before runtime threads start. Existing
process environment values win. Offline plan/graph/history never resolve it.
Only the configured reader/probe/writer variable names are consumed by adapters;
ambient AWS/PG credentials are never a fallback. Restart to reload this file.

Copy [the example](../examples/rust-console.toml) outside the repository. OIDC
uses signed ID tokens, issuer/audience/nonce validation, PKCE and an exact `sub`
allowlist. Register `<public_url>/auth/callback` with the provider. The public URL
must be HTTPS for shared deployments; terminate TLS at the trusted ingress.
Sessions are HttpOnly, SameSite=Lax, Secure on HTTPS, expire in one hour and are
invalidated on process restart. POST requires the exact Origin and session CSRF.
Identity `sub` is bound to the configured issuer, not an editable display name.

Trusted-proxy mode is an alternative for an existing authenticated proxy. It
must strip incoming `X-Forwarded-Email` (or the configured identity header),
authenticate the user and supply exactly one verified value. The native proxy
listener must stay on loopback; use the same network namespace (for example,
a sidecar). Do not expose an unauthenticated proxy header listener on a network.
Local preview is read-only and cannot impersonate an approver. The fictional
`demo` role switch is a separate in-memory playground, not production login.

## Slack and GitHub

`approvals.identities` maps authenticated subjects to unique approval identities,
usually Slack user IDs. `admin` is always required; every matching rule adds
approvers. A requester cannot satisfy any required approver slot. Configure all
identities before accepting requests. Requests expire after seven days; changing
origin, auth or approval policy invalidates old immutable plans.

Configure the Slack app with `im:write` and `chat:write`, install it in the
intended workspace and set interactivity to `<public_url>/api/slack/actions`.
Inject its bot token and signing secret by the configured environment names;
`team_id` pins the workspace. The server signs/verifies the raw request body
with Slack v0 HMAC, enforces timestamp tolerance and checks the acting user,
plan hash and single-use decision. Valid interactions receive an empty HTTP 200
acknowledgement. External DM/PR calls release the state mutex, so they cannot
hold up an independent decision; completion reloads the durable record to
preserve concurrent approvals. This follows [Slack's acknowledgement contract](https://docs.slack.dev/interactivity/handling-user-interaction/#acknowledgment-response). Link verification is not a substitute for
console authentication. A Slack DM exposes request details to its named
approver; keep approval scope limited. Integration errors withhold response
bodies and never automatically resend uncertain notifications.

The GitHub token needs read access to the selected repository and write access
to Contents and Pull requests there. Scope it to that repository. `expected_login`
checks the actual API account before reading a patch or publishing; commit author
and committer use that account's verified user ID and GitHub noreply address.
The default refuses public policy repositories. Set `allow_public_repository`
only after reviewing whether the intent file itself is suitable for publication.
The Grantline source being public does not authorize publishing private IAM policy.

Preview pins base commit, intent blob, full before/after document and hash. All
required independent decisions bind that immutable plan. Source changes refuse
publication. Publishing creates one deterministic branch and PR, without merge
or native IAM writes. A failed external write becomes `publish_unknown` and
must be inspected before any manual recovery. Do not delete the unknown record
and retry blindly. After a crash, `publishing` and notification `sending` become
unknown on startup; there is no automatic resend, re-publish or compensating IAM.

## Offline state migration and rollback

Snapshots retain the Python JSONL format and distinguish grant changes from
visibility changes. They can be copied privately and read by the native CLI;
importing a snapshot never restores access. Keep a separate verified backup of
the original config, intent, state and deployed image digest before a cutover.

Stop **all** source writers. The migration command defaults to a dry run and
requires an existing private parent and a destination that does not exist:

```sh
grantline-rs migrate --source /private/legacy-approvals \
  --destination /private/native-approvals-v1
# After reviewing counts and stopping every source process:
grantline-rs migrate --source /private/legacy-approvals \
  --destination /private/native-approvals-v1 --write --offline
```

The tool accepts bounded private regular JSON files, rejects symlinks, hardlinks,
unsafe paths, unsupported versions and destination overwrite, and verifies the
source again before an atomic directory publication. The manifest stores per-file
semantic SHA-256 hashes and counts; these hashes are not full backup verification.
Python request tokens, arbitrary commands, notes and legacy code plans are not
copied. Legacy records become schema-1 read-only archives, visible only to the
original requester and required approvers through the configured identity mapping.
They cannot be approved or published. Request a fresh immutable native plan.
Native schema-1 records are copied; pending/approved records become
`migration_review` with decisions cleared, and interrupted outcomes become
unknown. Re-run migration to a **different** destination when testing another
upgrade. Existing output, including sanitized archives, is supported as input.
No migration command changes source files, GitHub, Slack or IAM.

Point the new config at the new store and run it first on a separate loopback
port with fixture/saved observations. Verify row counts, archive authorization,
SSO with two independent identities and an isolated Slack/GitHub policy sandbox.
For a read-only shadow comparison, capture the same service observations once
and compare both CLIs against the same JSONL baseline. Separate configured reader,
probe and writer identities; do not grant a reader write permission for testing.

Only after separately authorized validation should an operator switch traffic.
Roll back by stopping the new process, switching back to the pinned old image
and its untouched original config/state, and restoring the previous ingress.
Do not point an old Python binary at native approval files, reuse bearer links
from migrated archives, or run two approval writers against one directory.
Inspect any external PRs/DMs created after cutover; rolling back the application
does not undo them or restore IAM.

## Native write and recovery boundaries

Use `plan --live`/`probe --live` explicitly. For a supported system, preview
`apply --system NAME --live --json`, review its plan hash and exact scope, then
an authorized operator can use `--write --expect HASH`. Preview is not an IAM
decision; service ownership and effective target-identity validation still apply.
See [adapter commands and boundaries](../rust/README.md) for each writer.
PostgreSQL transaction rollback, ClickHouse inverse review and local/remote S3
original-byte restore have different semantics. Remote JSON S3 writes require
an endpoint that actually implements strong ETag/If-Match atomically; the config
flag does not prove that behavior. Filer writes target one existing owning
identity file, selected with `apply --system NAME --subject IDENTITY --live`.
Configure `admin_filer_url_env` and optionally `admin_filer_auth_env` or
`admin_filer_jwt_env` separately from reader credentials. The latter mints a
short-lived HS256 Filer JWT. Review a fresh plan before `--write --expect HASH`.
Shared group/policy documents and inherited grants cannot be flattened into a
user file; IAM Query remains read-only. Backups include original credentials,
are mode 0600 and must stay private. Filer backups are inspection/recovery
records, not inputs for the monolithic-JSON `restore` command. A Filer endpoint
is not assumed to implement atomic If-Match: receipts always disclose
`concurrent_admin_guarantee=false`. Service reload, IAM backups and effective access are separate
checks. Restore must not overwrite a target changed since the reviewed apply.

Actual production SSO, Slack workspace, GitHub sandbox, service reload and
traffic cutover are deployment acceptance checks. Isolated tests and green CI
do not prove those checks or authorize running them.


## Observation, console and expanded privilege compatibility

Services are read concurrently with at most eight workers and merged in config
order. A service failure becomes unknown; an independent service can still be
shown. The console shares complete observation generations, coalesces concurrent
refreshes and invalidates on config/intent byte changes. `[web] cache_ttl_seconds`
defaults to 60 (0 disables, maximum 3600). The Refresh control bypasses TTL;
background refresh runs only in live mode. These display caches never authorize
a writer, probe or saved snapshot. CLI plan/graph still have no implicit writes.

`ca_bundle_env` names a PEM CA-bundle path for verified PostgreSQL and HTTP/S3
clients (S3 plane config for remote IAM, adapter config for data probes).
All certificates are loaded; missing/empty/invalid bundles and hostname mismatch
fail closed. No certificate-verification bypass is provided. PostgreSQL uses
`sslmode=require` with this bundle; libpq `verify-full` spelling, Unix sockets,
multi-host and client-certificate authentication remain outside the native DSN
contract. `sslmode=disable` is an explicit plaintext choice.

PostgreSQL expands `ALL` into the server's table privilege set, or the fixed
schema/database sets; `TEMP` becomes `TEMPORARY`. Multiple configured databases
require `apply --database NAME`; that selection must match include/exclude rules
and still executes one database transaction. `postgres_write_public=true`
explicitly authorizes PUBLIC object/default ACLs. `postgres_write_relations`
contains exact opt-in view/partition/inherited-relation resources. Column ACLs,
delegation, ambiguous grantors, owner/privileged targets and unmodelled default
scopes remain refused. Membership and default plans retain their separate scope
allowlists and cannot mix with object ACL changes.

ClickHouse defaults to one SELECT/INSERT atom. `clickhouse_write_privileges`
explicitly authorizes additional groups/leaves such as ALTER, CREATE, DROP,
SHOW, OPTIMIZE, dictGet or ALL. The server's bounded `system.privileges` tree
expands aliases into scope-compatible leaves. One statement may contain multiple
leaves only for the same action, subject and literal allowlisted resource; mixed
scopes/actions remain refused. Extended mode supports UUID-backed view/table
engines and direct covering GRANT OPTION. There is no ON CLUSTER, delegated
membership expansion, CAS, transaction rollback or automatic retry.

S3 `probe --live --write` tests Write with a fixed tiny body at a random UUID
under the selected prefix and conditional `If-None-Match: *`, then deletes that
same temporary object using the same explicit subject key. Upload does not imply
delete: cleanup failure reports the exact leftover key; an uncertain PUT reports
its possible key without automatically deleting an unconfirmed object. Ordinary
`probe --live` remains List/HEAD only. Only use explicit write probes where
creating and possibly retaining a temporary object is authorized.

Subject details show direct/inherited grants and bounded distinct access paths;
resource details provide bucket/prefix and database/schema navigation. Grant
source/grantor remain visible. Matrix cells link to details, and detail actions
prefill the authenticated request form. History compares selected snapshot names
or `?since=...`; malformed history stays an error rather than disappearing.
The graph retains the original entity borders/layout, keyboard controls and
resource hover/dimming. Four locale labels preserve configured proper names.

`notify --live --json` saves a fresh snapshot and prints access and visibility
changes. External Slack delivery additionally requires `--send` and
`[notify.slack]` with `bot_token_env` and `channel`; `redirect_to` supports a
pilot destination. First run only establishes a baseline. Saved snapshots are
not rolled back after dispatch failure; inspect the result before re-running.
Slack output disables mentions/markdown and bounds message length. This drift
notification command is separate from the signed approval workflow.

Operational authentication and approval remain bound to verified identities.
The native console publishes an approved policy PR; it does not automatically
execute IAM on approval. Use a separately reviewed `apply` for direct IAM writes.
The legacy bearer approval links / local request-execute CLI are deliberately
not accepted by the native auth contract; migrated requests need fresh reviews.


The map/resource `days` filter accepts 1–3650 days and compares consecutive
recorded snapshots with the displayed observation. It keeps current ancestor/
descendant context for changed grants; revoked and invisible permissions are
not drawn as current access. Missing pre-window history is explicitly incomplete.
Declared bridges and policy attachments have no historical grant timestamp and
serve only as current context. History is bounded to 1000 files, 32 MiB per
snapshot and 128 MiB total for recent-route selection; corrupt history fails
closed. Cached observations keep their original observation timestamp. Record
history explicitly with authenticated snapshots or a scheduled `snapshot`/`notify`
invocation; a read-only plan never creates it implicitly.

The migration's historical synthetic benchmark measured process-start-to-plan
medians of 8.0 ms Rust / 100.7 ms Python for a 212-grant fixture, and 112.7 ms
Rust / 261.6 ms Python for three independent HTTP readers with 100 ms delay each.
The Python benchmark launcher was retired with the service; these numbers are a
historical measurement, not a current performance guarantee. Native cache and
concurrency regressions are checked by `scripts/check_rust_runtime.py`.
