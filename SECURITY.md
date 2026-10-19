# Security

Report vulnerabilities privately through GitHub's **Report a vulnerability**
button on this repository's Security tab. Keep credentials and approval URLs
out of public issues. The current default branch is the supported source version.

## Trust boundaries

- The native console binds to loopback by default. Shared deployments require
  configured native OIDC or a trusted authenticated proxy; explicit public preview
  is only a read-only fictional demo. Native OIDC verifies signatures, issuer,
  audience, PKCE, state and nonce. Proxy deployments must strip untrusted identity
  headers and keep the backend isolated from clients.
- Native sessions and CSRF checks bind browser actions to authenticated identities.
  The retired Python service's bearer approval links are not a native login flow.
  Approval binds the original request, approvers and immutable plan. Slack callbacks
  require configured signatures and replay checks. A review or GitHub PR never
  implicitly applies native IAM changes.
- Readers and writers use separately configured credentials. Keep `admin_*`
  credentials out of observation-only deployments. The operator CLI, process
  environment and local filesystem remain trusted; web approval rules cannot
  restrict a human who already holds service administrator credentials.
- Supported writes require reviewed plan hashes and explicit `--write --expect`.
  Preserve recovery artifacts and inspect uncertain outcomes before retrying.
  No cross-service transaction or atomic service/local-log commit is claimed.
- Private state, approvals and snapshots belong outside the checkout with the
  documented `0700` directories and `0600` files. Preserve backups and follow
  [migration and rollback](docs/rust-operations.md#offline-state-migration-and-rollback).
- SQL generators and native writers validate supported privileges and resource
  scopes. Column ACL observation does not enable column writes. Unrepresentable
  ACLs remain unknown and must not produce inferred convergence actions.
- S3 interpretation is not a complete AWS policy evaluator. Discovery and
  prefix-conditioned listing capabilities remain distinct from object access.
  Version reads, retention inspection and governance operations retain exact
  privilege names. Unsupported conditions, missing policies and ambiguous denies
  remain unknown. Use service-native evaluation for final access decisions.
- The Python modules under `tests/reference` are test-only, have no application
  entry point and refuse network credential resolution. Docker excludes tests
  and ships the Rust binary, WASM and shared assets without Python or Node.

See [native authentication and recovery](docs/rust-operations.md) for the full
supported deployment and writer contracts.

## Read credentials

Use service-enforced read-only roles. On ClickHouse, also constrain observer query
execution, memory, and scan limits through a settings profile and quotas; an HTTP
client timeout alone does not stop server work. See the official
[query complexity limits](https://clickhouse.com/docs/operations/settings/query-complexity).

Demo identities, organizations, hostnames, and data in this repository are fictional.
The license does not establish permission to publish someone else's code or assets.

## Public-source privacy gate

Tracked hooks and the CI `privacy` job check newly published commit ranges for
realistic Slack user IDs, non-example email addresses, private-key/token patterns,
private IPv4 addresses, internal hosts and personal home paths. Author/committer
emails must use GitHub's noreply domain. A narrowly scoped exception preserves
the official AWS SigV4 example access key in its existing regression test; test
directories are not generally exempt.

The gate does not identify every person, secret, username or sensitive value.
Binary images/GIFs, unrecognized identifiers in arbitrary prose and PR descriptions still
need human review. Existing history is not rewritten or audited on every PR.
For a staged-index audit use `python3 scripts/privacy_gate.py --tracked`; for a
specific new range use `python3 scripts/privacy_gate.py --range BASE HEAD`.
If CI has no valid base (initial push or reusable invocation), it scans all history
instead of silently skipping. That fallback can report historical findings;
ordinary PR/push ranges do not recheck their baseline. CI runs on PRs and main
pushes, only after publication. A direct push or web-created merge on another
branch is not covered by this workflow; use hooks and GitHub email privacy settings.
Never suppress a finding merely because the identifier belongs to another
workspace: it can still link a person to operational context.
