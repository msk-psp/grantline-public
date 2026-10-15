# Approved permission changes as repository PRs

The native service adapters stay read-only. An optional trusted writer proposes a
repository patch and opens its PR only after every configured approver agrees.
Creating a PR is not applying a permission. Merge, deployment and real access
verification remain separate operator steps.

```toml
[approvals]
store = "/persistent/approvals"
admin = ["U_REVIEWER"]

[approvals.identities]
requester = "U_REQUESTER"
reviewer = "U_REVIEWER"

[approvals.code_writer]
command = ["/trusted/bin/access-writer"]
repository = "demo/access"
systems = ["s3"]
timeout = 60
```

Keys in `identities` are authenticated proxy login identities, not display names.
Values are approval recipient identities. Shared deployments must use a trusted,
header-stripping authentication proxy and persistent request storage. The requester
cannot approve their own request; there is no pilot exception.

The command comes only from trusted server configuration, runs without a shell,
and receives one JSON document on stdin:

```json
{"schema_version":1,"operation":"preview","request_id":"20260101T000000Z-aabbcc","action":"grant","system":"s3","subject":"demo-user","resource":"bucket:demo/team","priv":"Read","requester":"U_REQUESTER","approvers":["U_REVIEWER"]}
```

Preview must be read-only and return `base_commit` (40 lowercase hex),
`patch_sha256` (64 lowercase hex), and a nonempty human-readable `summary`.
Submit receives the same document with `operation="submit"` and `expected_plan`
containing that exact preview. It returns `base_commit`, `patch_sha256`, `pr_url`.
The URL must be HTTPS on GitHub and match the configured repository's `/pull/N`.
The writer must independently check the plan and make submit idempotent by
`request_id`, including after timeout or lost response. Grantline re-previews before
submit and refuses a changed plan. Request file locks prevent concurrent submits.

The writer owns its repository credentials, least-privilege scope, policy validation
and PR creation conventions. It must not apply native permissions. Grantline never
prints writer stderr or malformed responses because they may contain secrets.
Requests become `proposed` once the PR URL is recorded; this version does not claim
to track merge, application, or effective permission verification.
