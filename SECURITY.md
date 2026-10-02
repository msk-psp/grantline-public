# Security

Report vulnerabilities privately through GitHub's **Report a vulnerability** button
on this repository's Security tab. Do not put credentials or approval URLs in issues.
The current default branch is the supported version.

## Trust boundaries

- Grantline is an operator tool. The HTTP server binds to loopback. Before sharing
  it, put an authenticated reverse proxy in front of it, restrict
  network access, and set `[web] trusted_hosts = ["console.example.com"]` in the external
  configuration. This allowlist and same-origin POST checks do not authenticate users.
- Optional `[web.auth] mode = "proxy"` requires one validated proxy identity header
  for console data and writes. Grantline does not validate OIDC sessions itself.
  Strip untrusted client identity headers at the proxy and keep the backend reachable
  only by that proxy. A header from a directly reachable backend can be forged.
  Without this configuration the local console remains unauthenticated. See
  [console sign-in setup](docs/usage.md#console-sign-in).
- Reading and writing use separate configured credentials. Keep write credentials out
  of observation-only deployments. The CLI, config, process environment, and local files
  belong to trusted operators; approval rules govern the web console, not operator CLI
  access to service credentials.
- With `[approvals]`, direct web writes are refused. Tokens authorize one approver of
  one request, must be privately delivered, and are never returned to requesters. Slack
  pilot redirection is ignored for approvals. Without Slack, an operator can run
  `grantline request --links ID` and deliver each URL only to its intended recipient.
  These URLs remain sensitive while the request is pending: delete or deny abandoned
  requests and protect browser history. Tokens do not expire automatically.
- Approval files have mode `0600`, their directory `0700`. Keep configuration, approval
  stores, audit logs, and observation snapshots outside your checkout. Audit records
  contain identities and commands; one attempt and one result are appended per write.
  If a process dies after the attempt, reconcile the service before retrying. A remote
  change and a local result log cannot form an atomic transaction.
- The web body limit is 64 KiB and socket timeout 10 seconds. Use reverse-proxy request
  limits for shared deployments; this small server is not an internet-facing service.
- SQL writes accept the explicit privileges offered by each adapter, quote identifiers,
  and refuse unsupported privileges. They are not an arbitrary SQL interface.
- IAM observation is not a complete AWS policy evaluator. Conditional and negative
  statements, unsupported actions/resource wildcards, and non-exact/overlapping denies are
  reported as unknown. The S3 system is then unobserved for convergence planning;
  omitted grants must not be interpreted as denied access. Use the service's own policy
  evaluator/probes for final authorization decisions. Missing policy documents are
  reported separately. Policy writes do not remove access inherited from wider grants.

## Read credentials

Use service-enforced read-only roles. On ClickHouse, also constrain observer query
execution, memory, and scan limits through a settings profile and quotas; an HTTP
client timeout alone does not stop server work. See the official
[query complexity limits](https://clickhouse.com/docs/operations/settings/query-complexity).

Demo identities, organizations, hostnames, and data in this repository are fictional.
The license does not establish permission to publish someone else's code or assets.
