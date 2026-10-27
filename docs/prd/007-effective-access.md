# Administrator effective-access checks

Status: Implemented and locally verified; not released or deployed. Owner: Grantline native console.

## Problem

A declared grant or an administrator's successful request does not establish a
researcher's access. An empty prefix can pass LIST without proving object reads;
an Iceberg client can report missing version metadata when the real failure is
S3 authorization. The existing CLI samples observed grants and uses HEAD for
Read, so it cannot diagnose a requested grant that is currently absent.

## Acceptance

- [x] [E1] An authenticated operator explicitly named in `web.probe_operators`
  can submit an exact subject/service/bucket/prefix, independently of observed
  grants. Local preview, an empty operator list, invalid CSRF/origin and a server
  without `--live` cannot send probe traffic.
- [x] [E2] LIST, HEAD and a one-byte Range GET have separate allow/deny/unknown
  results, HTTP status and elapsed time. Explicit sample keys must be in scope.
  Empty listings, missing objects, signature errors, redirects and incomplete
  responses never prove a successful data read or an ACL denial.
- [x] [E3] An optional, configured SeaweedFS Iceberg REST endpoint permits a
  subject-signed `s3tables` LoadTable check and a separate S3 metadata Range GET.
  Only an in-scope `s3://` metadata location is followed through the configured
  S3 endpoint. Catalog configuration, vended credentials and returned object
  contents are never displayed or used as alternate credentials.
- [x] [E4] The administrator can repeat identical inputs before/after an approved
  change and test an explicit out-of-scope path with expected denial. Results
  preserve unknowns and identify the target subject, instance and observation
  time. A denied positive check links to the existing approval request flow;
  running a probe never grants access or writes/deletes objects.
- [x] [E5] Fictional HTTP fixtures verify signing/identity, independent stages,
  negative boundaries, credential non-disclosure, safe URL handling, disabled
  defaults and the console form. Native tests, formatting and Clippy pass.
- [x] [E6] The same operator page checks PostgreSQL database CONNECT/CREATE and
  schema USAGE/CREATE separately using an explicitly mapped subject TCP login.
  The existing fixed `has_*_privilege` evaluator verifies session/current user;
  no observer fallback, schema/table creation or permission writes are attempted.
- [x] [E7] Operators can select PostgreSQL read checks independently of creation.
  Exact table resources check CONNECT/USAGE/SELECT; database/schema resources
  check prerequisites only. The UI defaults to read; API requests omitting the
  operation retain creation checks. A read-only fixture must pass SELECT checks
  while CREATE is denied, and revoking SELECT must change only that result.

## Boundaries and rollout

The operator must bind each configured credential to its correct subject; there
is no STS identity proof. No ambient AWS, observation or administrator credential
fallback is permitted. Browser input cannot select a destination URL or supply
credentials. One in-scope sample is evidence for that object only. Range reads
do not parse Iceberg manifests, execute a query, prove row access or test a user's
desktop network/client configuration. PostgreSQL pg_duckdb credential forwarding
and infrastructure policy generation/reload remain separate integration work.

Producer: this repository's native API, config and Leptos UI. Consumer: configured
Grantline deployments; old configs keep probes disabled. Deploy matching native
and WASM builds, configure explicit operators, endpoint names and subject-specific
probe credentials privately, then run a separately authorized staging validation.
No production access or deployment is part of this change. Rollback removes the
operator allowlist or restores the previous matching image/config; IAM is unchanged.

## Local evidence

`cargo +1.99.0 test --locked --manifest-path rust/Cargo.toml --workspace --
--include-ignored`: 89 passed, including the opt-in disposable PostgreSQL 18.6
case. `rust/tests/effective_access.rs` covers the API, HTTP fixtures and real
PostgreSQL database/schema ACL distinctions, read checks with CREATE denied, and
SELECT revocation without losing CONNECT/USAGE. API requests without an operation
retain creation semantics; invalid operation values are rejected. The PostgreSQL
read selector is covered by the SSR assertion. `rust/ui/src/verify.rs` covers result
rendering and expected denials. The original API regression failed with 404 before
implementation, then passed with authentication enforcement. Formatting, workspace
Clippy (`-D warnings`), hydrated WASM release build and public-source privacy scan
also passed. No live deployment or target-user desktop validation occurred.

Next action: review the feature, then release matching native/WASM builds and
explicitly configure private operators and target credentials before an authorized
staging validation. Inspect live grants from an unlocked operator session first.
