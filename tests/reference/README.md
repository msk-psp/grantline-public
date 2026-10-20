# Test-only Python reference

These 13 modules are the minimum dependency closure used by the existing native
core, graph, snapshot, S3 and SigV4 differential suites. They were moved from
the retired Python service without changing their permission semantics. The
reference is an oracle for represented scopes, not an assertion that unsupported
PostgreSQL/ClickHouse permissions are complete.

There is no Python application, package entry point, web server, login screen or
approval backend here. The native test scripts explicitly add this directory to
their import path; normal runtime configuration does not load it. Docker's
allowlist excludes `tests/` and ships only Rust, WASM and runtime assets.
Network credential resolution is disabled in these adapters. Run real-provider
checks against disposable services through the native binary.

Keep the existing differential tests while native observation coverage expands.
Retire a reference module only after equivalent independent contract cases cover
its semantics; do not make the native implementation its own oracle.
