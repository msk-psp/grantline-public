# Grantline

[English](README.md) · [한국어](docs/README.ko.md) · [日本語](docs/README.ja.md) · [简体中文](docs/README.zh-CN.md)

**Untangle access. Follow the grants.**

An open-source **permission management and access control dashboard** for
**PostgreSQL, ClickHouse and S3-compatible storage**, including SeaweedFS.
Visualize role-based access control (RBAC), trace access through roles, groups
and IAM policies, and review permission drift before changing native grants.
Enforcement stays in each service.

![Grantline access map](docs/images/routes-map.png)

## Try it locally

Requires Rust **1.99.0**. The fictional demo needs no services or credentials.
The backend is native Rust; the console uses Leptos SSR and browser WASM.

```bash
git clone https://github.com/msk-psp/grantline-public.git
cd grantline-public
rustup target add --toolchain 1.99.0 wasm32-unknown-unknown
cargo +1.99.0 install --locked wasm-bindgen-cli --version 0.2.129
RUSTUP_TOOLCHAIN=1.99.0 scripts/build_rust_ui.sh
cargo +1.99.0 run --locked --manifest-path rust/Cargo.toml -- -c examples/demo/grantline.toml serve
```

Open **http://127.0.0.1:8424/**. The map is the first page; **Services** lists
resources by service, **Matrix** compares permissions, and **Changes** previews
explicit grants and revokes. Selecting a subject shows their access and routes.

The console supports **English, 한국어, 日本語 and 简体中文**. Select a language
at the top of any page; your choice is saved in a cookie. On your first visit,
Grantline uses your browser language. Account names, resource paths and native
commands retain their original spelling.

## Run with Docker

The release workflow tests and publishes native Rust/WASM images with `linux/amd64` and `linux/arm64` on GHCR.
Stable releases also update `latest`; pre-releases keep their own version tag.

```bash
docker run --rm -p 127.0.0.1:8420:8420 ghcr.io/msk-psp/grantline-public:v0.1.0
```

Open **http://127.0.0.1:8420/** for the built-in demo. No credentials are needed.
For real systems, mount your own configuration and persist runtime state; see
[container configuration](docs/usage.md#containers). Pin a release tag or digest
for deployments. The image runs as UID 10001 without Python or Node. Older release tags retain
their original runtime; merging this change does not publish a new image.
Build this version locally with `docker build -t grantline-native:local .`.

## Common commands

```bash
rust/target/debug/grantline-rs -c examples/demo/grantline.toml plan      # inspect drift and native commands
rust/target/debug/grantline-rs -c examples/demo/grantline.toml plan --json # structured preview
rust/target/debug/grantline-rs -c examples/demo/grantline.toml history  # compare recorded observations
```

Supported native writers require an explicit system, a reviewed plan hash and
`--write --expect HASH`. Review adapter scope before enabling them.

## Connect your systems

Keep real configuration outside the repository, for example
`~/.config/grantline/prod.toml`. Configuration names environment variables for
credentials; observation and write credentials are separate. Native PostgreSQL does not require a Python driver.

- [Native operations and migration](docs/rust-operations.md): OIDC, Slack/GitHub,
  private state, upgrade and rollback.
- [Configuration and operations](docs/usage.md): adapters, credentials, bridges,
  intent, probes, snapshots and approvals.
- [Security](SECURITY.md): sharing the console and enabling writes. Native shared deployments require configured OIDC or a trusted authenticated proxy.
- [Contributing](CONTRIBUTING.md): development setup and checks.
- [Product scope](docs/prd/003-scope.md): requirements and implementation status.

An unread scope is **unknown**, never “no access”. IAM writes require a separately reviewed native CLI plan. Approval and PR
creation do not apply access. Declaration-based revokes are
bounded by managed subjects and the systems the intent claims to describe.

The application and default container are Rust/Leptos. A minimal Python oracle
lives only in [tests/reference](tests/reference/README.md) for differential checks;
it has no service entry point and is excluded from container builds.

## License

[Apache-2.0](LICENSE).
