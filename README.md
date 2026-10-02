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

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). The demo needs no servers
or credentials.

```bash
git clone https://github.com/msk-psp/grantline-public.git
cd grantline-public
uv venv
uv pip install -e .
source .venv/bin/activate
grantline -c examples/demo/grantline.toml serve
```

Open **http://127.0.0.1:8420/**. The map is the first page; **Services** lists
resources by service, **Matrix** compares permissions, and **Changes** previews
explicit grants and revokes. Selecting a subject shows their access and routes.

The console supports **English, 한국어, 日本語 and 简体中文**. Select a language
at the top of any page; your choice is saved in a cookie. On your first visit,
Grantline uses your browser language. Account names, resource paths and native
commands retain their original spelling.

## Common commands

```bash
grantline -c examples/demo/grantline.toml plan      # inspect drift and native commands
grantline -c examples/demo/grantline.toml apply     # dry-run; changes nothing
grantline -c examples/demo/grantline.toml history  # compare recorded observations
```

`apply --write` changes the configured system, including demo fixture files.
Review the preview and management scope before enabling it.

## Connect your systems

Keep real configuration outside the repository, for example
`~/.config/grantline/prod.toml`. Configuration names environment variables for
credentials; observation and write credentials are separate. PostgreSQL also
needs `uv pip install 'grantline[postgres]'`.

- [Configuration and operations](docs/usage.md): adapters, credentials, bridges,
  intent, probes, snapshots and approvals.
- [Security](SECURITY.md): sharing the console and enabling writes. The built-in
  server does not authenticate users; shared deployments need an authenticated proxy.
- [Contributing](CONTRIBUTING.md): development setup and checks.
- [Product scope](docs/prd/003-scope.md): requirements and implementation status.

An unread scope is **unknown**, never “no access”. Every write previews the native
operation and records an audit attempt and result. Declaration-based revokes are
bounded by managed subjects and the systems the intent claims to describe.

## License

[Apache-2.0](LICENSE).
