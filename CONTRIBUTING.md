# Contributing

## Run it

```bash
uv venv && uv pip install -e ".[postgres,dev]"
grantline -c grantline.toml plan        # bundled fixture, no credentials needed
grantline -c grantline.toml serve       # http://127.0.0.1:8420
```

## Before you push

Enable the repository's opt-in hooks once (no global Git settings change):

```bash
git config --local core.hooksPath .githooks
```

The pre-commit hook scans staged text and effective author/committer emails,
not unsaved working-tree edits. The pre-push hook checks new commits, including
their message bodies, author/committer emails and
files added then removed within the range. CI repeats the range check as the
`privacy` job. Require that check in the protected branch rules; local hooks
can be bypassed and are not an access control.

Use fictional accounts and `example.com` addresses in fixtures. Use a GitHub
`users.noreply.github.com` email for new commits; this does not rewrite existing
history. GitHub web-flow’s exact `noreply@github.com` committer address is
also accepted; other `github.com` emails are not exempt. Never paste approval tokens or real Slack IDs in examples. Diagnostics
show rule names and locations only, not matched values.

In GitHub **Settings → Emails**, enable **Keep my email addresses private** and
**Block command line pushes that expose my email**. This also protects the identity
GitHub uses for future web-created merge commits. CI runs after upload: a failing
check cannot retract data already published. It is a review barrier, not a promise
that publication was prevented. The opt-in hooks run before commit/push instead.

```bash
ruff check grantline tests
python tests/run.py
node tests/test_map_hover.mjs
python3 scripts/privacy_gate.py --staged
```

CI runs these checks on Python 3.11–3.13 plus the fixture `plan`. A change is
not done until the checks pass locally.

## Where things live

| Concern | File |
|---|---|
| what a grant *is* | `grantline/model.py` |
| reading a system | `grantline/adapters/<system>.py` — `observe()`, `probe()`, `grant_cmd()` |
| declared vs observed | `grantline/diff.py`, `grantline/subsume.py` |
| routes (hops, bridges, kinds) | `grantline/graph.py`; data for the map in `web.graph_data()` |
| pages | `grantline/pages.py`, `grantline/web.py`; assets in `grantline/static/` |
| decisions and their reasons | `docs/prd/` |
| experimental native core, offline CLI and Leptos playground | `rust/` — [guide](rust/README.md), [migration stages](docs/prd/006-rust-leptos.md) |

For Rust changes run the native checks and all three differential suites in the
[Rust guide](rust/README.md#check-the-boundary). `plan` is read-only; only the
explicit `snapshot` command records state. Native PostgreSQL/ClickHouse/S3 reads require
`--live` and separately configured readers. PostgreSQL `probe --live` supports
read-only ACL checks and optional mapped subject TCP logins; see the Rust guide.
ClickHouse/S3 probes and all writers remain pending. Run `python3 scripts/check_rust_clickhouse.py --docker` and
`python3 scripts/check_rust_postgres.py --docker` plus
`python3 scripts/check_rust_s3_network.py --docker` for isolated boundary and
real-server checks. Local S3 IAM files/trees support observation
and grouped previews; directory-backed shared policies cannot be rewritten from
a per-user change.

## Conventions

- **Tests pin a mistake, not a feature.** Most files in `tests/` exist because something
  was wrong on a real cluster; the docstring says what. Keep that habit: when a live run
  finds a bug, the fix lands with the test that would have caught it.
- **A finding beats silence.** If something cannot be modelled, say so in a `Finding`;
  never let an unread scope render as "no access".
- **No credentials in the repo**, ever — config lives outside it (`~/.config/grantline/`)
  and secrets travel only through environment variables the config names.
- **Design changes get a PRD** in `docs/prd/` before the code. Bug fixes and small
  changes don't.
- Commit messages: `type(scope): what changed and why it matters` — the *why* is the
  part a reader can't get from the diff.
- The console is read-only by default. A write path needs the config to name a write
  credential *and* the environment to carry it; keep that split.

## Try approvals locally

```bash
python3 examples/approval-demo/run.py
```

Open **http://127.0.0.1:8422/demo** to switch between fictional requester and
reviewer roles, inspect a simulated Slack inbox, and approve or deny a sample
request. The real approval backend runs against disposable local fixtures; PRs
are simulated and no external credentials or accounts are required. See the
[approval playground guide](examples/approval-demo/README.md) for the steps and
what this does and does not verify. Restart the command for a fresh test state.
