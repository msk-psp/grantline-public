# Contributing

## Run it

```bash
uv venv && uv pip install -e ".[postgres,dev]"
grantline -c grantline.toml plan        # bundled fixture, no credentials needed
grantline -c grantline.toml serve       # http://127.0.0.1:8420
```

## Before you push

```bash
ruff check grantline tests
python tests/run.py
node tests/test_map_hover.mjs
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
