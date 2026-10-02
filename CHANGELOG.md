# Changelog

Notable changes, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/);
versions follow [SemVer](https://semver.org/) once 1.0 is cut — until then, minor bumps may break.

## [Unreleased]

### Changed
- The routes map is the front page. `/` is the map, services moved to `/services`, and
  the nav leads with **routes**. "Who reaches what, and by what path" is the question the
  console is opened for; the inventory is the one you drill into afterwards. `/graph`
  still opens the map, so bookmarks and `/graph?focus=` links keep working.
- The map's shell no longer waits for the observation. `/` answers in milliseconds and
  the picture arrives from `/api/graph.json`; until it does, the page says what it is
  waiting for. Before, the heaviest read in the tool stood between a first-time visitor
  and any pixel at all.
- Changes page, where the console holds no write credential: the tab and the page head
  say so before the form is filled in, instead of leaving it to be discovered at the
  preview. The command is still spelled out; only the button was ever missing.

### Added
- The map says which systems it could not read (F6), by name and with the reason,
  above the picture. A system that failed to answer draws no lines, and a map with no
  lines into it looks exactly like a system nobody can reach — the confusion this tool
  exists to prevent, now on its first screen.
- Changes page: proposing a grant or revoke and the queue of everything proposed sit on
  one screen, with the exact command each would run and who still has to agree. The nav
  carries the pending count.
- Routes map: one column per kind (principal — humans then declared services under header
  rows — service account, role, group, policy, service instance), edges coloured by relationship with arrowheads, click-to-follow with a
  gliding camera, wheel zoom and drag pan, prod/staging toggles, brand icons, people's names.
  Selection is a stack: a lit node narrows to routes through every pick, picking it again steps back.
- Resources column: picking a service instance opens a tree of what it collapses — db ›
  schema shown, tables folded under their schema (▸ to open, ⊞ expand all), bucket › prefix
  for S3 — only what the selection reaches (`/api/resources.json?instance=`). S3 rows carry
  the identity's grade even when its access comes through a policy.
- Service toggles next to the environment ones; a toolbar with headers; boxes are opaque so
  a line passing behind one is hidden by it.
- Account, role, group and policy columns are grouped by service with a header row; an
  edge that skips a column travels a lane above the columns and moves vertically only in
  the gutters, so no line runs behind a box it does not belong to.
- Every node shows where it lives and who uses it: an icon strip with the services it
  appears in and the declared service that reaches it (one hop on, so Airflow's roles are
  marked too), plus `stg` / `prod·stg` when not simply production. Full names on hover.
- The instance column is titled `resources in`, so `service` names one thing on the map.
- Bridges may name a declared actor as `service:<name>` so it never collides with a login
  of the same name (`service:airflow` vs the PostgreSQL user `airflow`).
- S3 routes drawn the way access is resolved: identity → group → policy → bucket.
- Adapters report subject kinds (account vs role) from what they observe; `[graph]` config
  names services, people, and environments.
- `/api/graph.json` — the map as data; `/static/*` — stylesheet and map module.
- Approval flow with Slack notification; `history`, `probe`, `request`, `notify` commands.
- PRD 004: the Rust/Dioxus port, planned and measured (recommendation: not for speed).

### Changed
- Routes page: zoom and glide are compositor transitions (JS-driven scale re-rasterised the
  layer every frame — 50 ms/frame); the page drops the backdrop blur, the ambient animation
  and the SVG drop-shadow, which were re-composited under every drag.
- The console keeps one observation for 60 s; POST reads fresh; `?refresh` forces.
- `plan()` reuses the enforced S3 document read by `observe()` — it re-walked the IAM
  tree once per change and stalled for minutes on a real filer.
- Stylesheet and map script moved out of Python strings into `grantline/static/`.

## [0.1.0] — 2026-08

Initial PoC: matrix, plan/apply, PostgreSQL · ClickHouse · S3 adapters, snapshots.
