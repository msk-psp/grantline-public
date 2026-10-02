# PRD 004 — Porting to Rust / Dioxus: plan, and what it would and would not buy

Status: **plan only** (2026-09-04). Nothing here is scheduled.

## 1. Why this was raised

"There are speed issues, let's port to Rust + Dioxus." The issues were real; this document
records what they turned out to be, because that decides whether a port addresses them.

## 2. Where the time actually goes (measured, real cluster, 2026-09-04)

| Step | Time | Where |
|---|---|---|
| observe, all 5 adapters (PG ×2, CH ×2, S3 filer walk) | **4.5 s** | network — other machines answering |
| `plan()` before the fix | **minutes** | S3 `grant_cmd` re-walked the filer tree once per change (282×) |
| `plan()` after the fix (`_enforced_doc` reuse) | 0.1 s | Python |
| render a page from a cached observation | **3–7 ms** | Python |
| routes page over the wire | 49 KB, 121 paths, ~230 nodes | browser |
| zoom / glide before the fix | stutter | browser re-tessellated the SVG on every viewBox write |
| zoom / glide after the fix (CSS transform) | smooth | compositor |

Every stall had one of two causes: **a network round trip that should not have happened**, or
**the browser re-laying-out the SVG**. Neither runs in Python. The Python that does run —
diffing a few thousand grants and printing HTML — is single-digit milliseconds.

## 3. What a port would consist of

A faithful port is the whole product, not the page:

| Piece | Now (Python) | Port | Notes |
|---|---|---|---|
| PostgreSQL adapter | psycopg, 6 catalog queries, `has_*_privilege` probes | tokio-postgres | ACL parsing (`aclexplode`) stays SQL-side |
| ClickHouse adapter | HTTP + `SHOW GRANTS` parser | reqwest | parser is a port |
| S3 adapter | IAM tree merge, SigV4 (stdlib), data-path probes, planes | reqwest + hand SigV4 | the largest module; policy semantics are subtle (Deny, shadowing) |
| model / diff / graph / snapshot | dataclasses, sets | structs, `HashSet` | mechanical |
| approvals + Slack | JSON store, tokens | serde + reqwest | mechanical |
| CLI | argparse | clap | mechanical |
| web | `http.server`, f-string HTML | axum | mechanical |
| routes map | server-rendered SVG + 250 lines of JS | Dioxus (WASM) | the only part where Dioxus is *the* reason |
| tests | 20 script files | `#[test]` | must be re-derived, not translated — many pin bugs found live |

Estimate: **3–4 weeks** for parity, plus the adapters' live re-validation against every
mistake the current tests pin (string `Action`, `SHOW USERS` 497, `information_schema` blind
spots, `sum(cityHash64)` NULL trap …). The risk is not the Rust; it is re-discovering those.

## 4. What the port would buy

- Page render: 3–7 ms → <1 ms. Not perceivable.
- Observation: unchanged — it is the servers' time, not ours.
- Browser: unchanged — Dioxus emits the same SVG DOM; the compositor does the same work.
  A WASM app *could* virtualise the graph (draw only what's in view), but so can the
  current page in 40 lines of JS, and at 230 nodes it does not need to.
- Deployment: a single static binary instead of a venv. Real, and the one genuine gain.

## 5. Recommendation

**Do not port for speed.** The speed problems are fixed and were never in the language.
Revisit if any of these becomes true:

1. The map must show **thousands** of nodes with per-node interactivity — then a canvas /
   WebGL renderer (Dioxus or not) is the answer, and the server language still isn't.
2. Distribution matters more than iteration — a single binary for people who won't run
   `uv`. Then port the **CLI only** first; the web console can stay Python behind it.
3. Observation must be **concurrent** across 20+ instances — Python `asyncio` gets there
   too; if it doesn't, Rust does.

If speed is still felt, the cheaper knobs in order: warm the observation cache at start-up
(the first page pays 4.5 s once per minute), observe adapters concurrently (5 → ~2.5 s),
refresh in the background so no request ever pays it.

## 6. Follow-up (2026-09-04, later the same day): "drag lags and flickers — port?"

Measured in the browser on the real map (1865×1273 css px, dpr 2, 687 paths, 242 texts):

| Motion | Before | After | What changed |
|---|---|---|---|
| JS-driven pan (translate) | 16.7 ms/frame, some 34 ms | 16.7 ms/frame | nothing to fix |
| JS-driven zoom (scale) | **50–67 ms/frame** (15 fps) | main thread idle, 16.7 ms | scale is a CSS transition; the compositor scales the bitmap it has and re-rasterises once at rest |
| any motion, with glass | +backdrop blur + animated gradient re-composited per frame | plain panels on this page | `backdrop-filter` and `body::before` animation off for `.page.wide` |
| selected node | `filter: drop-shadow` re-rendered per frame — the "flicker" | thicker stroke | no SVG filter |

Every one of these is a rendering-pipeline cost in the browser. A Dioxus/WASM app emitting
the same SVG pays exactly the same rasterisation; the language on either side of the DOM
does not appear in the profile. The only change that would alter *this* cost is a different
renderer (Canvas/WebGL), and that is a swap inside `static/map.js` — which is why the map
became JSON + a module. Recommendation unchanged.

## Implementation update — 2026-10-02

Startup warming and concurrent adapter observation are implemented. Observations now also
refresh in the background; cached requests use a completed result while refresh runs.
The first observation and an explicitly fresh read still wait. Rust/Dioxus remains an
unscheduled option, not required implementation work. Current live latency is unverified.
