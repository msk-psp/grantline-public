"""F1 (inventory by service) and F2 (subject page with routes) — PRD 003.

Both features fail the same way: by summarising. A per-service total or a single
representative route reads as an answer while withholding the thing a steward would
act on, so these tests assert against *collapse*, not just presence.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline.graph import build
from grantline.model import Grant
from grantline.pages import parse_path, render_group, render_inventory, render_subject

G = [
    Grant("clickhouse", "researcher_c", "db:product", "SELECT"),
    Grant("clickhouse", "researcher_c", "db:reference", "SELECT"),
    Grant("clickhouse", "researcher_c", "global:*", "REMOTE"),
    Grant("clickhouse", "researcher", "db:product", "SELECT"),
    Grant("postgres", "researcher_a", "role:analytics_reader", "MEMBER"),
    Grant("postgres", "analytics_reader", "table:analytics.public.vitals", "SELECT"),
    Grant("postgres", "researcher_a", "role:duckdb", "MEMBER"),
    Grant("postgres", "duckdb", "table:analytics.public.vitals", "SELECT"),
]
BR = [{"from": "duckdb", "to": "bucket:warehouse", "system": "s3",
       "note": "server-held key"}]


def t(name, cond):
    assert cond, name
    print("  ok", name)


def test_f1_keeps_kinds_apart():
    """A service must not collapse to one number — that is where F1's value dies."""
    h = render_inventory(set(G))
    t("db kind row", ">db:" in h.replace('"', "") or "db<" in h or ">db</a>" in h)
    for kind in ("db", "global", "role", "table"):
        t(f"kind {kind} shown", f">{kind}</a>" in h)


def test_f1_reaches_resources_in_one_step():
    h = render_inventory(set(G))
    t("group link present", "/g/clickhouse/db" in h)
    g = render_group(set(G), "clickhouse", "db")
    t("individual resources listed", "db:product" in g and "db:reference" in g)


def test_f1_counts_subjects_not_just_grants():
    h = render_inventory(set(G))
    # clickhouse db: 2 resources, 2 subjects — both numbers must survive
    t("subject chips link out", "/s/researcher_c" in h and "/s/researcher" in h)


def test_f2_lists_every_reachable_resource():
    h = render_subject(set(G), build(set(G), BR), "researcher_c")
    for r in ("db:product", "db:reference", "global:*"):
        t(f"{r} listed", r in h)


def test_f2_table_includes_inherited_resources():
    """The list must be what they reach, not what bears their name — researcher_a holds no
    grant on the table at all; analytics_reader does."""
    h = render_subject(set(G), build(set(G), BR), "researcher_a")
    t("inherited resource listed", "table:analytics.public.vitals" in h)
    t("hop attributed", "via analytics_reader" in h or "via duckdb" in h)


def test_f2_shows_every_route_not_one():
    """researcher_a reaches the same table twice — via analytics_reader and via duckdb. Revoking
    one changes nothing, so both must appear."""
    routes = build(set(G), BR).routes_from("researcher_a")
    via = {r[1] for r in routes}
    t("both hops present", {"analytics_reader", "duckdb"} <= via)
    h = render_subject(set(G), build(set(G), BR), "researcher_a")
    t("analytics_reader route rendered", "analytics_reader" in h)
    t("duckdb route rendered", "duckdb" in h)


def test_f2_marks_the_bridge_distinctly():
    """A hop onto a server-held credential is not the same as a role membership."""
    h = render_subject(set(G), build(set(G), BR), "researcher_a")
    t("bridge styled apart", 'class="bridge"' in h)
    t("bridge destination reached", "bucket:warehouse" in h)


def test_routing():
    # 첫 화면은 지도다. services 는 자기 주소를 갖고, 옛 `/graph` 는 그대로 열린다 —
    # 주소를 옮기면서 링크를 깨지 않는 것이 이 세 줄의 전부다.
    t("root is the map", parse_path("/") == ("graph", ()))
    t("services moved", parse_path("/services") == ("inventory", ()))
    t("old /graph still opens the map", parse_path("/graph") == ("graph", ()))
    t("subject", parse_path("/s/researcher_c") == ("subject", ("researcher_c",)))
    t("subject unquoted", parse_path("/s/svc-duckdb%20x")[1] == ("svc-duckdb x",))
    t("group", parse_path("/g/postgres/table") == ("group", ("postgres", "table")))
    t("matrix", parse_path("/matrix") == ("matrix", ()))
    t("unknown 404", parse_path("/nope") == ("404", ()))


for fn in [v for k, v in dict(globals()).items() if k.startswith("test_")]:
    print(fn.__name__)
    fn()
print("all tests passed")
