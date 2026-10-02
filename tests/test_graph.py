"""Authorization paths — hops, bridges, and the routes into a resource."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grantline.graph import build  # noqa: E402
from grantline.model import Grant  # noqa: E402


def _g(subject, resource, priv="X", system="postgres"):
    return Grant(system, subject, resource, priv)


def test_role_resource_becomes_a_hop_node():
    """`role:X` collapses into node X when X itself grants something onward."""
    g = build({
        _g("alice", "role:reader", "MEMBER"),
        _g("reader", "table:t", "SELECT"),
    })
    assert g.principals == {"alice"}
    assert g.hops == {"reader"}
    assert g.terminals == {"table:t"}
    assert [(e.src, e.dst) for e in g.edges if e.dst == "reader"] == [("alice", "reader")]


def test_role_without_onward_grants_stays_a_terminal():
    """A role nobody grants *from* is a dead end, not a hop — don't invent structure."""
    g = build({_g("alice", "role:unused", "MEMBER")})
    assert g.terminals == {"role:unused"} and g.hops == set()


def test_paths_show_every_route_not_just_the_holder():
    """The point of the graph: two people reach one table through different roles."""
    g = build({
        _g("alice", "role:reader", "MEMBER"), _g("reader", "table:t", "SELECT"),
        _g("bob", "role:admin", "MEMBER"), _g("admin", "table:t", "ALL"),
    })
    routes = {tuple(p) for p in g.paths_to("table:t")}
    assert routes == {("alice", "reader", "table:t"), ("bob", "admin", "table:t")}


def test_privs_are_merged_per_edge():
    g = build({_g("a", "table:t", "SELECT"), _g("a", "table:t", "INSERT")})
    assert g.edges[0].privs == {"SELECT", "INSERT"}


def test_bridge_is_declared_because_no_grant_table_records_it():
    """A cross-system hop (extension -> server-held key) cannot be discovered."""
    g = build(
        {_g("carol", "role:duckdb", "MEMBER")},
        bridges=[{"from": "duckdb", "to": "svc-reader", "system": "s3",
                  "note": "server-held key"}],
    )
    bridge = [e for e in g.edges if e.kind == "bridge"][0]
    assert (bridge.src, bridge.dst) == ("duckdb", "svc-reader")
    assert bridge.label == "server-held key"
    # carol reaches a storage identity she was never granted directly
    assert ("carol", "duckdb", "svc-reader") in {tuple(p) for p in g.paths_to("svc-reader")}


def test_cycles_do_not_hang():
    g = build({_g("a", "role:b", "M"), _g("b", "role:a", "M")})
    assert g.depth("a") >= 0 and g.paths_to("a") is not None


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
    print("all tests passed")


# ── node kinds and S3 routes ─────────────────────────────────────────────
# The adapters say account/role/group/policy; the config says which accounts are
# services; the map colours by the result and draws an S3 identity through its
# group and policy instead of flat onto the bucket.
if True:
    g = build(
        {_g("researcher_b", "role:analytics_reader", "MEMBER"), _g("analytics_reader", "table:t", "SELECT"),
         _g("svc-ray", "table:t", "SELECT"),
         Grant("s3", "researcher_b", "bucket:projects/research", "Read", "policy"),
         Grant("s3", "loner", "bucket:temp", "Read", "native")},
        kinds={"researcher_b": "account", "svc-ray": "account", "analytics_reader": "role",
               "group:research": "group", "policy:team-research": "policy", "loner": "account"},
        routes=[("s3", "researcher_b", "group:research", "member"),
                ("s3", "group:research", "policy:team-research", "attaches"),
                ("s3", "policy:team-research", "bucket:projects/research", "allows")],
        services=("svc-*",))
    assert g.kind_of("researcher_b") == "human" and g.kind_of("svc-ray") == "svc-account"
    assert g.kind_of("analytics_reader") == "role"
    assert g.kind_of("group:research") == "group" and g.kind_of("policy:team-research") == "policy"
    assert g.kind_of("loner") == "human", "native-action identity is still an account"
    routes = g.routes_from("researcher_b")
    assert ["researcher_b", "group:research", "policy:team-research", "bucket:projects/research"] in routes, routes
    flat = [e for e in g.edges if e.src == "researcher_b" and e.dst == "bucket:projects/research"]
    assert flat and flat[0].kind == "flat", "policy-routed identity keeps its grade as a flat edge, never drawn"
    print("ok node kinds + s3 routes")


# ── names ────────────────────────────────────────────────────────────────
g = build({_g("researcher_b", "table:t", "SELECT")}, kinds={"researcher_b": "account"}, names={"researcher_b": "Example Researcher", "ghost": ""})
assert g.label("researcher_b") == "researcher_b (Example Researcher)" and g.label("ghost") == "ghost" and g.label("nobody") == "nobody"
print("ok names")


# ── a declared actor is a service; the login it uses is a service account ──
g = build({_g("svc-airflow", "table:t", "SELECT")},
          bridges=[{"from": "airflow-dags", "to": "svc-airflow", "system": "postgres"}],
          kinds={"svc-airflow": "account"}, services=("svc-*", "airflow*"))
assert g.kind_of("airflow-dags") == "service" and g.kind_of("svc-airflow") == "svc-account"
print("ok service vs service account")


# ── environments ─────────────────────────────────────────────────────────
g = build({Grant("postgres-staging", "a", "table:t", "SELECT"), Grant("s3", "a", "bucket:b", "Read")},
          envs={"s3": ("prod", "staging")})
assert g.env_of("s3") == ("prod", "staging") and g.env_of("postgres-staging") == ("staging",) and g.env_of("postgres") == ("prod",)
print("ok environments")

# ── F6 on the map ────────────────────────────────────────────────────────
# 지도가 첫 화면이 되면서 이 경로를 훨씬 자주 밟는다. 시스템 하나가 죽으면 그 쪽으로
# 가는 선이 하나도 안 그려지는데, 그건 「아무도 못 닿는다」와 화면상 구별이 안 된다.
# 이름과 이유를 데이터에 실어 지도가 말하게 한다 — 그리고 나머지는 그대로 그린다.
from grantline import cli, web  # noqa: E402


class _Dead:
    def observe(self):
        raise RuntimeError("connection refused")


class _Live:
    def observe(self):
        return {Grant("postgres", "researcher_a", "role:analytics_reader", "MEMBER"),
                Grant("postgres", "analytics_reader", "db:analytics", "CONNECT")}, [], []


class _NoIntent:
    grants, managed, managed_systems, naming_synonyms = set(), set(), set(), []


out = cli._observe_and_plan(_NoIntent(), {"postgres": _Live(), "clickhouse": _Dead()})
data = web.graph_data(build(out[0]), out[5])
assert [b["system"] for b in data["blind"]] == ["clickhouse"], data["blind"]
assert "connection refused" in data["blind"][0]["note"]
assert data["nodes"], "죽은 어댑터가 나머지 지도까지 지우면 안 된다"
assert not web.graph_data(build(out[0]))["blind"], "못 읽은 것이 없으면 아무 말도 안 한다"
print("ok the map names what it could not read")
