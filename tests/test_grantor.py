"""Grantor — PRD 003 F1's known gap.

Three claims: (1) grantor is metadata, never identity — the same grant with a different
grantor is the same grant; (2) it survives a snapshot round-trip; (3) the subject page
shows it only when the source said it, and answers "what did I grant" from the grantor's
own page.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline import snapshot
from grantline.adapters import FixtureAdapter
from grantline.graph import build
from grantline.model import Grant
from grantline.pages import render_subject

# 1. metadata, not identity
a = Grant("postgres", "alice", "role:analyst_read", "MEMBER", grantor="dba")
b = Grant("postgres", "alice", "role:analyst_read", "MEMBER")
assert a == b and hash(a) == hash(b), "grantor must not take part in equality"
assert Grant("postgres", "x", "db:y", "CONNECT").grantor is None

# 2. snapshot round-trip
with tempfile.TemporaryDirectory() as d:
    snapshot.write(d, {a, Grant("clickhouse", "researcher_c", "db:product", "SELECT")}, [], ["postgres", "clickhouse"])
    loaded = snapshot.load(snapshot.latest(d))
    back = {(g.system, g.subject, g.resource, g.priv): g.grantor for g in loaded.grants}
    assert back[("postgres", "alice", "role:analyst_read", "MEMBER")] == "dba"
    assert back[("clickhouse", "researcher_c", "db:product", "SELECT")] is None

# 3. pages
G = [
    Grant("postgres", "researcher_a", "role:analytics_reader", "MEMBER", grantor="dba"),
    Grant("postgres", "analytics_reader", "table:analytics.public.vitals", "SELECT", grantor="dba"),
    Grant("clickhouse", "researcher_a", "db:product", "SELECT"),  # source knows no grantor
]
graph = build(set(G), [])
page = render_subject(set(G), graph, "researcher_a")
assert "granted by" in page and ">dba<" in page, "column shown when a row has a grantor"
dba = render_subject(set(G), graph, "dba")
assert "Granted by dba" in dba and "role:analytics_reader" in dba, "what did I grant"
only_ch = {Grant("clickhouse", "researcher_a", "db:product", "SELECT")}
assert "granted by" not in render_subject(only_ch, build(only_ch, []), "researcher_a"), \
    "no column when no source said who — blanks would imply nobody"

# 4. fixture loader carries it
from grantline.adapters import postgres as _pg

fx = FixtureAdapter("postgres", Path(__file__).resolve().parent.parent / "examples/fixtures/postgres.json", (_pg.grant_cmd, _pg.revoke_cmd))
grants, _, _ = fx.observe()
assert any(g.grantor == "dba" for g in grants)
print("ok")
