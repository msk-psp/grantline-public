"""PRD gaps: no silent route caps, identity-scoped unknowns, nonblocking refresh/login checks."""
import json
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline import snapshot, web
from grantline.adapters.clickhouse import ClickHouseAdapter
from grantline.adapters.postgres import PostgresAdapter
from grantline.adapters.s3 import S3ConfigAdapter, _MemTree, _policy_scopes, merge_iam_tree
from grantline.graph import build
from grantline.model import Grant
from grantline.pages import render_subject

# The default used to silently hide the 201st route (and reverse routes after 40).
grants = {Grant("postgres", "person", f"role:r{i}", "MEMBER") for i in range(205)}
grants |= {Grant("postgres", f"r{i}", "table:db.public.shared", "SELECT") for i in range(205)}
graph = build(grants)
assert len(graph.routes_from("person")) == len(graph.paths_to("table:db.public.shared")) == 205
assert len(graph.routes_from("person", limit=3)) == 3
page = render_subject(grants, graph, "person")
assert all(f'/s/r{i}"' in page for i in range(205))

# A conditional policy cannot be evaluated, but a healthy user is still known.
statement = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::demo/*"}
doc = {"identities": [
    {"name": "unread", "policy": {"Statement": [{**statement, "Condition": {"test": True}}]}},
    {"name": "healthy", "actions": ["Read:demo"]}],
    "_routes": [("unread", "bucket:demo", "allows"), ("healthy", "bucket:demo", "allows")]}
adapter = S3ConfigAdapter({"enforced": "main", "planes": {"main": {"file": "unused"}}})
with patch.object(adapter.planes["main"], "read", return_value=doc):
    observed, findings, unknown = adapter.observe()
assert observed == {Grant("s3", "healthy", "bucket:demo", "Read")}
assert unknown[0].covers(Grant("s3", "unread", "bucket:demo", "Read"))
assert not unknown[0].covers(next(iter(observed)))
assert not unknown[0].covers(Grant("s3", "unread", "bucket:demo-other", "Read"))
assert not unknown[0].covers(Grant("s3", "unread", "bucket:other", "Read"))
assert [r[1] for r in adapter.routes] == ["healthy"]
assert "unknown: s3" in render_subject(observed, build(observed), "unread", unknown)
assert "unknown: s3" not in render_subject(observed, build(observed), "healthy", unknown)
assert 'class="blind"' in web.render(observed, [], findings, unobserved=unknown)
assert "unread:" in web.graph_data(build(observed), unknown)["blind"][0]["note"]

assert _policy_scopes({"Statement": [{**statement, "NotResource": "arn:aws:s3:::private/*"}]}) == ("bucket:",)
assert _policy_scopes({"Statement": [{**statement, "Resource": "arn:aws:s3:::demo-*/x"}]}) == ("bucket:",)

# Missing shared policies identify exactly the group's members.
tree = _MemTree()
tree.files["identities"] = {n: {"name": n, "actions": ["Read:demo"]} for n in ("unread", "healthy")}
tree.files["groups"]["team"] = {"name": "team", "members": ["unread"], "policy_names": ["missing"]}
with patch.object(adapter.planes["main"], "read", return_value=merge_iam_tree(tree)):
    observed, _, unknown = adapter.observe()
assert observed == {Grant("s3", "healthy", "bucket:demo", "Read")}
assert unknown[0].subjects == ("unread",)
with tempfile.TemporaryDirectory() as directory:
    saved = snapshot.write(directory, observed, unknown, {"s3"})
    restored = snapshot.load(saved.path)
    assert restored.unobserved == tuple(unknown)
    assert not restored.blind_to(next(iter(observed)))
    # Legacy scope records without subjects still cover the entire scope.
    text = saved.path.read_text()
    lines = [json.loads(line) for line in text.splitlines()]
    for line in lines:
        if "unobserved" in line:
            line["unobserved"].pop("subjects")
    saved.path.write_text("\n".join(json.dumps(line) for line in lines))
    assert snapshot.load(saved.path).blind_to(next(iter(observed)))

# Cached readers must not wait for a refresh, and failed refreshes cannot destroy data.
entered, release = threading.Event(), threading.Event()
calls = []
def read():
    calls.append(1)
    if len(calls) > 1:
        entered.set()
        assert release.wait(2)
    return len(calls)
cache = web._ObservationCache(read)
assert cache.get() == 1
worker = threading.Thread(target=lambda: cache.get(fresh=True))
worker.start()
assert entered.wait(2)
try:
    assert cache.get() == 1
finally:
    release.set(); worker.join(2)
assert not worker.is_alive() and cache.get() == 2
with patch.object(cache, "read", side_effect=RuntimeError("temporary failure")):
    try: cache.get(fresh=True); assert False
    except RuntimeError: pass
assert cache.get() == 2
cache.clear()
assert cache.get() == 3

# Explicit login credentials verify identity; observer credentials never substitute.
class Connection:
    def __init__(self, user): self.user = user
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def execute(self, query, params=()):
        self.row = (self.user, self.user) if query == "SELECT session_user, current_user" else (True,)
        return self
    def fetchone(self): return self.row
pg = PostgresAdapter({"probe_dsn_envs": {"alice": "ALICE_DSN"}})
g = {Grant("postgres", "alice", "db:demo", "CONNECT")}
with patch.object(pg, "_connect", return_value=Connection("alice")) as connect:
    result = pg.probe(g)
    assert result[0].verdict == "allow" and "subject TCP login" in result[0].how
    connect.assert_called_once_with(dbname="demo", subject="alice")
with patch.object(pg, "_connect", return_value=Connection("observer")):
    assert pg.probe(g)[0].verdict == "unknown"
with patch.object(pg, "_connect", side_effect=ValueError("secret DSN")):
    result = pg.probe(g)[0]
    assert result.verdict == "unknown" and "secret DSN" not in result.how
ch = ClickHouseAdapter({"probe_url_envs": {"alice": "ALICE_URL"}})
g = {Grant("clickhouse", "alice", "db:demo", "SELECT")}
with patch.object(ClickHouseAdapter, "_query", side_effect=[[["alice"]], [["GRANT SELECT ON demo.* TO alice"]]]) as query:
    result = ch.probe(g)
    assert result[0].verdict == "allow" and "subject HTTP login" in result[0].how
    assert query.call_args_list[1].args[0] == "SHOW GRANTS WITH IMPLICIT FINAL"
with patch.object(ClickHouseAdapter, "_query", return_value=[["observer"]]) as query:
    assert ch.probe(g)[0].verdict == "unknown" and query.call_count == 1
print("ok PRD gaps (205 routes, isolated unknowns, snapshot compatibility, cache refresh, login identity)")

# Missing subject credentials are unknown, not an uncaught SystemExit or observer fallback.
with patch.dict("os.environ", {}, clear=True):
    assert ch.probe(g)[0].verdict == "unknown"
with patch.object(pg, "_connect", side_effect=SystemExit("missing subject environment")):
    assert pg.probe({Grant("postgres", "alice", "db:demo", "CONNECT")})[0].verdict == "unknown"

# The actual periodic loop must refresh without blocking cached HTTP reads.
import urllib.request

servers = []
second, finish = threading.Event(), threading.Event()
counter = [0]
real_server = web.HTTPServer
def capture(address, handler):
    server = real_server(("127.0.0.1", 0), handler)
    servers.append(server)
    return server
def observation():
    counter[0] += 1
    if counter[0] == 2:
        second.set()
        assert finish.wait(3)
    return {Grant("postgres", "alice", f"db:run{counter[0]}", "CONNECT")}, [], []
with patch.object(web, "HTTPServer", capture):
    server_thread = threading.Thread(target=web.serve, args=(observation, 0), kwargs={"ttl_s": 0.02})
    server_thread.start()
    try:
        assert second.wait(2), "observation was not refreshed automatically"
        url = f"http://127.0.0.1:{servers[0].server_port}/api/resources.json?instance=postgres"
        with urllib.request.urlopen(url, timeout=1) as response:
            assert "db:run1" in response.read().decode(), "read must use the completed observation"
    finally:
        finish.set()
        if servers: servers[0].shutdown()
        server_thread.join(3)
assert not server_thread.is_alive()
print("ok periodic HTTP refresh and missing-login handling")
