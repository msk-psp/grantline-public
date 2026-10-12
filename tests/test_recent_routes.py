"""Recent route filtering uses recorded grant deltas, not inferred creation dates."""
import datetime
import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grantline import snapshot, web
from grantline.graph import build
from grantline.model import Grant, Unobserved
from grantline.recent_routes import filter_recent, parse_days

now = datetime.datetime(2026, 10, 12, tzinfo=datetime.UTC)
member = Grant("pg", "alice", "role:reader", "MEMBER")
old = Grant("pg", "reader", "table:old", "SELECT")
new = Grant("pg", "reader", "table:new", "SELECT")
other = Grant("pg", "bob", "table:unrelated", "SELECT")
base = {member, old, other}
with tempfile.TemporaryDirectory() as directory:
    snapshot.write(directory, base, (), ["pg"], now - datetime.timedelta(days=10))
    current = base | {new}
    snapshot.write(directory, current, (), ["pg"], now - datetime.timedelta(days=2))
    result, info = filter_recent(build(current), current, (), directory, 7, now, ["pg"])
    assert {(e.src, e.dst) for e in result.edges} == {("alice", "reader"), ("reader", "table:new")}
    assert info["complete"] and info["added"] == 1 and info["removed"] == 0
    # A failed observation must not turn invisible access into deleted access.
    blind = (Unobserved("pg", ("",), "offline"),)
    _, info = filter_recent(build(set()), set(), blind, directory, 7, now, ["pg"])
    assert info["removed"] == 0
    result, info = filter_recent(build(base), base, (), directory, 7, now, ["pg"])
    assert not result.edges and info["removed"] == 1

with tempfile.TemporaryDirectory() as directory:
    current = base | {new}
    snapshot.write(directory, current, (), ["pg"], now - datetime.timedelta(days=2))
    result, info = filter_recent(build(current), current, (), directory, 7, now, ["pg"])
    assert not result.edges and not info["complete"]
    assert info["baseline"] == (now - datetime.timedelta(days=2)).isoformat()
    result, info = filter_recent(build(current), current, (), None, 7, now, ["pg"])
    assert not result.edges and info["baseline"] is None

for value in ("0", "-1", "1.5", "abc", "3651", "99999999999999999"):
    try:
        parse_days(value)
    except ValueError:
        pass
    else:
        raise AssertionError(value)
assert parse_days("7") == 7
print("recent route context, removals, incomplete history, visibility and validation passed")

# The resource drill-down and the rendered graph must use the same window.
with tempfile.TemporaryDirectory() as directory:
    live_now = datetime.datetime.now(datetime.UTC)
    snapshot.write(directory, base, (), ["pg"], live_now - datetime.timedelta(days=10))
    current = base | {new}
    recorder = snapshot.Recorder(directory)
    servers = []
    real_server = web.HTTPServer

    def capture(address, handler):
        server = real_server(("127.0.0.1", 0), handler)
        servers.append(server)
        return server

    with patch.object(web, "HTTPServer", capture):
        thread = threading.Thread(target=web.serve, args=(lambda: (current, [], []), 0),
                                  kwargs={"recorder": recorder}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 3
        while not servers and time.monotonic() < deadline:
            time.sleep(.01)
        assert servers
        server = servers[0]
        url = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(url + "/api/graph.json?days=7", timeout=3) as response:
                payload = json.load(response)
            assert payload["recent"]["complete"] and payload["recent"]["added"] == 1
            assert not any(n["id"] == "bob" for n in payload["nodes"])
            with urllib.request.urlopen(url + "/api/resources.json?instance=pg&days=7", timeout=3) as response:
                resources = json.load(response)
            assert [item["res"] for item in resources["items"]] == ["table:new"]
            with urllib.request.urlopen(url + "/api/graph.json", timeout=3) as response:
                assert any(n["id"] == "bob" for n in json.load(response)["nodes"])
            for endpoint in ("graph.json", "resources.json"):
                try:
                    urllib.request.urlopen(url + f"/api/{endpoint}?days=-1", timeout=3)
                except urllib.error.HTTPError as exc:
                    assert exc.code == 400 and "error" in json.load(exc)
                else:
                    raise AssertionError("invalid days accepted")
        finally:
            server.shutdown()
            thread.join(timeout=3)
print("graph and resources HTTP filters preserve default behavior and reject invalid windows")
