"""Lost accounts, misleading empty states, silent form resets and POST replay regressions.

HTTP writes below use a spy and temporary approval files; no service or Slack calls.
"""
import datetime
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from types import SimpleNamespace

from grantline import pages, web
from grantline.act import propose
from grantline.adapters import Adapter
from grantline.approvals import Approvals
from grantline.graph import build
from grantline.model import Finding, Grant, Unobserved
from grantline.snapshot import Snapshot, compare

grants = {Grant("s3", f"account{i}", "bucket:demo", "Read") for i in range(12)}
inventory = pages.render_inventory(grants)
assert '<details class="more-chips">' in inventory
assert all(f'href="/s/account{i}"' in inventory for i in range(12)), "+N must not discard accounts"
assert 'href="/s/alice%2Fops"' in web.render({Grant("s3", "alice/ops", "bucket:demo", "Read")}, [], [])
assert 'href="/g/s3/bucket%3Ademo"' in web.render(grants, [], [])
slash = {Grant("s3", "alice/ops", "bucket:demo", "Read")}
assert 'href="/s/alice%2Fops/probe"' in pages.render_subject(slash, build(slash, []), "alice/ops")
blind = Unobserved("s3", ("*",), "read timed out")
empty = pages.render_inventory(set(), unobserved=[blind])
assert "unknown access" in empty and "read timed out" in empty and "No observed grants" in empty
assert "convergence is unknown" in web.render(set(), [], [], unobserved=[blind])
assert "No grants were observed for this account" in pages.render_subject(set(), build(set(), []), "missing")
assert "<img" not in pages.render_error(404, '<img src=x onerror="alert(1)">')
assert 'name="subject" value="alice" autocomplete="off" required' in pages.render_act(
    {"subject": "alice"}, set(), {})

# Readable logs still include each change, escape service data, and retain unknown scopes.
before = Snapshot(Path("before"), datetime.datetime(2026, 10, 1, tzinfo=datetime.UTC), "demo",
                  frozenset({"s3"}), frozenset({Grant("s3", "old", "bucket:demo", "Read")}), ())
after = Snapshot(Path("after"), datetime.datetime(2026, 10, 2, tzinfo=datetime.UTC), "demo",
                 frozenset({"s3"}), frozenset({Grant("s3", "<new>", "bucket:demo/path", "Write")}), ())
log = pages._since_run(SimpleNamespace(comparison=compare(before, after)))
assert "+ Added" in log and "− Removed" in log and "bucket:demo/path" in log
assert "&lt;new&gt;" in log and "<new>" not in log and before.ts.isoformat() in log
findings = [Finding("s3", "drift", f"account{i} <review>") for i in range(5)]
details = web.render(grants, [], findings)
assert all(f"account{i} &lt;review&gt;" in details for i in range(5)), "collapsed findings must remain reachable"
assert "<review>" not in details


class Spy(Adapter):
    cfg = {}
    privs = ("SELECT",)
    def __init__(self): self.calls = []
    def write_ready(self): return True, "mock only"
    def grant_cmd(self, grant): return "MOCK GRANT " + grant.subject
    def revoke_cmd(self, grant): return "MOCK REVOKE " + grant.subject
    def apply(self, change): self.calls.append(change.cmd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


with tempfile.TemporaryDirectory() as td:
    spy = Spy()
    ap = Approvals({"admin": ["reviewer"]}, Path(td))
    previous = pages.APPROVALS_ENABLED, pages.WRITE_READY
    servers = []
    real_server = web.HTTPServer
    def capture(addr, handler):
        server = real_server(("127.0.0.1", 0), handler); servers.append(server); return server
    with patch.object(web, "HTTPServer", capture), patch("grantline.slack.post", return_value=None):
        thread = threading.Thread(target=web.serve, args=(lambda: (set(), [], []), 0),
                                  kwargs={"adapters": {"postgres": spy}, "approvals": ap,
                                          "audit_path": str(Path(td) / "audit.jsonl")}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 3
        while not servers and time.monotonic() < deadline: time.sleep(.01)
        assert servers
        server = servers[0]; url = f"http://127.0.0.1:{server.server_port}"
        opener = urllib.request.build_opener(NoRedirect)
        def request(path, fields=None):
            data = urllib.parse.urlencode(fields).encode() if fields is not None else None
            req = urllib.request.Request(url + path, data=data, headers={"Origin": url})
            try:
                with opener.open(req, timeout=3) as response:
                    return response.status, response.headers, response.read().decode()
            except urllib.error.HTTPError as exc:
                return exc.code, exc.headers, exc.read().decode()
        try:
            prop = propose("grant", "postgres", "alice", "db:demo", "SELECT", set(), {"postgres": spy})
            fields = dict(action="grant", system="postgres", subject="alice", resource="db:demo", priv="SELECT", cmd=prop.cmd)
            status, headers, _ = request("/request", fields)
            assert status == 303 and len(ap.all()) == 1 and spy.calls == []
            detail = headers["Location"]
            status, detail_headers, body = request(detail)
            req = ap.all()[0]
            assert status == 200 and "Viewing only" in body and "not delivered" in body
            assert detail_headers["Referrer-Policy"] == "strict-origin", "native POST needs Origin without leaking approval URLs"
            assert all(token not in body for token in req.required.values())
            request(detail)  # refresh the read-only landing page
            assert len(ap.all()) == 1 and spy.calls == []
            token = req.required["reviewer"]
            assert request(detail, dict(t=token, decision="invalid"))[0] == 400
            assert ap.load(req.id).status == "pending" and not ap.load(req.id).approved
            status, headers, _ = request(detail, dict(t=token, decision="approve"))
            assert status == 303 and spy.calls == [prop.cmd]
            assert request(headers["Location"])[0] == 200
            request(headers["Location"])
            assert spy.calls == [prop.cmd], "refresh must not execute the approved command again"
            ap.enabled = False; pages.APPROVALS_ENABLED = False
            assert request("/approve/missing")[0] == 404
            assert "Approvals are not enabled" in request("/request", fields)[2]
            status, headers, _ = request("/act", fields)
            assert status == 303 and headers["Location"] == "/s/alice"
            request(headers["Location"]); request(headers["Location"])
            assert len(spy.calls) == 2, "direct changes also land on a read-only page"
            status, _, body = request("/missing")
            assert status == 404 and "Return to the access map" in body
            with patch.object(pages, "render_inventory", side_effect=RuntimeError("private connection detail")):
                status, _, body = request("/services?refresh=1")
                assert status == 503 and "Service temporarily unavailable" in body
                assert "private connection detail" not in body and "Traceback" not in body
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)
            pages.APPROVALS_ENABLED, pages.WRITE_READY = previous

print("ok console workflows, accessible hidden accounts, unknown states and POST redirect boundaries")
