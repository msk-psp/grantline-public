"""Code proposal boundary: identity, approval, immutable plan and URL allowlist."""
import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from grantline import web
from grantline.act import ActError, Proposal
from grantline.adapters import Adapter
from grantline.approvals import Approvals
from grantline.model import Grant
from grantline.pages import render_approve

plan = {"base_commit": "a" * 40, "patch_sha256": "b" * 64, "summary": "Read demo/team only"}
calls = []
response_url = "https://github.com/demo/access/pull/12"
changed = False

def writer(command, **kwargs):
    assert command == ["/trusted/writer"] and "shell" not in kwargs
    payload = json.loads(kwargs["input"])
    calls.append(payload)
    data = dict(plan)
    if changed:
        data["patch_sha256"] = "c" * 64
    if payload["operation"] == "submit":
        assert payload["expected_plan"] == plan
        data["pr_url"] = response_url
    return SimpleNamespace(stdout=json.dumps(data))

def denied(fn):
    try:
        fn()
        raise AssertionError("must refuse")
    except ActError:
        pass

with tempfile.TemporaryDirectory() as directory, patch("grantline.code_writer.subprocess.run", writer):
    cfg = {"store": "approvals", "admin": ["U_REVIEWER"],
           "identities": {"requester": "U_REQUESTER", "reviewer": "U_REVIEWER"},
           "code_writer": {"command": ["/trusted/writer"], "repository": "demo/access", "systems": ["s3"]}}
    ap = Approvals(cfg, Path(directory))
    prop = Proposal("grant", Grant("s3", "demo-user", "bucket:demo/team", "Read"), "preview", False, "readonly")
    denied(lambda: ap.create(prop, requester="unknown"))
    denied(lambda: ap.create(prop, requester="reviewer"))
    req = ap.create(prop, requester="requester")
    assert req.code_plan == plan and req.requester == "U_REQUESTER"
    denied(lambda: ap.submit(req))
    denied(lambda: ap.decide(req.id, req.required["U_REVIEWER"], True, actor="requester"))
    denied(lambda: ap.decide(req.id, req.required["U_REVIEWER"], True))
    req, _ = ap.decide(req.id, req.required["U_REVIEWER"], True, actor="reviewer")
    changed = True
    denied(lambda: ap.submit(req))
    assert not any(c["operation"] == "submit" for c in calls)
    changed = False
    response_url = "https://github.com/other/access/pull/12"
    denied(lambda: ap.submit(req))
    response_url = "https://github.com/demo/access/pull/12"
    req = ap.submit(req)
    assert req.status == "proposed" and req.pr_url == response_url
    previous = len(calls)
    assert ap.submit(req).status == "proposed" and len(calls) == previous
    denied(lambda: ap.decide(req.id, req.required["U_REVIEWER"], True, actor="reviewer"))
    html = render_approve(req, "U_REVIEWER")
    assert "View permission PR" in html and "Approval creates a PR" in html
print("ok code writer approval boundary")

class ReadOnly(Adapter):
    privs = ("Read",)
    def grant_cmd(self, grant): return "READ ONLY PREVIEW"
    def apply(self, change): raise AssertionError("must never apply native permissions")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args): return None

with tempfile.TemporaryDirectory() as directory, patch("grantline.code_writer.subprocess.run", writer):
    ap = Approvals(cfg, Path(directory))
    servers = []
    original = web.HTTPServer
    def capture(addr, handler):
        server = original(("127.0.0.1", 0), handler)
        servers.append(server)
        return server
    with patch.object(web, "HTTPServer", capture), patch("grantline.slack.post", return_value=None):
        thread = threading.Thread(target=web.serve, args=(lambda: (set(), [], []), 0), daemon=True,
            kwargs={"adapters": {"s3": ReadOnly()}, "approvals": ap,
                    "auth": {"mode": "proxy"}})
        thread.start()
        deadline = time.monotonic() + 3
        while not servers and time.monotonic() < deadline: time.sleep(.01)
        server = servers[0]
        url = f"http://127.0.0.1:{server.server_port}"
        opener = urllib.request.build_opener(NoRedirect)
        def post(path, actor, fields):
            req = urllib.request.Request(url + path, data=urllib.parse.urlencode(fields).encode(),
                headers={"Origin": url, "X-Forwarded-Email": actor})
            try:
                with opener.open(req, timeout=3) as response: return response.status
            except urllib.error.HTTPError as exc: return exc.code
        try:
            assert post("/request", "requester", {"action":"grant", "system":"s3", "subject":"demo-user",
                "resource":"bucket:demo/team", "priv":"Read", "cmd":"READ ONLY PREVIEW"}) == 303
            req = ap.all()[0]
            fields = {"t":req.required["U_REVIEWER"], "decision":"approve"}
            assert post("/approve/" + req.id, "requester", fields) == 409
            assert post("/approve/" + req.id, "reviewer", fields) == 303
            assert ap.load(req.id).status == "proposed"
        finally:
            server.shutdown(); thread.join(timeout=3); server.server_close()
print("ok authenticated web approval creates PR without native writes")
