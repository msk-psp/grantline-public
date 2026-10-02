"""Public-release regressions: approval boundaries, SQL input, policy scope and safe failure.

All writes are spies or temporary files; no live service or Slack call is made.
"""
import json
import stat
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

from grantline import audit, pages, web
from grantline.act import ActError, propose
from grantline.adapters import Adapter, clickhouse, postgres
from grantline.adapters.s3 import S3ConfigAdapter, _Plane, effective_grants, policy_with
from grantline.approvals import Approvals
from grantline.model import Grant


class Spy(Adapter):
    system = "postgres"
    cfg = {}
    privs = ("SELECT",)

    def __init__(self): self.calls = []
    def write_ready(self): return True, "mock only"
    def grant_cmd(self, g): return "MOCK GRANT " + g.subject
    def revoke_cmd(self, g): return "MOCK REVOKE " + g.subject
    def apply(self, change): self.calls.append(change.cmd)


with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    spy = Spy()
    ap = Approvals({"admin": ["reviewer-a", "reviewer-b"]}, base)
    prop = propose("grant", "postgres", "target", "db:demo", "SELECT", set(), {"postgres": spy})
    req = ap.create(prop)
    assert stat.S_IMODE(ap.store.stat().st_mode) == 0o700
    assert stat.S_IMODE(ap._path(req.id).stat().st_mode) == 0o600
    for rid in ("../outside", "a/b", "", req.id + "/x"):
        try: ap.load(rid); assert False, rid
        except ActError: pass
    deliveries = []
    def deliver(cfg, who, text): deliveries.append((cfg, who, text)); return "sent"
    ap.slack_cfg = {"redirect_to": "pilot"}
    with patch("grantline.slack.post", deliver):
        status = ap.notify(req)
    assert len(deliveries) == 2 and all("redirect_to" not in cfg for cfg, _, _ in deliveries)
    rendered = pages.render_requested(req, status)
    assert all(token not in rendered for token in req.required.values())
    assert all(req.required[who] in text for _, who, text in deliveries)
    assert "<img" not in pages.render_act({}, set(), {}, done='<img src=x onerror="bad()">')
    assert audit.record(str(base / "missing/audit.jsonl"), "mock", "grant", "cmd", lambda: spy.calls.append("bad"))
    assert spy.calls == [], "an unavailable audit sink must prevent mutation"
    assert audit.record(str(base / "audit.jsonl"), "mock", "grant", "cmd", lambda: spy.calls.append("logged")) is None
    records = [json.loads(line) for line in (base / "audit.jsonl").read_text().splitlines()]
    assert records[0]["phase"] == "attempt" and records[1]["ok"]
    spy.calls.clear()

    servers = []
    real_server = web.HTTPServer
    def capture(addr, handler):
        s = real_server(("127.0.0.1", 0), handler); servers.append(s); return s
    with patch.object(web, "HTTPServer", capture):
        thread = threading.Thread(target=web.serve, args=(lambda: (set(), [], []), 0),
                                  kwargs={"adapters": {"postgres": spy}, "audit_path": str(base / "audit.jsonl"),
                                          "approvals": ap}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 3
        while not servers and time.monotonic() < deadline: time.sleep(.01)
        assert servers, "server did not start"
        server = servers[0]
        url = f"http://127.0.0.1:{server.server_port}"
        fields = dict(action="grant", system="postgres", subject="target", resource="db:demo", priv="SELECT", cmd=prop.cmd)
        def post(path, data, origin=None, **headers):
            request = urllib.request.Request(url + path, data=urllib.parse.urlencode(data).encode(),
                                             headers={"Origin": origin or url, **headers})
            try:
                with urllib.request.urlopen(request, timeout=3) as response: return response.status, response.read().decode()
            except urllib.error.HTTPError as exc: return exc.code, exc.read().decode()
        try:
            assert post("/request", fields, origin="https://attacker.example")[0] == 403
            assert post("/request", fields, Host="attacker.example")[0] == 403
            assert post("/request", dict(fields, cmd="stale preview"))[0] == 409
            code, body = post("/request", fields)
            assert code == 200
            request = max(ap.all(), key=lambda r: r.ts)
            assert all(token not in body for token in request.required.values())
            assert post("/act", fields)[0] == 403 and spy.calls == []
            for who, token in request.required.items():
                assert post("/approve/" + request.id, dict(t=token, decision="approve"))[0] == 200
            assert ap.load(request.id).status == "executed" and spy.calls == [prop.cmd]
            assert post("/approve/" + request.id, dict(t=token, decision="approve"))[0] == 409
            assert post("/request", fields, **{"Content-Length": "65537"})[0] == 413
            assert post("/request", fields, **{"Content-Length": "invalid"})[0] == 400
            ap.enabled = False
            pages.APPROVALS_ENABLED = False
            assert post("/act", {k: v for k, v in fields.items() if k != "cmd"})[0] == 409
            assert len(spy.calls) == 1
            assert post("/act", fields)[0] == 200 and len(spy.calls) == 2
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)
            pages.APPROVALS_ENABLED = False

# SQL delimiters stay inside quoted identifiers; injected privileges are rejected.
for mod, quote in ((postgres, '"'), (clickhouse, "`")):
    name = f"role{quote}; SELECT 1; --"
    cmd = mod.grant_cmd(Grant("mock", "user", "role:" + name, "MEMBER"))
    assert mod._ident(name) in cmd
    for verb in (mod.grant_cmd, mod.revoke_cmd):
        try: verb(Grant("mock", "user", "db:demo", "SELECT; DROP TABLE x")); assert False
        except ValueError: pass
        try: verb(Grant("mock", "user\nSELECT 1", "db:demo", "ALL")); assert False
        except ValueError: pass
assert "\\\\" in clickhouse._ident("a\\b") and "\\`" in clickhouse._ident("a`b")
assert postgres.grant_cmd(Grant("postgres", "PUBLIC", "db:demo", "CONNECT")).endswith("TO PUBLIC;")
assert '"x""; SELECT 1; --"' in postgres.grant_cmd(Grant("postgres", "user", 'db:x"; SELECT 1; --', "CONNECT"))

# Revoke exactly one resource while retaining the other resources and conditions.
policy = {"Statement": [{"Sid": "shared", "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
                          "Resource": ["arn:aws:s3:::first/*", "arn:aws:s3:::second/*"],
                          "Condition": {"StringEquals": {"test": "demo"}}}]}
result = policy_with(policy, Grant("s3", "user", "bucket:first", "Read"), False)
assert policy["Statement"][0]["Action"] == ["s3:GetObject", "s3:PutObject"]
assert any(st["Resource"] == ["arn:aws:s3:::second/*"] and st["Action"] == ["s3:GetObject", "s3:PutObject"] for st in result["Statement"])
assert any(st["Resource"] == ["arn:aws:s3:::first/*"] and st["Action"] == ["s3:PutObject"] for st in result["Statement"])
assert all(st["Condition"] == policy["Statement"][0]["Condition"] for st in result["Statement"])
try:
    policy_with({"Statement": [{"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "*"}]},
                Grant("s3", "user", "bucket:first", "Read"), False)
    assert False, "unsupported statement must not be normalized into a damaged policy"
except ValueError: pass
conditional = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::first/*"], "Condition": {"test": True}}]}
added = policy_with(conditional, Grant("s3", "user", "bucket:first", "Write"), True)
assert len(added["Statement"]) == 2 and "Condition" not in added["Statement"][1]

for extra in ({"Condition": {"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}}},
              {"NotResource": "arn:aws:s3:::demo/private/*"}, {"Action": "s3:Get*"},
              {"Resource": "arn:aws:s3:::demo/a*b/*"}, {"Action": "s3:UnrecognizedAction"}):
    st = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::demo/*", **extra}
    grants, findings = effective_grants({"identities": [{"name": "user", "policy": {"Statement": [st]}}]})
    assert not grants and any(f.title == "policy evaluation incomplete" for f in findings)
doc = {"identities": [{"name": "user", "policy": {"Statement": [
    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::demo/*"},
    {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::demo/private/*"}]}}]}
assert not effective_grants(doc)[0]
ad = S3ConfigAdapter({"enforced": "demo", "planes": {"demo": {"file": "unused"}}})
with patch.object(ad.planes["demo"], "read", return_value=doc):
    grants, findings, unobserved = ad.observe()
    assert not grants and unobserved and not ad.routes

# Failed reads never overwrite identity credentials; only a confirmed 404 creates.
plane = _Plane("demo", {"filer_url_env": "READ", "admin_filer_url_env": "WRITE"})
with patch.dict("os.environ", {"WRITE": "http://filer.example"}):
    for error in (TimeoutError("read timed out"), urllib.error.HTTPError("mock", 403, "denied", {}, None), ValueError("bad JSON")):
        with patch.object(plane, "_filer_get", side_effect=error), patch("urllib.request.urlopen") as put:
            try: plane.write_identity({"name": "user", "actions": []}); assert False
            except type(error): pass
            put.assert_not_called()
    with patch.object(plane, "_filer_get", return_value=b'{"name":"user","credentials":[{"access_key":"test","secret_key":"mock"}]}'), patch("urllib.request.urlopen") as put:
        plane.write_identity({"name": "user", "actions": ["Read:demo"]})
        assert json.loads(put.call_args.args[0].data)["credentials"][0]["secret_key"] == "mock"
    with patch.object(plane, "_filer_get", side_effect=urllib.error.HTTPError("mock", 404, "missing", {}, None)), patch("urllib.request.urlopen") as put:
        plane.write_identity({"name": "new-user", "actions": []})
        assert json.loads(put.call_args.args[0].data)["name"] == "new-user"
    with patch("urllib.request.urlopen") as put:
        try: plane.write_identity({"name": "../outside", "actions": []}); assert False
        except ValueError: pass
        put.assert_not_called()

print("ok public security boundaries (mock writes only)")
