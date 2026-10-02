"""Proxy login boundary, safe redirects and per-request identity isolation.

Synthetic proxy headers are used only against a loopback test server. No OIDC provider is called.
"""
import http.client
import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline import pages, web
from grantline.auth import current, local_path, proxy_config, proxy_target, proxy_user
from grantline.model import Grant

for value in ("https://evil.example", "//evil.example", "/%2f%2fevil.example", "/%5cevil", "/bad%0d%0aLocation:evil", "javascript:alert(1)"):
    assert local_path(value) == "/", value
assert local_path("/s/alice?view=routes") == "/s/alice?view=routes"
assert proxy_target("/oauth2/start?provider=demo&rd=evil", "//evil.example") == "/oauth2/start?provider=demo&rd=%2F"
for cfg in ({}, {"mode": "unsupported"}, {"mode": "proxy", "identity_header": "Host"},
            {"mode": "proxy", "login_url": "//evil.example"}, {"mode": "proxy", "login_url": ""}):
    try: proxy_config(cfg); assert False, cfg
    except ValueError: pass
cfg = proxy_config({"mode": "proxy", "identity_header": "X-Auth-Request-Email"})
headers = Message(); headers["X-Auth-Request-Email"] = "alice@example.com"
assert proxy_user(headers, None) == "", "local mode ignores injected identity headers"
headers["X-Auth-Request-Email"] = "bob@example.com"
assert proxy_user(headers, cfg) == "", "ambiguous identity headers must be refused"
assert "Explore the console" in pages.render_login(None)
token = current.set({"enabled": True, "user": '<img src=x onerror="bad()">', "logout": "/oauth2/sign_out"})
try:
    assert "<img" not in pages.render_login(cfg)
finally:
    current.reset(token)

servers = []
real_server = web.HTTPServer
def capture(addr, handler):
    server = real_server(("127.0.0.1", 0), handler); servers.append(server); return server
previous = pages.APPROVALS_ENABLED, pages.WRITE_READY
with patch.object(web, "HTTPServer", capture):
    grants = {Grant("s3", "private-account", "bucket:private", "Read")}
    thread = threading.Thread(target=web.serve, args=(lambda: (grants, [], []), 0), kwargs={"auth": cfg}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 3
    while not servers and time.monotonic() < deadline: time.sleep(.01)
    assert servers
    server = servers[0]; url = f"http://127.0.0.1:{server.server_port}"
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    opener = urllib.request.build_opener(NoRedirect)
    def get(path, email=None, post=False):
        headers = {"Origin": url}
        if email is not None: headers["X-Auth-Request-Email"] = email
        req = urllib.request.Request(url + path, headers=headers, data=b"action=grant" if post else None)
        try:
            with opener.open(req, timeout=3) as response: return response.status, response.headers, response.read().decode()
        except urllib.error.HTTPError as exc: return exc.code, exc.headers, exc.read().decode()
    try:
        code, headers, body = get("/services?view=demo")
        assert code == 303 and headers["Location"] == "/login?next=%2Fservices%3Fview%3Ddemo"
        assert "private-account" not in body
        code, headers, body = get("/api/graph.json")
        assert code == 401 and headers["Content-Type"] == "application/json"
        assert json.loads(body)["login"].startswith("/login?") and "private-account" not in body
        assert get("/act", post=True)[0] == 401
        code, _, body = get("/login?next=%2Fmatrix")
        assert code == 200 and "Continue with SSO" in body and "rd=%2Fmatrix" in body
        assert "rd=%2F" in get("/login?next=https%3A%2F%2Fevil.example")[2]
        assert get("/static/console.js")[0] == 200
        code, _, body = get("/services", "alice@example.com")
        assert code == 200 and "private-account" in body and "alice@example.com" in body
        assert "alice@example.com" not in get("/login")[2], "identity must not leak into the next request"
        assert "bob@example.com" in get("/services", "bob@example.com")[2]
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.putrequest("GET", "/api/graph.json")
        connection.putheader("X-Auth-Request-Email", "alice@example.com")
        connection.putheader("X-Auth-Request-Email", "bob@example.com")
        connection.endheaders(); response = connection.getresponse()
        assert response.status == 401
        response.read(); connection.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
        pages.APPROVALS_ENABLED, pages.WRITE_READY = previous

print("ok proxy sign-in boundaries, safe return URLs, API expiry and request identity isolation")
