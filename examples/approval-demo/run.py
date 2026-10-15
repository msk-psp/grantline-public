#!/usr/bin/env python3
"""Loopback-only approval playground. Every identity, notification and PR is simulated."""
import argparse
import html
import http.client
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
ROLES = {"requester": "요청자", "reviewer": "승인자"}
PR_PREFIX = "https://github.com/example/approval-demo/pull/"
COOKIE = "grantline_demo_role"
SAMPLE = {"action": "grant", "system": "s3", "subject": "demo-user",
          "resource": "bucket:demo/team", "priv": "Read"}


def backend(state, port, public):
    from grantline import slack, web
    from grantline.adapters.s3 import S3ConfigAdapter
    from grantline.approvals import Approvals

    def notify(cfg, to, text):
        inbox = state / "inbox"
        inbox.mkdir(exist_ok=True)
        path = inbox / f"{time.time_ns()}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"to": to, "text": text}), encoding="utf-8")
        tmp.replace(path)
        return path.stem
    slack.post = notify
    identities = state / "iam" / "identities"
    identities.mkdir(parents=True)
    (identities / "demo-user.json").write_text(json.dumps(
        {"name": "demo-user", "credentials": [], "actions": ["Read:demo/reference"]}))
    adapter = S3ConfigAdapter({"enforced": "dynamic", "planes": {"dynamic": {"dir": str(state / "iam")}}})
    assert not adapter.write_ready()[0]
    ap = Approvals({"store": "approvals", "console_url": public, "admin": ["DEMO_REVIEWER"],
        "identities": {"requester": "DEMO_REQUESTER", "reviewer": "DEMO_REVIEWER"},
        "names": {"DEMO_REQUESTER": "가상 요청자", "DEMO_REVIEWER": "가상 승인자"},
        "code_writer": {"command": [sys.executable, str(Path(__file__).with_name("writer.py")), str(state)],
                        "repository": "example/approval-demo", "systems": ["s3"]}}, state, {"language": "ko"})
    def observe():
        grants, findings, blind = adapter.observe()
        return grants, [], findings, (), None, blind
    web.serve(observe, port, adapters={"s3": adapter}, approvals=ap, default_language="ko",
              auth={"mode": "proxy", "login_url": "/demo", "logout_url": "/demo/logout"})


def frontend(state, port, upstream):
    from grantline.auth import local_path
    e = html.escape

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def send(self, body, status=200, headers=()):
            raw = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "strict-origin")
            for name, value in headers: self.send_header(name, value)
            self.end_headers()
            self.wfile.write(raw)

        def role(self):
            cookie = SimpleCookie()
            try: cookie.load(self.headers.get("Cookie", ""))
            except Exception: return ""
            value = cookie[COOKIE].value if COOKIE in cookie else ""
            return value if value in ROLES else ""

        def banner(self):
            role = ROLES.get(self.role(), "미선택")
            return ('<aside class="warn" style="position:sticky;top:0;z-index:10;margin:8px;padding:12px">'
                    '<b>로컬 승인 시험 · 가상 로그인 / 모의 알림 / PR 시뮬레이션</b> '
                    f'현재 역할: {role} · <a href="/demo">역할 전환·알림함</a></aside>')

        def page(self, title, body, status=200):
            self.send('<!doctype html><html lang="ko"><meta charset="utf-8">'
                      '<meta name="viewport" content="width=device-width,initial-scale=1">'
                      '<link rel="stylesheet" href="/static/grantline.css">'
                      f'<title>{e(title)} · Grantline Demo</title><body>{self.banner()}'
                      f'<main style="max-width:1040px;margin:24px auto;padding:0 20px"><header class="glass"><h1>{e(title)}</h1></header>{body}</main></body></html>',
                      status, [("Content-Type", "text/html; charset=utf-8")])

        def do_GET(self): self.route()
        def do_POST(self): self.route()

        def route(self):
            public = f"http://127.0.0.1:{self.server.server_port}"
            if self.headers.get_all("Host", []) != [urlsplit(public).netloc]:
                return self.send("Untrusted Host", 403)
            body = b""
            if self.command == "POST":
                if self.headers.get_all("Origin", []) != [public]:
                    return self.send("Same-origin POST required", 403)
                try:
                    lengths = self.headers.get_all("Content-Length", [])
                    if len(lengths) != 1 or self.headers.get("Transfer-Encoding"): raise ValueError
                    size = int(lengths[0])
                    if not 0 <= size <= 65536: raise ValueError
                    body = self.rfile.read(size)
                    if len(body) != size: raise ValueError
                except ValueError:
                    return self.send("Invalid body", 400)
            path = urlsplit(self.path).path
            if path == "/demo/logout" and self.command == "GET":
                return self.send(b"", 303, [("Location", "/demo"),
                    ("Set-Cookie", f"{COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict")])
            if path == "/demo/login" and self.command == "POST":
                form = parse_qs(body.decode())
                role = form.get("role", [""])[0]
                if role not in ROLES: return self.send("Unknown role", 400)
                target = local_path(form.get("next", ["/demo"])[0], "/demo")
                return self.send(b"", 303, [("Location", target),
                    ("Set-Cookie", f"{COOKIE}={role}; Path=/; HttpOnly; SameSite=Strict")])
            if path in {"/", "/demo"} and self.command == "GET":
                target = local_path(parse_qs(urlsplit(self.path).query).get("rd", ["/demo"])[0], "/demo")
                controls = ''.join('<form method="post" action="/demo/login" style="display:inline-block;margin:8px">'
                    f'<input type="hidden" name="role" value="{role}"><input type="hidden" name="next" value="{e(target, quote=True)}">'
                    f'<button type="submit">{label}로 전환</button></form>'
                    for role, label in ROLES.items())
                inbox = []
                for file in sorted((state / "inbox").glob("*.json")):
                    msg = json.loads(file.read_text())
                    links = re.findall(re.escape(public) + r"(/approve/[A-Za-z0-9-]+\?t=[A-Za-z0-9_-]+)", msg["text"])
                    inbox.append('<article class="glass"><p>수신: 가상 승인자</p><pre>' + e(msg["text"]) + '</pre>'
                                 + ''.join(f'<a class="chip" href="{e(link, quote=True)}">승인 요청 열기</a>' for link in links) + '</article>')
                prs = [json.loads(f.read_text()) for f in (state / "prs").glob("*.json")]
                rows = ''.join(f'<li><a href="/demo/pr/{pr["number"]}">시뮬레이션 PR #{pr["number"]}</a></li>' for pr in prs)
                return self.page('승인 흐름 시험실',
                    '<section class="glass"><h2>1. 역할 선택</h2><p>새 GitHub 계정이나 Slack 토큰 없이 시험합니다. 역할 전환은 가상 로그인입니다.</p>'
                    + controls + '<h2>2. 요청 만들기</h2><p>요청자로 전환한 뒤 샘플 요청을 제출하세요.</p>'
                    + f'<a class="chip" href="/act?{e(urlencode(SAMPLE), quote=True)}">샘플 권한 요청</a> '
                    '<a class="chip" href="/act">요청 목록</a>'
                    '<h2>3. 승인·거절</h2><p>가상 승인자로 전환하고 아래 알림에서 요청을 여세요. 요청자 역할로 승인하면 거부됩니다.</p>'
                    '<p>외부 서비스에는 연결하지 않습니다. 앱을 종료하고 다시 실행하면 모든 시험 기록이 초기화됩니다.</p></section>'
                    '<section class="glass"><h2>모의 Slack 알림함</h2><p>새 요청을 제출하면 이곳에 승인 링크가 도착합니다.</p></section>'
                    + ''.join(inbox) + '<section class="glass"><h2>PR 시뮬레이션</h2><p>GitHub에 게시하지 않으며 실제 권한도 바꾸지 않습니다.</p><ul>' + rows + '</ul></section>')
            if path.startswith("/demo/pr/") and self.command == "GET":
                number = path.rsplit("/", 1)[-1]
                for file in (state / "prs").glob("*.json"):
                    pr = json.loads(file.read_text())
                    if str(pr["number"]) == number:
                        return self.page('시뮬레이션 PR #' + number,
                            '<section class="glass"><p>승인한 계획이 로컬 파일로 기록됐습니다. 실제 GitHub PR·IAM 적용은 아닙니다.</p>'
                            + '<pre>' + e(pr["patch"]) + '</pre><p>patch SHA-256: <code>'
                            + e(pr["plan"]["patch_sha256"]) + '</code></p><a href="/demo">시험실로 돌아가기</a></section>')
                return self.send("Unknown simulated PR", 404)
            headers = {name: self.headers[name] for name in ("Host", "Origin", "Content-Type", "Accept", "Accept-Language", "Cookie") if name in self.headers}
            if self.role(): headers["X-Forwarded-Email"] = self.role()
            conn = http.client.HTTPConnection("127.0.0.1", upstream, timeout=15)
            try:
                conn.request(self.command, self.path, body=body, headers=headers)
                response = conn.getresponse()
                raw = response.read()
                out = [(k, v) for k, v in response.getheaders() if k.lower() not in {"content-length", "connection", "transfer-encoding"}]
                if "text/html" in response.getheader("Content-Type", ""):
                    text = raw.decode().replace(PR_PREFIX, "/demo/pr/")
                    raw = re.sub(r"(<body[^>]*>)", lambda m: m[0] + self.banner(), text, count=1).encode()
                self.send(raw, response.status, out)
            finally:
                conn.close()

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8422)
    parser.add_argument("--backend", nargs=3, metavar=("STATE", "PORT", "PUBLIC"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.backend:
        state, port, public = args.backend
        return backend(Path(state), int(port), public)
    def stop(*_): raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    with tempfile.TemporaryDirectory(prefix="grantline-approval-demo-") as directory:
        state = Path(directory)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            upstream = sock.getsockname()[1]
        server = frontend(state, args.port, upstream)
        public = f"http://127.0.0.1:{server.server_port}"
        env = {k: v for k, v in os.environ.items() if k in {"PATH", "SYSTEMROOT", "LANG", "LC_ALL"}}
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--backend", str(state), str(upstream), public], env=env, stdout=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while True:
                if child.poll() is not None: raise RuntimeError("Demo backend could not start")
                try:
                    with socket.create_connection(("127.0.0.1", upstream), timeout=.2): break
                except OSError:
                    if time.monotonic() >= deadline: raise RuntimeError("Demo backend startup timed out") from None
                    time.sleep(.05)
            print(f"DEMO_URL={public}/demo", flush=True)
            print(f"DEMO_STATE={state}", flush=True)
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            child.terminate()
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: child.kill(); child.wait()


if __name__ == "__main__":
    main()
