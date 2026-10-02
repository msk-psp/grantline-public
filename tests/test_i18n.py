"""Language requests must not leak between users or translate service data/commands."""
import html
import json
import re
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from grantline import pages, web
from grantline.adapters import Adapter
from grantline.graph import build
from grantline.i18n import LANGUAGES, catalog, client_catalog, elapsed, h, language, negotiate, t
from grantline.model import Grant

root = Path(__file__).resolve().parent.parent
assert negotiate("ja", "grantline_lang=ko", "en") == "ja"
assert negotiate("", "other=1; grantline_lang=zh-CN", "ko") == "zh-CN"
assert negotiate("unknown", "grantline_lang=invalid", "ja;q=0.2, ko-KR; q=0.8, en;q=0") == "ko"
assert negotiate("", "", "en;q=bad, ja;q=0, fr, zh-CN;q=0.9") == "zh-CN"
assert negotiate("", "", "de") == "en"

formatter = string.Formatter()
fields = lambda s: sorted(field for _, field, _, _ in formatter.parse(s) if field is not None)
for locale in ("ko", "ja", "zh-CN"):
    assert catalog(locale).keys() == catalog("ko").keys()
    for source, translation in catalog(locale).items():
        assert translation and fields(source) == fields(translation), (locale, source)
    token = language.set(locale)
    try:
        # Labels are localized before interpolation. Account/resource names remain opaque,
        # including names that happen to be English interface words and literal braces.
        rendered = h('<h1>Services</h1><p>{0}</p><code>SELECT services FROM "Read";</code>',
                     html.escape('Read <script>{0}</script>'))
        assert '<h1>' + t("Services") + '</h1>' in rendered
        assert 'Read &lt;script&gt;{0}&lt;/script&gt;' in rendered and '<script>' not in rendered
        assert 'SELECT services FROM "Read";' in rendered
        assert h('<input name="subject" value="{0}" placeholder="Search {1}">', "services", "Read").startswith('<input name="subject" value="services"')
        assert 'Read' in h('<input placeholder="Search {0}">', 'Read')
        assert elapsed("2 minutes ago") == t("{0} minutes ago", 2)
        assert json.loads(client_catalog()) == catalog(locale)
        login = pages.render_login(None)
        assert f'<html lang="{locale}">' in login and t("Explore the console") in login
    finally:
        language.reset(token)
assert language.get() == "en"
for locale in LANGUAGES:
    token = language.set(locale)
    try:
        req = SimpleNamespace(id="request1", action="grant", subject="services", priv="Read", resource="bucket:Read",
                              system="s3", requester="Read", ts="2026-10-02T12:00:00Z", status="pending",
                              cmd="MOCK GRANT Read TO services", required={"services": "test-token"}, approved={}, note="")
        approval = pages.render_approve(req, "services")
        assert t("Approvers") in approval and 'value="test-token"' in approval and req.cmd in approval
        assert t("View request") in "".join(pages.queue_sections([req])) and req.cmd in "".join(pages.queue_sections([req]))
        assert t("on the path") in pages.render_probe("services", [], [])
    finally:
        language.reset(token)

# Service icons share the map marks; configured names are data in every locale.
services = {Grant(kind, 'alice', 'db:example' if kind != 's3' else 'bucket:example', 'Read')
            for kind in ('postgres', 'clickhouse', 's3')}
custom = 'custom" onload="alert(1)'
services.add(Grant(custom, 'alice', 'db:example', 'Read'))
for locale in LANGUAGES:
    token = language.set(locale)
    try:
        inventory = pages.render_inventory(services)
        assert inventory.count('<svg class="service-icon') == 4
        for kind in ('postgres', 'clickhouse', 's3'):
            assert f'class="service-icon i-{kind}"' in inventory and web._ICONS[kind] in inventory
        assert html.escape(custom) in inventory and ' onload="alert(1)"' not in inventory
        assert t('prod') == 'prod' and t('staging') == 'staging'
        assert 'class="env"' in web.render_graph_page()
    finally:
        language.reset(token)
graph = build({Grant('postgres', 'alice', 'db:example', 'CONNECT')},
              [{'from': 'service:worker', 'to': 'alice', 'system': '*'}],
              envs={'postgres': ('Read', '自定义 <env>')})
data = web.graph_data(graph)
assert data['instances']['postgres']['env'] == ['Read', '自定义 <env>']
assert all(set(edge['env']) == {'Read', '自定义 <env>'} for edge in data['edges'])

# README translations must retain all runnable commands and resolve every local link.
readmes = [root / 'README.md'] + [root / 'docs' / f'README.{c}.md' for c in ('ko', 'ja', 'zh-CN')]
commands = []
for readme in readmes:
    text = readme.read_text()
    assert all(name in text for name in LANGUAGES.values())
    commands.append([line.split('#', 1)[0].strip() for block in re.findall(r'```bash\n(.*?)```', text, re.S)
                     for line in block.splitlines() if line.strip()])
    for target in re.findall(r'\]\(([^)]+)\)', text):
        if '://' not in target:
            assert (readme.parent / target).is_file(), (readme, target)
assert all(command == commands[0] for command in commands)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


class Spy(Adapter):
    cfg = {}
    privs = ("Read",)
    def __init__(self): self.calls = []
    def write_ready(self): return False, "mock read-only"
    def grant_cmd(self, grant): return f"MOCK GRANT {grant.priv} TO {grant.subject} ON {grant.resource}"
    def revoke_cmd(self, grant): return "MOCK REVOKE"
    def apply(self, change): self.calls.append(change)


servers = []
real_server = web.HTTPServer
spy = Spy()
grant = Grant("s3", "services", "bucket:Read", "Read")
previous = pages.WRITE_READY

def capture(addr, handler):
    server = real_server(("127.0.0.1", 0), handler)
    servers.append(server)
    return server

with patch.object(web, "HTTPServer", capture):
    thread = threading.Thread(target=web.serve, args=(lambda: ({grant}, [], []), 0),
                              kwargs={"adapters": {"s3": spy}}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 3
    while not servers and time.monotonic() < deadline: time.sleep(.01)
    assert servers
    server = servers[0]; base = f"http://127.0.0.1:{server.server_port}"
    opener = urllib.request.build_opener(NoRedirect)
    def request(path, headers=None):
        try:
            with opener.open(urllib.request.Request(base + path, headers=headers or {}), timeout=3) as response:
                return response.status, response.headers, response.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read().decode()
    try:
        # Both shared logos must be real local PNGs with a browser image MIME type.
        for kind, name in (("postgres", "postgresql.png"), ("s3", "seaweedfs.png")):
            assert f'href="{web.asset(name)}"' in web._ICONS[kind]
            with opener.open(base + web.asset(name), timeout=3) as response:
                data = response.read()
                assert response.status == 200 and response.headers['Content-Type'] == 'image/png'
                assert data.startswith(b'\x89PNG\r\n\x1a\n')
                assert data == (web._STATIC / name).read_bytes()
        for locale in LANGUAGES:
            for path in ('/login', '/', '/services', '/s/services', '/g/s3/bucket%3ARead', '/matrix', '/act', '/missing'):
                status, headers, body = request(path, {"Cookie": f"grantline_lang={locale}"})
                assert status == (404 if path == '/missing' else 200), (locale, path, status)
                assert headers['Content-Language'] == locale and f'<html lang="{locale}">' in body
                assert f'<option value="{locale}" selected>' in body
            status, _, body = request('/act?action=grant&system=s3&subject=services&resource=bucket%3ARead&priv=Read',
                                      {"Cookie": f"grantline_lang={locale}"})
            assert status == 200 and 'MOCK GRANT Read TO services ON bucket:Read' in body
            assert 'name="subject" value="services"' in body and 'name="priv" value="Read"' in body
        status, headers, _ = request('/language?' + urllib.parse.urlencode({"lang": "ko", "next": "/services?lang=en&refresh=1&focus=Read#main"}))
        assert status == 303 and headers['Location'] == '/services?focus=Read#main'
        assert 'grantline_lang=ko;' in headers['Set-Cookie'] and 'HttpOnly' in headers['Set-Cookie']
        assert request('/services', {"Cookie": headers['Set-Cookie'], "Accept-Language": "ja"})[1]['Content-Language'] == "ko"
        assert request('/services?lang=ja', {"Cookie": headers['Set-Cookie']})[1]['Content-Language'] == "ja"
        assert request('/language?lang=invalid')[0] == 400
        assert request('/language?lang=en&next=https%3A%2F%2Fexample.com')[1]['Location'] == '/'
        assert request('/login', {"Accept-Language": "zh-CN"})[1]['Content-Language'] == 'zh-CN'
        assert request('/login')[1]['Content-Language'] == 'en', "the previous request must not leak its language"
        assert not spy.calls, "language selection, rendering and preview must not write service grants"
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
        pages.WRITE_READY = previous
print("ok four language catalogs, opaque identifiers/commands, README links, cookies and HTTP isolation")
