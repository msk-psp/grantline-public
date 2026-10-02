"""Web UI: one page — the access matrix, the drift plan, the findings.

Rendered fresh on every request from the same code path the CLI uses, so the
page and `plan` can never disagree.
"""
from __future__ import annotations

import html
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from .diff import Change
from .i18n import LANGUAGES, h, language, negotiate, t
from .model import Finding, Grant, level

_STATIC = Path(__file__).parent / "static"


def asset(name: str) -> str:
    """`/static/<name>?v=<mtime>` — the URL changes when the file does, so a browser
    never runs a stale module against a fresh page (module scripts are cached hard)."""
    try:
        return f"/static/{name}?v={int((_STATIC / name).stat().st_mtime)}"
    except OSError:
        return f"/static/{name}"



def _kind(resource: str) -> str:
    """`db:analytics` -> `db`. Resources are `kind:name` by convention (model.py)."""
    return resource.split(":", 1)[0] if ":" in resource else "other"


def _bucket_family(resource: str) -> str:
    """`bucket:warehouse/analytics.silver/*` -> `bucket:warehouse`.

    Object storage resources carry a prefix path, so one bucket becomes dozens of
    columns. The bucket is the unit people reason about; the prefix is detail.
    """
    name = resource.split(":", 1)[1] if ":" in resource else resource
    return "bucket:" + name.split("/", 1)[0]


def group_of(system: str, resource: str) -> tuple[str, str]:
    """(system, group) — the column a resource lands in."""
    k = _kind(resource)
    return (system, _bucket_family(resource) if k == "bucket" else k)


_RANK = {"admin": 4, "write": 3, "rw": 3, "read": 2, "list": 1}


def _strength(privs: set[str]) -> str:
    """A cell holds many privileges; the class should reflect the strongest one."""
    best, label = 0, "read"
    for p in privs:
        v = _RANK.get(p.lower(), 3 if p.upper() in
                      {"INSERT", "UPDATE", "DELETE", "ALTER", "CREATE", "DROP",
                       "TRUNCATE", "ALL", "MEMBER"} else 2)
        if v > best:
            best, label = v, ("admin" if v == 4 else "write" if v == 3 else
                              "read" if v == 2 else "list")
    return label


def render(observed: set[Grant], changes: list[Change], findings: list[Finding],
           unverified: list[Grant] = (), unobserved=()) -> str:
    e = html.escape
    atoms = [(g.system, g.subject, g.resource, g.priv, g.source, 0, 0) for g in observed]
    atoms += [(c.grant.system, c.grant.subject, c.grant.resource, c.grant.priv, "plan",
               1 if c.action == "grant" else 0, 0 if c.action == "grant" else 1)
              for c in changes]
    atoms += [(g.system, g.subject, g.resource, g.priv, "blind", 0, 0) for g in unverified]

    # ── group, don't enumerate ────────────────────────────────────────────────
    # One column per (system, resource) produced 760 columns on a real cluster — every
    # table, every storage prefix. Nobody reads that. Resources already carry their kind
    # (`db:`, `role:`, `table:`, `bucket:`), and that kind is the level people actually
    # reason at: "can researcher_a reach the warehouse bucket" long before "…which prefix".
    cols: dict[tuple[str, str], set[str]] = {}
    cell: dict[tuple, dict] = {}
    for system, subj, res, priv, src, add, rm in atoms:
        col = group_of(system, res)
        cols.setdefault(col, set()).add(res)
        c = cell.setdefault((subj, col), {"privs": set(), "src": set(), "res": set(),
                                          "add": 0, "rm": 0})
        c["privs"].add(priv)
        c["src"].add(src)
        c["res"].add(res)
        c["add"] += add
        c["rm"] += rm

    col_list = sorted(cols)
    subjects = sorted({a[1] for a in atoms} | {s for u in unobserved for s in u.subjects})

    sys_span: dict[str, int] = {}
    for sysname, _ in col_list:
        sys_span[sysname] = sys_span.get(sysname, 0) + 1
    head1 = "".join(h('<th scope="colgroup" colspan="{0}">{1}</th>', n, e(s)) for s, n in sys_span.items())
    head2 = "".join(
        h('<th scope="col"><a href="/g/{0}/{1}">{2}</a><span class="cnt">{3}</span></th>', quote(s, safe=""), quote(g, safe=""), e(g), len(cols[(s, g)])) for s, g in col_list)

    rows = []
    for subj in subjects:
        tds = []
        for col in col_list:
            c = cell.get((subj, col))
            if any(u.covers(Grant(col[0], subj, res, ""))
                   for u in unobserved for res in cols[col]):
                tds.append(h('<td class="blind" title="could not check">?</td>'))
                continue
            if not c:
                tds.append(h('<td class="none">—</td>'))
                continue
            if c["src"] == {"blind"}:
                tds.append(h('<td class="blind" title="could not check">?</td>'))
                continue
            klass = _strength(c["privs"])
            n = len(c["res"])
            badge = ""
            if c["add"]:
                badge += h('<span class="drift d-add">+{0}</span>', c["add"])
            if c["rm"]:
                badge += h('<span class="drift d-rm">−{0}</span>', c["rm"])
            label = t(klass.capitalize()) + ("" if n == 1 else f" · {n}")
            tds.append(h('<td class="{0}" title="{1}"><span class="access-grade">{2}</span>{3}</td>', klass, e(", ".join(sorted(c["res"]))[:400]), e(label), badge))
        rows.append(h('<tr><th scope="row"><a href="/s/{0}">{1}</a></th>{2}</tr>', quote(subj, safe=""), e(subj), "".join(tds)))

    if changes:
        lines = "".join(
            h('<code class="{0}">{1} [{2}] {3}</code>', "add" if c.action == "grant" else "rm", "+" if c.action == "grant" else "−", e(c.grant.system), e(c.cmd))
            for c in changes[:200])
        more = (h('<p class="ok">… {0} more</p>', len(changes) - 200)
                if len(changes) > 200 else "")
        plan_html = h('<div class="cmd">{0}</div>{1}', lines, more)
    elif unobserved:
        plan_html = h('<p class="ok">No changes planned. Some scopes could not be observed; convergence is unknown.</p>')
    else:
        plan_html = h('<p class="ok">Converged — observed state matches intent.</p>')

    groups: dict[tuple[str, str], list] = {}
    for f in findings:
        groups.setdefault((f.system, f.title), []).append(f)
    notes = "".join(
        h('<div class="note"><b>[{0}] {1}</b>', e(sysname), e(title))
        + (h('<span class="cnt">{0}</span>', len(fs)) if len(fs) > 1 else "")
        + "".join(h('<p>{0}</p>', e(f.detail)) for f in fs[:2])
        + (h('<details><summary>{0} more findings</summary>', len(fs) - 2)
           + "".join(h('<p>{0}</p>', e(f.detail)) for f in fs[2:]) + h('</details>') if len(fs) > 2 else "")
        + h('</div>')
        for (sysname, title), fs in sorted(groups.items(), key=lambda kv: -len(kv[1]))
    ) or h('<p class="ok">No findings.</p>')

    # 이 페이지만 nav 가 없어서 매트릭스에 들어가면 다른 탭으로 못 나갔다 —
    # 브라우저 뒤로가기 말고는 길이 없었다. pages._shell 을 안 거치는 두 페이지
    # (여기와 routes) 가 같은 이유로 빠졌고, routes 는 앞서 고쳤다.
    from .pages import _nav, _shell
    return _shell(t("Access matrix"), h("""
{0}
<header class="glass">
<h1>Access matrix</h1>
<p class="lede">Subjects &times; resource groups, read live with read-only credentials.
Columns collapse to the level people reason at — a bucket, a kind of object — with the
count of distinct resources behind each. Hover a cell for the list.
<span class="drift d-add">+n</span> grants missing from the server,
<span class="drift d-rm">−n</span> present but absent from intent,
<span class="blind">?</span> could not be checked (not the same as "no access").</p>
</header>
<section class="glass matrix">
<h2>Observed</h2>
<p class="hint">Read / Write / Admin / List shows the strongest observed access; · n is the resource count.
— means no observed grant; ? means unknown. Scroll across for all services.</p>
<div class="scroll"><table>
<thead><tr><th></th>{1}</tr><tr><th>subject</th>{2}</tr></thead>
<tbody>{3}</tbody></table></div>
{4}
</section>
<section class="glass">
<h2>Plan &middot; native commands, nothing applied</h2>{5}
</section>
<section class="glass">
<h2>Findings</h2>{6}
</section>
""", _nav("/matrix"), head1, head2, "".join(rows), h('<p class="ok">No accounts or grants were observed. Check service read errors and refresh before interpreting this as no access.</p>') if not rows else '', plan_html, notes))


def _form(raw: str) -> dict[str, str]:
    """Flatten a query/body into single values — every field here is single-valued."""
    from urllib.parse import parse_qs
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


class _ObservationCache:
    """One observer at a time; cached readers never wait for a periodic refresh."""
    def __init__(self, read):
        import threading
        self.lock = threading.RLock()
        self.read = read
        self.value = None

    def get(self, fresh=False):
        value = self.value
        if value is not None and not fresh:
            return value
        with self.lock:
            if fresh or self.value is None:
                value = self.read()  # publish only complete observations
                self.value = value
            return self.value

    def clear(self):
        with self.lock:
            self.value = None


def serve(observe_fn, port: int, bridges_fn=lambda: [], adapters: dict | None = None,
          audit_path: str | None = None, recorder=None, approvals=None, ttl_s: float = 60,
          graph_fn=None, trusted_hosts=(), auth=None) -> None:
    """GET renders, POST writes. That split is load-bearing, not convention: a GET
    that changed something would be triggered by a link, a prefetch, or a reload of
    the page that just wrote — and F3's whole claim is that only what the operator
    named is touched."""
    adaps = adapters or {}
    from .auth import current, local_path, proxy_config, proxy_target, proxy_user
    auth_cfg = proxy_config(auth)

    def reqs() -> list:
        """Everything proposed so far — the queue that lives under the form."""
        return approvals.all() if approvals is not None and approvals.enabled else []

    if graph_fn is None:
        from .graph import build as _build
        graph_fn = lambda observed: _build(observed, bridges_fn())
    # One observation serves every page for a while. Each observe is every adapter over
    # the network (~4 s on a real cluster); paying it per click made the tabs crawl.
    # A write (POST) reads fresh and drops the cache, and `?refresh` forces one.
    def read():
        data = tuple(observe_fn())
        data = (*data[:3], data[3] if len(data) > 3 else (),
                data[4] if len(data) > 4 else None, data[5] if len(data) > 5 else ())
        # Routes/kinds live on adapters and change on observe: freeze them with the
        # same observation so a background read cannot mix two generations.
        return (*data, graph_fn(data[0]))

    cache = _ObservationCache(read)
    observe = cache.get

    from . import pages as _pages
    _pages.APPROVALS_ENABLED = approvals is not None and approvals.enabled
    # 한 번만 묻는다: 이 프로세스에 쓰기 자격이 있는가. 환경변수는 기동 후 바뀌지
    # 않고, 답이 「없음」이면 changes 탭이 그 사실을 먼저 말한다 (pages._nav).
    # 어댑터가 답을 못 주면(구식 어댑터) 아무 말도 하지 않는다 — None.
    try:
        _pages.WRITE_READY = any(a.write_ready()[0] for a in adaps.values())
    except Exception:                           # noqa: BLE001
        _pages.WRITE_READY = None

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def _trusted(self, write=False):
            port = self.server.server_port
            hosts = {f"127.0.0.1:{port}", f"localhost:{port}", *trusted_hosts}
            if approvals is not None and approvals.console_url:
                hosts.add(urlsplit(approvals.console_url).netloc)
            host = self.headers.get("Host", "")
            if host not in hosts:
                self.send_error(403, "untrusted Host"); return False
            if write:
                try:
                    origin = urlsplit(self.headers.get("Origin", ""))
                except ValueError:
                    self.send_error(403, "invalid Origin"); return False
                if origin.scheme not in ("http", "https") or origin.netloc != host or origin.path:
                    self.send_error(403, "same-origin POST required"); return False
            return True

        def _send(self, html_: str, status: int = 200):
            body = html_.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Language", language.get())
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            # Native form POSTs need Origin; no-referrer turns it into null.
            # Send only the origin, never an approval token in the page's path/query.
            self.send_header("Referrer-Policy", "strict-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD": self.wfile.write(body)

        def send_error(self, code, message=None, explain=None):
            from .pages import render_error
            self._send(render_error(code, message or self.responses.get(code, ("Request unavailable",))[0]), code)

        def _redirect(self, location):
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send_bytes(self, body: bytes, ctype: str, cache: str = "no-store", status=200):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            user = proxy_user(self.headers, auth_cfg)
            locale_token = language.set(negotiate(_form(urlsplit(self.path).query).get("lang", ""),
                                                 self.headers.get("Cookie", ""),
                                                 self.headers.get("Accept-Language", "")))
            token = current.set({"enabled": auth_cfg is not None, "user": user,
                                 "path": local_path(self.path),
                                 "logout": proxy_target(auth_cfg["logout_url"], "/login") if auth_cfg else ""})
            try:
                self._get()
            except Exception:  # noqa: BLE001 — do not expose service credentials in HTTP errors
                self.send_error(503, "Unable to load access data. Refresh or check the configured service connections.")
            finally:
                current.reset(token)
                language.reset(locale_token)

        def _get(self):
            if not self._trusted():
                return
            from .pages import parse_path, render_act, render_group, render_inventory, render_subject
            path, _, query = self.path.partition("?")
            if path == "/language":
                params = _form(query)
                if params.get("lang") not in LANGUAGES:
                    self.send_error(400, "Unsupported language"); return
                self.send_response(303)
                destination = urlsplit(local_path(params.get("next", "/")))
                query = urlencode([(k, v) for k, v in parse_qsl(destination.query, keep_blank_values=True)
                                   if k not in ("lang", "refresh")])
                self.send_header("Location", destination.path + ("?" + query if query else "") +
                                 ("#" + destination.fragment if destination.fragment else ""))
                self.send_header("Set-Cookie", f'grantline_lang={params["lang"]}; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly')
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path.startswith("/static/"):
                name = path.removeprefix("/static/")
                f = _STATIC / name
                if "/" in name or not f.is_file():
                    self.send_error(404); return
                ctype = {"css": "text/css", "js": "text/javascript"}.get(f.suffix[1:], "application/octet-stream")
                # versioned URLs (asset()) — safe to cache for a long time
                self._send_bytes(f.read_bytes(), ctype + "; charset=utf-8", cache="max-age=31536000, immutable")
                return
            if path == "/login":
                from .pages import render_login
                self._send(render_login(auth_cfg, _form(query).get("next", "/")))
                return
            if auth_cfg and not current.get()["user"]:
                login = "/login?" + urlencode({"next": local_path(self.path)})
                if path.startswith("/api/"):
                    import json
                    self._send_bytes(json.dumps({"error": "Sign in to continue", "login": login}).encode(),
                                     "application/json", status=401)
                else:
                    self._redirect(login)
                return
            if path == "/api/graph.json":
                import json
                data = observe("refresh" in query)
                blind = data[5] if len(data) > 5 else ()
                self._send_bytes(json.dumps(graph_data(data[-1], blind)).encode(),
                                 "application/json")
                return
            if path == "/api/resources.json":
                import json
                instance = html.unescape(_form(query).get("instance", ""))
                data = observe()
                self._send_bytes(json.dumps(resources_data(data[-1], instance)).encode(), "application/json")
                return
            page, args = parse_path(path)
            if page == "404":
                self.send_error(404)
                return
            if page in ("approve", "request") and not (approvals is not None and approvals.enabled):
                self.send_error(404, "Approvals are not enabled on this console. Preview a change instead.")
                return
            # 큐의 대기 건수는 nav 배지가 쓴다. 파일 몇 개를 세는 일이라 매 요청에 해도 된다.
            from . import pages as _pages
            _pages.PENDING_COUNT = sum(1 for r in reqs() if r.status in ("pending", "approved"))
            if page == "graph":
                # 지도는 첫 화면이다. 그리고 이 응답은 관측을 **기다리지 않는다** —
                # 껍데기는 정적이고 내용은 /api/graph.json 이 따로 가져온다. 여기서
                # observe() 를 부르면 캐시가 식은 첫 방문자가 다섯 시스템을 다 읽을
                # 때까지 흰 화면을 본다. 껍데기부터 칠하고, 지도는 도착하는 대로.
                self._send(render_graph_page())
                return
            data = observe("refresh" in query)
            observed = data[0]
            if page == "matrix":
                html_ = render(*data[:3], unverified=data[3], unobserved=data[5])
            elif page == "subject":
                html_ = render_subject(observed, data[-1], *args, unobserved=data[5])
            elif page == "approve":
                from .act import ActError
                from .pages import render_approve
                q = _form(query)
                try:
                    req = approvals.load(args[0])
                    approver = next((a for a, t in req.required.items() if t == q.get("t", "")), None)
                    html_ = render_approve(req, approver)
                except ActError as exc:
                    self.send_error(404, str(exc)); return
            elif page == "probe":
                from . import probe as probe_mod
                from .pages import render_probe
                (subject,) = args
                probes, fnd = probe_mod.run(adaps, observed, {subject})  # read-only probes
                html_ = render_probe(subject, probes, fnd)
            elif page == "group":
                html_ = render_group(observed, *args)
            elif page == "act":
                html_ = render_act(_form(query), observed, adaps, requests=reqs())
            else:
                # F8. The recorder, not the request: this process snapshots once, so
                # "since your previous run" keeps meaning the run and not the reload.
                html_ = render_inventory(observed, recorder, unobserved=data[5])
            self._send(html_)

        def do_POST(self):
            user = proxy_user(self.headers, auth_cfg)
            locale_token = language.set(negotiate("", self.headers.get("Cookie", ""),
                                                 self.headers.get("Accept-Language", "")))
            token = current.set({"enabled": auth_cfg is not None, "user": user,
                                 "path": local_path(self.path),
                                 "logout": proxy_target(auth_cfg["logout_url"], "/login") if auth_cfg else ""})
            try:
                with cache.lock:
                    self._post()
            except Exception:  # noqa: BLE001 — a failed response does not prove a write failed
                self.send_error(503, "Unable to finish this request. Check its status in Changes before retrying.")
            finally:
                current.reset(token)
                language.reset(locale_token)

        def _post(self):
            if not self._trusted(write=True):
                return
            if auth_cfg and not current.get()["user"]:
                self.send_error(401, "Your sign-in session is unavailable. Sign in again before submitting a change.")
                return
            from .pages import parse_path
            page, args = parse_path(self.path.partition("?")[0])
            if page not in ("act", "request", "approve"):
                self.send_error(404)
                return
            if page == "act" and _pages.APPROVALS_ENABLED:
                self.send_error(403, "approval is required"); return
            if page in ("request", "approve") and not (approvals is not None and approvals.enabled):
                self.send_error(404, "Approvals are not enabled on this console."); return
            try:
                if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                    raise ValueError("one Content-Length required")
                n = int(self.headers["Content-Length"])
                if not 0 <= n <= 65536:
                    self.send_error(413, "body exceeds 64 KiB"); return
                params = _form(self.rfile.read(n).decode())
            except (ValueError, UnicodeError):
                self.send_error(400, "invalid request body"); return
            if page == "approve" and params.get("decision") not in ("approve", "deny"):
                self.send_error(400, "Choose approve or deny. No decision was recorded."); return
            observed = observe(fresh=True)[0]
            cache.clear()  # before and after: no refresh can publish pre-write state
            try:
                self._perform_post(page, args, params, observed)
            finally:
                cache.clear()

        def _perform_post(self, page, args, params, observed):
            from .act import ActError, execute, propose
            from .pages import render_act
            if page == "approve":
                from .pages import render_approve
                try:
                    req, who = approvals.decide(args[0], params.get("t", ""), params.get("decision") == "approve")
                    if req.status == "approved" and adaps.get(req.system) and adaps[req.system].write_ready()[0]:
                        req = approvals.run(req, adaps, audit_path, observed)
                    self._redirect("/approve/" + quote(req.id, safe="") + "?" + urlencode({"t": params.get("t", "")}))
                except ActError as exc:
                    try:
                        req = approvals.load(args[0])
                        self._send(render_approve(req, None, error=str(exc)), 409)
                    except ActError:
                        self.send_error(404, str(exc))
                return
            if page == "request":
                try:
                    prop = propose(params.get("action", ""), params.get("system", ""), params.get("subject", ""),
                                   params.get("resource", ""), params.get("priv", ""), observed, adaps)
                    if not params.get("cmd") or params["cmd"] != prop.cmd:
                        raise ActError("preview the current command before requesting approval")
                    req = approvals.create(prop, requester=current.get()["user"] or None)
                    req.note = "; ".join(approvals.notify(req))
                    approvals.save(req)
                    self._redirect("/approve/" + quote(req.id, safe=""))
                except ActError as exc:
                    self._send(render_act(params, observed, adaps, error=str(exc), requests=reqs()), 409)
                return
            done = error = ""
            try:
                if not params.get("cmd"):
                    raise ActError("preview command is required")
                prop = propose(params.get("action", ""), params.get("system", ""),
                               params.get("subject", ""), params.get("resource", ""),
                               params.get("priv", ""), observed, adaps)
                execute(prop, adaps, audit_path, expect_cmd=params.get("cmd"))
                self._redirect("/s/" + quote(prop.grant.subject, safe=""))
                return
            except ActError as exc:
                error = str(exc)
            self._send(render_act(params, observed, adaps, error=error, done=done, requests=reqs()),
                       200 if done else 409)

        def log_message(self, *a):  # quiet
            pass

    print(f"grantline: http://127.0.0.1:{port}/  (Ctrl-C to stop)")
    # 첫 방문자가 관측을 기다리지 않게 미리 한 번 읽어 둔다. 서버가 뜬 뒤 백그라운드로
    # 도니 기동이 늦어지지 않고, 실패해도 첫 요청이 정상 경로로 다시 시도한다.
    # 그리고 이 예열이 프로세스당 하나뿐인 스냅샷을 남기므로, 콘솔을 켠 시각이
    # 곧 이력의 한 점이 된다.
    stopped = threading.Event()

    def refresh():
        while not stopped.is_set():
            try:
                observe(fresh=True)
            except Exception:                       # noqa: BLE001 — keep the last complete result
                pass
            if stopped.wait(max(0.01, ttl_s)):
                break

    server = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=refresh, daemon=True).start()
    try:
        server.serve_forever()
    finally:
        stopped.set()
        server.server_close()



_KIND_ORDER = ("human", "service", "svc-account", "role", "group", "policy", "instance")
_KIND_TITLE = {"svc-account": "service account", "instance": "service instance"}

_ICONS = {
    # The marks people already know, reduced to 16px strokes in the brand's colour.
    # PostgreSQL: the elephant — head, ear, trunk, eye
    "postgres": '<ellipse cx="3" cy="7.2" rx="2" ry="2.9" fill="currentColor" stroke="none" opacity=".6"/>'
                '<ellipse cx="13" cy="7.2" rx="2" ry="2.9" fill="currentColor" stroke="none" opacity=".6"/>'
                '<circle cx="8" cy="6.6" r="4.6" fill="currentColor" stroke="none"/>'
                '<path d="M8 9.5v5.5" stroke-width="2.8"/>'
                '<circle cx="6.3" cy="5.8" r=".85" fill="#0e1116" stroke="none"/><circle cx="9.7" cy="5.8" r=".85" fill="#0e1116" stroke="none"/>',
    # ClickHouse: the bars, one of them red
    "clickhouse": '<path d="M1.5 2v12M4.8 2v12M8.1 2v12M11.4 2v12" stroke-width="1.8"/><path d="M14.5 6.5v3" stroke="#e03e2d" stroke-width="1.8"/>',
    # SeaweedFS (S3 here): a seaweed stalk with fronds
    "s3": '<path d="M8 15V1.5"/><path d="M8 6C5.4 6 3.8 4.6 3.3 2.6 5.8 2.6 7.5 3.7 8 6z"/>'
          '<path d="M8 9.8c2.6 0 4.2-1.4 4.7-3.4-2.5 0-4.2 1.1-4.7 3.4z"/><path d="M8 13.4c-2.4 0-3.9-1.2-4.4-3 2.3 0 3.9 1 4.4 3z"/>',
    # Airflow: the pinwheel
    "airflow": '<path d="M8 8C8 4.4 9.8 2.2 14 1.8 12.6 4.6 10.8 6.8 8 8zM8 8c3.6 0 5.8 1.8 6.2 6-2.8-1.4-5-3.2-6.2-6zM8 8c0 3.6-1.8 5.8-6 6.2 1.4-2.8 3.2-5 6-6.2zM8 8C4.4 8 2.2 6.2 1.8 2c2.8 1.4 5 3.2 6.2 6z" fill="currentColor" stroke="none"/>',
    # a running service: a box with a status light
    "app": '<rect x="1.5" y="3" width="13" height="10" rx="2"/><path d="M4 8h5"/><circle cx="11.5" cy="8" r="1" fill="currentColor" stroke="none"/>',
    # a person
    "person": '<circle cx="8" cy="5.2" r="3"/><path d="M2.5 14.5c.6-3.3 2.6-5 5.5-5s4.9 1.7 5.5 5"/>',
    # a service account: gear
    "gear": '<circle cx="8" cy="8" r="2.6"/><path d="M8 1.5v2.2M8 12.3v2.2M1.5 8h2.2M12.3 8h2.2M3.4 3.4l1.6 1.6M11 11l1.6 1.6M3.4 12.6L5 11M11 5l1.6-1.6"/>',
    "generic": '<circle cx="8" cy="8" r="6"/>',
}


_SERVICE_ICONS = {"airflow*": "airflow", "duckdb*": "postgres"}


def _service_icon(name: str) -> str:
    from fnmatch import fnmatch
    return next((ic for pat, ic in _SERVICE_ICONS.items() if fnmatch(name, pat)), "app")


def _icon(kind: str, x: float, y: float) -> str:
    return (f'<g class="ic i-{kind}" transform="translate({x},{y})" fill="none" stroke="currentColor" '
            f'stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">'
            f'{_ICONS.get(kind, _ICONS["generic"])}</g>')


def _kind_of_instance(instance: str) -> str:
    from .model import kind_of
    return kind_of(instance)


def _edge_class(edge) -> str:
    """What kind of relationship a line is — the colour says it.
    member  : into a role or group (PG/CH MEMBER, S3 group membership)
    policy  : a policy attached to a group, or inline on an identity
    read/write/admin : a privilege on a resource, graded like the matrix
    route   : a policy's statement scope (no privilege grade of its own here)"""
    if edge.kind == "bridge":
        return "bridge"
    if edge.kind == "route":
        return {"member": "e-member", "attaches": "e-policy", "inline": "e-policy"}.get(edge.note, "e-route")
    if edge.privs == {"MEMBER"}:
        return "e-member"
    return f"e-{level(edge.privs)}"




def resources_data(graph, instance: str) -> dict:
    """What the map collapses onto one instance node, unfolded: every (source, resource,
    grade) in that instance. The map groups it level by level — db › schema › table,
    bucket › prefix — so the reader drills instead of drowning."""
    keep = graph.principals | graph.hops
    # grants and flat grants carry a grade; a policy's scope ("route") does not
    items = [{"src": e.src, "res": e.dst, "level": level(e.privs)}
             for e in graph.edges if e.system == instance and e.dst not in keep and e.kind != "route"]
    return {"instance": instance, "items": items}


def graph_data(graph, unobserved=()) -> dict:
    """The routes map as data. Layout and drawing live in static/map.js; this is the
    one place that decides *what* is on the map — which nodes, which edges, coloured
    how, in which environment. The page and the JSON can never disagree because the
    page has nothing else to draw from.

    `unobserved` carries F6 onto the map. A system the observer could not read has no
    nodes and no edges, which on a map is indistinguishable from a system nobody can
    reach — the one reading this tool exists to prevent. The map cannot draw the
    routes it could not see, so it says so, by name, above the picture."""
    nodes = sorted(graph.principals | graph.hops | graph.terminals)
    # Terminals dominate the count (760 on a real cluster) and would make the page
    # unreadable. The map's job is the *route*: hops and what leads into them; the
    # resources collapse, per service instance, onto one node at the right edge.
    keep = graph.principals | graph.hops
    fan_privs: dict[tuple[str, str], set] = {}   # (src, instance) -> union of privileges
    reached: dict[str, int] = {}                 # instance -> resources reached
    for edge in graph.edges:
        if edge.dst not in keep:
            if edge.kind == "flat":
                # counted, not drawn: the identity's line runs through its policy
                reached[edge.system] = reached.get(edge.system, 0) + 1
                continue
            fan_privs.setdefault((edge.src, edge.system), set()).update(edge.privs)
            if edge.kind != "route":          # a policy's scope is a line, not a resource count
                reached[edge.system] = reached.get(edge.system, 0) + 1

    def env(system: str) -> list[str]:
        return ["prod", "staging"] if system == "*" else list(graph.env_of(system))

    # Where each node lives: the instances whose grant tables mention it. A role
    # called research_maintainer exists in postgres *and* postgres-staging; the column
    # says it is a role, this says which ones.
    homes: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.system == "*":
            continue
        homes.setdefault(edge.src, set()).add(edge.system)
        homes.setdefault(edge.dst, set()).add(edge.system)
    out_nodes = []
    for n in nodes:
        if n not in keep:
            continue
        kind = graph.kind_of(n)
        # `service:airflow` 는 접두사를 떼고 보여준다. 접두사가 없는 이름은 그대로 —
        # partition 은 구분자가 없으면 빈 문자열을 준다 (이름 없는 노드가 되던 버그).
        label = (n.partition(":")[2] or n) if kind in ("group", "policy", "service") else graph.label(n)
        icon = (_service_icon(label) if kind == "service" else "gear" if kind == "svc-account" else None)
        out_nodes.append({"id": n, "kind": kind, "label": label, "icon": icon, "tag": None,
                          "homes": sorted(homes.get(n, ())), "team": graph.teams.get(n),
                          "sort": n.partition(":")[2] or n})
    for sy in sorted(reached):
        out_nodes.append({"id": f"@{sy}", "kind": "instance", "label": sy, "icon": _kind_of_instance(sy),
                          "tag": f"{reached[sy]} res ›", "sort": sy})   # › : click to unfold

    out_edges = []
    for edge in graph.edges:
        if edge.src not in keep or edge.dst not in keep or edge.kind == "flat":
            continue
        out_edges.append({"src": edge.src, "dst": edge.dst, "cls": _edge_class(edge), "env": env(edge.system),
                          "kind": None if edge.system == "*" else _kind_of_instance(edge.system),
                          # what the line *is*, in the words of the system it came from
                          "what": edge.note or (edge.label if edge.kind != "route" else edge.note) or ", ".join(sorted(edge.privs)[:4]),
                          "label": edge.label if edge.kind == "bridge" else None})
    for (src, sy), privs in sorted(fan_privs.items()):
        if src in keep:
            out_edges.append({"src": src, "dst": f"@{sy}", "cls": f"e-{level(privs)}" if privs else "e-route",
                              "env": env(sy), "kind": _kind_of_instance(sy), "label": None,
                              "what": f"{len(privs) and ', '.join(sorted(privs)[:4])} on {sum(1 for e in graph.edges if e.src == src and e.system == sy and e.dst not in keep)} resources"})
    instances = {sy: {"kind": _kind_of_instance(sy), "env": list(graph.env_of(sy))}
                 for sy in {e.system for e in graph.edges if e.system != "*"}}
    # 같은 시스템에 여러 건이 오면 한 줄로 합친다 — 이름이 세 번 나오는 게 아니라
    # 시스템 하나가 안 읽혔다는 사실 하나다.
    blind: dict[str, list[str]] = {}
    for u in unobserved or ():
        blind.setdefault(u.system, []).append(
            f"{', '.join(u.subjects) + ': ' if u.subjects else ''}{', '.join(u.prefixes)} — {u.note}")
    return {"columns": list(_KIND_ORDER), "titles": _KIND_TITLE, "icons": _ICONS, "instances": instances,
            "nodes": out_nodes, "edges": out_edges,
            "blind": [{"system": sy, "note": "; ".join(notes)} for sy, notes in sorted(blind.items())]}


def render_graph_page() -> str:
    from .pages import _nav, _shell
    return _shell(t("Authorization paths"), h("""
{0}
<header class="glass">
<h1>Authorization paths</h1>
<p class="lede">How authority <em>reaches</em> a resource. The matrix shows who holds
what; it cannot show that a person holds nothing directly and reaches everything through
a role — or that a hop leaves the system entirely and continues on a credential the
server holds, never theirs.</p>
</header>
<section class="glass">
<h2>Routes <span class="cnt">click a name &middot; scroll to zoom &middot; drag to pan</span></h2>
<div class="tools">
  <div class="grp" role="group" aria-label="environment"><span class="lbl">environment</span>
    <button type="button" class="on" data-env="prod" title="what reaches production">prod</button>
    <button type="button" class="on" data-env="staging" title="what reaches staging">staging</button>
  </div>
  <div class="grp" role="group" aria-label="service"><span class="lbl">service</span><span class="svc"></span></div>
  <div class="grp view" role="group" aria-label="view"><span class="lbl">view</span>
    <button type="button" data-z="in" title="zoom in (or scroll)">+</button>
    <button type="button" data-z="out" title="zoom out">−</button>
    <button type="button" data-z="fit" title="back to the top, full width (Esc)">home</button>
  </div>
</div>
<div class="blind"></div>
<div class="map"><p class="loading">reading every service &mdash; the map is drawn from a live read of all of them, and appears as soon as the slowest one answers.</p>
<svg class="gr" role="img" aria-label="authorization paths"></svg>
<div class="hint">click a name to follow its routes · click a lit one to narrow · click it again to step back · Esc clears · scroll zooms · drag pans</div>
</div>
<div class="legend">
  <span style="color:var(--read)"><b>▭</b> human</span>
  <span style="color:var(--add)"><b>▭</b> service &middot; declared actor, not a login &middot; <b>┄</b> service account, the login it presents</span>
  <span style="color:var(--write)"><b>▭</b> role &middot; a hop others pass through</span>
  <span style="color:var(--grp)"><b>▭</b> group &middot; <b>┄</b> policy (S3)</span>
  <span><b>· ·</b> service instance &middot; n resources reached in it</span>
  <span class="sep"></span>
  <span style="color:var(--mem)"><b>→</b> member of a role / group</span>
  <span style="color:var(--grp)"><b>→</b> policy attached &middot; <b>┄→</b> policy scope</span>
  <span style="color:var(--read)"><b>→</b> read</span>
  <span style="color:var(--write)"><b>→</b> write</span>
  <span style="color:var(--admin)"><b>→</b> admin &middot; <b>- -</b> bridge, declared not discovered</span>
</div>
</section>
<script type="module" src="{1}"></script>""", _nav("/"), asset("map.js")), wide=True)
