"""ClickHouse adapter (HTTP interface, stdlib urllib — no driver needed).

ClickHouse has no DENY: the only way to block is to not grant. Worse, grants
are not garbage-collected — DROP DATABASE leaves db-scoped grants in the
catalog, ready to spring back to life if the name is reused. observe() flags
those stale grants so the convergence plan revokes them by name.
"""
from __future__ import annotations

import re
import urllib.parse
import urllib.request

from ..model import Finding, Grant, Unobserved
from . import Adapter, env, env_ready


def _on(g: Grant) -> str:
    kind, _, rest = g.resource.partition(":")
    if kind == "db":
        return f"ON {_ident(rest)}.*"
    if kind == "table":
        db, table = rest.split(".", 1)
        return f"ON {_ident(db)}.{_ident(table)}"
    raise ValueError(f"unsupported clickhouse resource: {g.resource}")


def grant_cmd(g: Grant) -> str:
    priv = _priv(g)
    if g.resource.startswith("role:"):
        return f'GRANT {_ident(g.resource.removeprefix("role:"))} TO {_ident(g.subject)};'
    return f"GRANT {priv} {_on(g)} TO {_ident(g.subject)};"


def revoke_cmd(g: Grant) -> str:
    priv = _priv(g)
    if g.resource.startswith("role:"):
        return f'REVOKE {_ident(g.resource.removeprefix("role:"))} FROM {_ident(g.subject)};'
    return f"REVOKE {priv} {_on(g)} FROM {_ident(g.subject)};"


def stale_grant_findings(grants: set[Grant], databases: list[str]):
    """Grants scoped to databases that no longer exist."""
    live = set(databases)
    stale: dict[tuple[str, str], list[str]] = {}
    for g in grants:
        if g.resource.startswith("db:") and g.resource.removeprefix("db:") not in live:
            stale.setdefault((g.subject, g.resource), []).append(g.priv)

    # One finding per (subject, resource), not per privilege. A dropped database
    # typically leaves dozens of privileges behind — emitting one line each buries
    # every other finding under a wall of near-identical text (observed on a real
    # cluster: a single dropped database produced ~60 lines, and the run produced
    # 2170 findings in total, which is the same as producing none).
    for (subject, resource), privs in sorted(stale.items()):
        shown = ", ".join(sorted(privs)[:6])
        more = f" (+{len(privs) - 6} more)" if len(privs) > 6 else ""
        yield Finding(
            "clickhouse", "stale grants on dropped database",
            f"{subject} still holds {len(privs)} privilege(s) on {resource} but the "
            f"database is gone: {shown}{more}. ClickHouse keeps them; they re-apply if "
            f"the name returns. Revoke by name.",
        )


def facts_findings(data: dict):
    grants = {Grant("clickhouse", g["subject"], g["resource"], g["priv"])
              for g in data.get("grants", [])}
    return stale_grant_findings(grants, data.get("facts", {}).get("databases", []))


def _ident(name: str) -> str:
    if not name or any(ord(c) < 32 for c in name):
        raise ValueError("empty identifier or control character")
    return "`" + name.replace("\\", "\\\\").replace("`", "\\`") + "`"


def _priv(g: Grant) -> str:
    priv = g.priv.upper()
    allowed = {"MEMBER"} if g.resource.startswith("role:") else {
        "SELECT", "INSERT", "ALTER", "CREATE", "DROP", "SHOW", "OPTIMIZE", "DICTGET", "ALL"}
    if priv not in allowed:
        raise ValueError(f"unsupported privilege: {g.priv}")
    return "dictGet" if priv == "DICTGET" else priv


_GRANT_RE = re.compile(r"^GRANT (?P<what>.+?) ON (?P<scope>\S+) TO ", re.I)
_ROLE_RE = re.compile(r"^GRANT (?P<roles>.+?) TO (?P<who>\S+)$", re.I)


def parse_show_grants(lines: list[str]) -> set[tuple[str, str, str]]:
    """`SHOW GRANTS FOR x WITH IMPLICIT FINAL` lines → {("priv", PRIV, scope) | ("role", NAME, "")}.

        GRANT SELECT, SHOW ON research_silver.* TO researcher_b    →  ("priv","SELECT","db:research_silver"), ("priv","SHOW",…)
        GRANT SELECT ON research_meta.runs TO researcher_b         →  ("priv","SELECT","table:research_meta.runs")
        GRANT READ ON S3 TO researcher_b                       →  ("priv","READ","global:S3")
        GRANT research_reader TO researcher_b                      →  ("role","research_reader","")
    Scope spellings follow the adapter's resource convention so subsumption can compare."""
    out: set[tuple[str, str, str]] = set()
    for line in lines:
        line = line.strip().rstrip(";")
        m = _GRANT_RE.match(line)
        if m:
            scope = m.group("scope").strip("`")
            if scope == "*.*":
                res = "global:*"
            elif scope.endswith(".*"):
                res = "db:" + scope[:-2].strip("`")
            elif "." in scope:
                res = "table:" + scope.replace("`", "")
            else:
                res = "global:" + scope
            # column lists carry commas of their own: SELECT(a, b), INSERT(c) → strip
            # the parentheses first, then split on the commas that separate privileges
            for pr in re.sub(r"\([^)]*\)", "", m.group("what")).split(","):
                pr = pr.strip()
                if pr:
                    out.add(("priv", pr.upper(), res))
            continue
        m = _ROLE_RE.match(line)
        if m and " ON " not in line:
            for r in m.group("roles").split(","):
                r = r.strip().strip("`")
                if r and not r.upper().startswith("WITH "):
                    out.add(("role", r, ""))
    return out


class ClickHouseAdapter(Adapter):
    system = "clickhouse"
    privs = ("SELECT", "INSERT", "ALTER", "CREATE", "DROP", "SHOW", "OPTIMIZE",
             "dictGet", "MEMBER", "ALL")

    def __init__(self, cfg: dict, system: str = "clickhouse"):
        self.system = system
        self.cfg = cfg

    def _query(self, sql: str, admin: bool = False, key: str | None = None) -> list[list[str]]:
        # url_env e.g. GRANTLINE_CH_URL = http://reader:pass@host:8123
        # admin_url_env is used only by apply(); `key` names another read credential
        # (probe_url_env) and falls back to url_env when the config does not have it
        if key and not self.cfg.get(key):
            key = None
        raw = env(self.cfg, key or ("admin_url_env" if admin else "url_env"))
        u = urllib.parse.urlsplit(raw)
        url = f"{u.scheme}://{u.hostname}:{u.port or 8123}/?" + urllib.parse.urlencode(
            {"user": u.username or "default", "password": u.password or "", "query": sql})
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                body = r.read().decode()
        except urllib.error.HTTPError as exc:
            # ClickHouse 는 거절 이유를 **본문에** 담는다. 상태 코드만 올리면
            # 화면에 남는 것이 "HTTP Error 500" 뿐이고, 그건 무엇을 고쳐야 하는지
            # 아무것도 말해주지 않는다. 자격은 URL 안에 있으므로 본문만 옮긴다.
            detail = ""
            try:
                detail = exc.read().decode(errors="replace").strip()
            except Exception:
                pass
            first = detail.splitlines()[0] if detail else ""
            raise RuntimeError(f"HTTP {exc.code}: {first or exc.reason}") from None
        return [line.split("\t") for line in body.splitlines() if line]

    def probe(self, grants, write: bool = False):
        """Server-resolved, not a login. ClickHouse cannot evaluate access *as* another
        user, but `SHOW GRANTS FOR <user> WITH IMPLICIT FINAL` makes the server itself
        flatten roles, inheritance and wildcards into the effective set — its resolution,
        not this tool's. That needs `SHOW USERS` (or SHOW ACCESS) on the observer; without
        it every row is `unknown` with that reason. A dedicated `probe_url_env` may carry
        that credential; otherwise the observer's is tried."""
        from ..probe import Probe
        from ..subsume import _scope_covers
        HOW = "server-resolved (SHOW GRANTS … WITH IMPLICIT FINAL), not a login"
        out: list[Probe] = []
        by_subject: dict[str, list] = {}
        for g in grants:
            by_subject.setdefault(g.subject, []).append(g)
        for subject, gs in sorted(by_subject.items()):
            how = HOW
            subject_login = subject in self.cfg.get("probe_url_envs", {})
            credential = self.cfg.get("probe_url_envs", {}).get(subject)
            try:
                if subject_login:
                    login = ClickHouseAdapter({"url_env": credential}, self.system)
                    user = login._query("SELECT currentUser() LIMIT 1 SETTINGS max_execution_time = 10")
                    if user != [[subject]]:
                        raise ValueError("credential does not log in as the requested subject")
                    rows = login._query("SHOW GRANTS WITH IMPLICIT FINAL")
                    how = "subject HTTP login + server-resolved grants (no data read or write)"
                else:
                    rows = self._query(f"SHOW GRANTS FOR {_ident(subject)} WITH IMPLICIT FINAL", key="probe_url_env")
            except (Exception, SystemExit) as exc:
                note = "subject login could not be verified (" + type(exc).__name__ + ")" if subject_login else str(exc).splitlines()[0]
                if "SHOW USERS" in note or "SHOW ACCESS" in note or "497" in note:
                    note = "observer lacks SHOW USERS (grant SHOW ACCESS ON *.*, or set probe_url_env)"
                out += [Probe(g.system, g.subject, g.resource, g.priv, "unknown", note) for g in gs]
                continue
            effective = parse_show_grants([r[0] for r in rows if r])
            for g in sorted(gs, key=lambda g: (g.resource, g.priv)):
                if g.resource.startswith("role:"):
                    ok = ("role", g.resource.removeprefix("role:"), "") in effective
                else:
                    ok = any(kind == "priv" and (pr == g.priv or pr == "ALL")
                             and _scope_covers(self.system, scope, g.resource)
                             for kind, pr, scope in effective)
                out.append(Probe(g.system, g.subject, g.resource, g.priv, "allow" if ok else "deny", how))
        return out

    def observe(self):
        # A server we cannot reach or authenticate to is **not** a server with no
        # grants. Letting the exception escape kills the request and prints a stack
        # trace; swallowing it into an empty set is worse — the matrix would render a
        # column of '—' that reads as "nobody has access". Both are wrong; the honest
        # answer is "unknown", which is what Unobserved means.
        #
        # This bites in a mundane way: a staging password against a production host
        # returns 403, and the whole page dies rather than saying which system it was.
        try:
            return self._observe()
        except Exception as ex:
            note = f"{type(ex).__name__}: {ex}"
            return set(), [Finding(
                self.system, "system could not be read",
                f"{note}. Everything in '{self.system}' is unknown, not empty — check the "
                f"endpoint and that the credential belongs to *this* server "
                f"(a credential from another environment authenticates nowhere and "
                f"surfaces as 403).",
            )], [Unobserved(self.system, ("",), note)]

    def _observe(self):
        grants: set[Grant] = set()
        # system.users / system.roles need SHOW USERS; the grant rows already say which
        # column a name came from, and the observer can read those.
        self.kinds = {}
        for user, role in self._query(
                "SELECT user_name, granted_role_name FROM system.role_grants "
                "WHERE user_name != '' FORMAT TSV"):
            grants.add(Grant(self.system, user, f"role:{role}", "MEMBER"))
            self.kinds[user] = "account"; self.kinds[role] = "role"
        # ⚠ `WHERE database != ''` 로 거르면 **전역 grant 가 통째로 사라진다.**
        #    `GRANT SELECT ON *.*` 은 database 가 비어 있어 그 필터에 탈락하는데,
        #    그건 이 서버에서 가장 강한 권한이다. 앞 페이지에 안 보이는 것이 하필
        #    가장 넓은 것이 된다.
        #
        #    table 컬럼도 함께 읽는다. 전엔 SELECT 목록에 없어서 테이블 단위 grant 가
        #    DB 단위로 뭉개졌다 — 실제보다 넓게 보고하는 쪽이라 더 나쁘다.
        for subject, is_user, access, db, table in self._query(
                "SELECT coalesce(user_name, role_name), user_name IS NOT NULL, access_type, "
                "coalesce(database, ''), coalesce(table, '') "
                "FROM system.grants FORMAT TSV"):
            self.kinds.setdefault(subject, "account" if is_user == "1" else "role")
            if not db:
                resource = "global:*"      # ON *.* — 모델에 담되 이름으로 구분한다
            elif table:
                resource = f"table:{db}.{table}"
            else:
                resource = f"db:{db}"
            grants.add(Grant(self.system, subject, resource, access))
        databases = [r[0] for r in self._query("SHOW DATABASES FORMAT TSV")]
        return grants, list(stale_grant_findings(grants, databases)), []

    grant_cmd = staticmethod(grant_cmd)
    revoke_cmd = staticmethod(revoke_cmd)

    def write_ready(self):
        return env_ready(self.cfg, "admin_url_env")

    def apply(self, change):
        self._query(change.cmd.rstrip(";"), admin=True)
