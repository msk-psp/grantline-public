"""PostgreSQL adapter.

Knows the traps the catalog hides:
  * PUBLIC gets CONNECT and TEMPORARY on every database *by default* (when
    datacl is NULL). We surface those as source="implicit" grants so revoking
    only CONNECT can't silently leave TEMPORARY behind.
  * An owner whose relacl is an *empty array* (not NULL) has revoked itself —
    the "frozen ACL" state where even the owner can no longer use the table.
"""
from __future__ import annotations

from ..model import Finding, Grant, Unobserved
from . import Adapter, env, env_ready


def _ident(name: str, public: bool = False) -> str:
    if not name or any(ord(c) < 32 for c in name):
        raise ValueError("empty identifier or control character")
    return "PUBLIC" if public and name == "PUBLIC" else '"' + name.replace('"', '""') + '"'


def _priv(g: Grant) -> str:
    kind = g.resource.partition(":")[0]
    allowed = {"db": {"CONNECT", "CREATE", "TEMP", "TEMPORARY", "ALL"},
               "schema": {"USAGE", "CREATE", "ALL"},
               "table": {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN", "ALL"},
               "role": {"MEMBER"}}
    priv = g.priv.upper()
    if priv not in allowed.get("table" if kind == "default" else kind, set()):
        raise ValueError(f"unsupported privilege for {kind}: {g.priv}")
    return priv


def _target(g: Grant) -> tuple[str, str]:
    """-> (SQL target, trailing comment) — schema/table grants must run inside
    their database, which the statement itself cannot express."""
    kind, _, rest = g.resource.partition(":")
    if kind == "db":
        return f'DATABASE {_ident(rest)}', ""
    if kind == "schema":
        db, schema = rest.split(".", 1)
        _ident(db)
        return f'SCHEMA {_ident(schema)}', f"  -- in database {db}"
    if kind == "table":
        db, schema, table = rest.split(".", 2)
        _ident(db)
        return f'TABLE {_ident(schema)}.{_ident(table)}', f"  -- in database {db}"
    raise ValueError(f"unsupported postgres resource: {g.resource}")


def _default_priv(g: Grant, verb: str, to: str) -> str:
    scope, creator = g.resource.removeprefix("default:").rsplit("@", 1)
    db, schema = scope.split(".", 1)
    _ident(db)
    return (f'ALTER DEFAULT PRIVILEGES FOR ROLE {_ident(creator)} IN SCHEMA {_ident(schema)} '
            f"{verb} {_priv(g)} ON TABLES {to} {_ident(g.subject, public=True)};  -- in database {db}")


def grant_cmd(g: Grant) -> str:
    priv = _priv(g)
    if g.resource.startswith("role:"):
        return f'GRANT {_ident(g.resource.removeprefix("role:"))} TO {_ident(g.subject, public=True)};'
    if g.resource.startswith("default:"):
        return _default_priv(g, "GRANT", "TO")
    target, note = _target(g)
    return f"GRANT {priv} ON {target} TO {_ident(g.subject, public=True)};{note}"


def revoke_cmd(g: Grant) -> str:
    priv = _priv(g)
    if g.resource.startswith("role:"):
        return f'REVOKE {_ident(g.resource.removeprefix("role:"))} FROM {_ident(g.subject, public=True)};'
    if g.resource.startswith("default:"):
        return _default_priv(g, "REVOKE", "FROM")
    target, note = _target(g)
    return f"REVOKE {priv} ON {target} FROM {_ident(g.subject, public=True)};{note}"


def facts_findings(data: dict):
    for t in data.get("facts", {}).get("tables", []):
        if t.get("acl_empty"):
            yield Finding(
                "postgres", "frozen ACL (owner locked out)",
                f"{t['name']} (owner {t['owner']}): ACL is an empty array, so even the "
                f"owner has no privileges. Recover with an explicit "
                f"GRANT ALL ON {t['name']} TO \"{t['owner']}\";",
                entities=(t['name'], t['owner']),
            )


# ── live adapter (optional psycopg) ──────────────────────────────────────────
#
# One maintenance connection lists databases, memberships, and db-level ACLs;
# then each target database gets its own connection for schema/table/default-
# privilege ACLs — those live per-database and are invisible from outside.
# A database the observer cannot connect to is NOT an error: it is returned
# as an Unobserved scope, because "no access" and "could not check" are
# different facts and the matrix must show which one it is.

# coalesce(datacl, acldefault(...)) materializes the implicit PUBLIC defaults
# (CONNECT + TEMPORARY) that never show up as stored rows.
_DB_ACL_SQL = """
SELECT d.datname, coalesce(nullif(a.grantee::regrole::text, '-'), 'PUBLIC'),
       a.privilege_type, (d.datacl IS NULL) AS implicit, a.grantor::regrole::text
  FROM pg_database d, aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
 WHERE NOT d.datistemplate
"""

_DATABASES_SQL = "SELECT datname FROM pg_database WHERE NOT datistemplate"

# no `^pg_` filter here: pg_database_owner and friends are roles too, and an
# unclassified name falls back to a guess on the map
_ROLE_KIND_SQL = "SELECT rolname, rolcanlogin FROM pg_roles"

_MEMBERSHIP_SQL = """
SELECT m.rolname AS member, r.rolname AS role, gr.rolname AS grantor
  FROM pg_auth_members am
  JOIN pg_roles m ON m.oid = am.member
  JOIN pg_roles r ON r.oid = am.roleid
  LEFT JOIN pg_roles gr ON gr.oid = am.grantor
 WHERE m.rolname !~ '^pg_'
"""

# ⚠ `information_schema.role_table_grants` 를 쓰면 **읽기 전용 관찰자에게 남의 grant 가
#    안 보인다.** 그 뷰는 현재 활성 롤이 grantor 이거나 grantee 인 행만 돌려준다 —
#    비특권 계정으로 보면 다른 사람끼리의 grant 가 통째로 빠지고, 그 부재가 화면에서
#    '권한 없음' 으로 렌더된다. "확인 못 함 ≠ 권한 없음" 이라는 이 도구의 원칙을
#    어댑터가 안에서 어기는 셈이다.
#
#    `pg_class.relacl` 은 누구나 읽을 수 있다. db·schema ACL 이 이미 pg_catalog +
#    aclexplode 로 직접 읽고 있었는데(_DB_ACL_SQL·_SCHEMA_ACL_SQL) 테이블만 뷰를 쓰던
#    비일관이 원인이었다. 셋을 같은 방식으로 맞춘다.
#
#    relacl 이 NULL 이면 "소유자만" 이라는 뜻이라 acldefault 로 실체화한다 — db·schema
#    에 쓰는 것과 같은 처리다. 그래야 소유자 권한이 조용히 빠지지 않는다.
_TABLE_GRANT_SQL = """
SELECT coalesce(nullif(a.grantee::regrole::text, '-'), 'PUBLIC'),
       n.nspname, c.relname, a.privilege_type, (c.relacl IS NULL) AS implicit,
       a.grantor::regrole::text
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace,
       aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
 WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
   AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_'
"""

# same acldefault trick as databases: a NULL nspacl still implies privileges
_SCHEMA_ACL_SQL = """
SELECT n.nspname, coalesce(nullif(a.grantee::regrole::text, '-'), 'PUBLIC'),
       a.privilege_type, (n.nspacl IS NULL) AS implicit, a.grantor::regrole::text
  FROM pg_namespace n, aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_'
"""

# default privileges key on (database, schema, CREATING role) — all three matter
_DEFAULT_ACL_SQL = """
SELECT pg_get_userbyid(d.defaclrole), n.nspname,
       coalesce(nullif(a.grantee::regrole::text, '-'), 'PUBLIC'), a.privilege_type,
       a.grantor::regrole::text
  FROM pg_default_acl d
  JOIN pg_namespace n ON n.oid = d.defaclnamespace, aclexplode(d.defaclacl) a
 WHERE d.defaclobjtype = 'r'
"""

_FROZEN_ACL_SQL = """
SELECT n.nspname || '.' || c.relname, pg_get_userbyid(c.relowner)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r', 'v', 'm') AND c.relacl = '{}'::aclitem[]
"""


def _resource_db(g: Grant) -> str | None:
    """Which database a command must run in (None = any / maintenance DB)."""
    kind, _, rest = g.resource.partition(":")
    if kind in ("table", "schema", "default"):
        return rest.split(".", 1)[0].split("@", 1)[0]
    return None


class PostgresAdapter(Adapter):
    system = "postgres"
    privs = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES",
             "TRIGGER", "CREATE", "CONNECT", "TEMPORARY", "USAGE", "EXECUTE",
             "MEMBER", "ALL")

    def __init__(self, cfg: dict, system: str = "postgres"):
        self.cfg = cfg
        self.system = system

    def _connect(self, admin: bool = False, dbname: str | None = None, subject: str | None = None):
        try:
            import psycopg
        except ImportError:
            raise SystemExit("pip install 'grantline[postgres]' for a live PostgreSQL adapter")
        # observe uses the read-only DSN; only apply() ever touches the admin DSN
        kw = {"dbname": dbname} if dbname else {}
        credential = self.cfg.get("probe_dsn_envs", {}).get(subject) if subject else None
        dsn = env({"dsn": credential}, "dsn") if subject is not None else env(
            self.cfg, "admin_dsn_env" if admin else "dsn_env")
        if subject is not None:
            from psycopg.conninfo import conninfo_to_dict
            kw["connect_timeout"] = 10
            host = conninfo_to_dict(dsn).get("host", "")
            if not host or any(not h or h.startswith("/") for h in host.split(",")):
                raise ValueError("subject probes require a TCP host, not a local socket")
        return psycopg.connect(dsn, autocommit=True, **kw)

    def _targets(self, all_dbs: list[str]) -> list[str]:
        import fnmatch
        include = self.cfg.get("databases", ["*"])
        exclude = self.cfg.get("exclude_databases", [])
        return [d for d in all_dbs
                if any(fnmatch.fnmatch(d, p) for p in include)
                and not any(fnmatch.fnmatch(d, p) for p in exclude)]

    def _observe_db(self, db: str, grants: set[Grant], frozen: list[dict]) -> None:
        with self._connect(dbname=db) as conn:
            for grantee, schema, table, priv, implicit, grantor in conn.execute(_TABLE_GRANT_SQL):
                grants.add(Grant(self.system, grantee, f"table:{db}.{schema}.{table}", priv,
                                 "implicit" if implicit else "explicit", grantor))
            for schema, grantee, priv, implicit, grantor in conn.execute(_SCHEMA_ACL_SQL):
                grants.add(Grant(self.system, grantee, f"schema:{db}.{schema}", priv,
                                 "implicit" if implicit else "explicit", grantor))
            for creator, schema, grantee, priv, grantor in conn.execute(_DEFAULT_ACL_SQL):
                grants.add(Grant(self.system, grantee, f"default:{db}.{schema}@{creator}", priv,
                                 grantor=grantor))
            frozen += [{"name": f"{db}.{n}", "owner": o, "acl_empty": True}
                       for n, o in conn.execute(_FROZEN_ACL_SQL)]

    def observe(self):
        grants: set[Grant] = set()
        unobserved: list[Unobserved] = []
        frozen: list[dict] = []
        with self._connect() as conn:
            self.kinds = {"PUBLIC": "role"}
            for name, can_login in conn.execute(_ROLE_KIND_SQL):
                self.kinds[name] = "account" if can_login else "role"
            for member, role, grantor in conn.execute(_MEMBERSHIP_SQL):
                grants.add(Grant(self.system, member, f"role:{role}", "MEMBER", grantor=grantor))
            for datname, grantee, priv, implicit, grantor in conn.execute(_DB_ACL_SQL):
                grants.add(Grant(self.system, grantee, f"db:{datname}", priv,
                                 "implicit" if implicit else "explicit", grantor))
            all_dbs = [r[0] for r in conn.execute(_DATABASES_SQL)]

        import psycopg  # after _connect(): its ImportError message is friendlier
        for db in self._targets(all_dbs):
            try:
                self._observe_db(db, grants, frozen)
            except psycopg.OperationalError as exc:
                unobserved.append(Unobserved(
                    self.system,
                    (f"table:{db}.", f"schema:{db}.", f"default:{db}."),
                    f"observer cannot connect to database '{db}': "
                    f"{str(exc).strip().splitlines()[0]}"))
        findings = list(facts_findings({"facts": {"tables": frozen}}))
        return grants, findings, unobserved

    def probe(self, grants, write: bool = False):
        """Server-evaluated, not a login: has_*_privilege(subject, …) runs the same ACL
        evaluation the executor runs for that subject (inheritance included), asked from
        the observer's connection. It cannot see pg_hba, expired passwords, or a
        connection limit — optional `probe_dsn_envs` credentials add a real TCP login before the ACL check. `how` says
        exactly that, so a reader never mistakes this for the S3 probe's strength."""
        from ..probe import Probe
        HOW = "server-evaluated (has_*_privilege), not a login"
        out: list[Probe] = []
        by_db: dict[tuple[str | None, str | None], list[Grant]] = {}
        for g in grants:
            subject = g.subject if g.subject in self.cfg.get("probe_dsn_envs", {}) else None
            db = g.resource.removeprefix("db:") if subject and g.resource.startswith("db:") else _resource_db(g)
            by_db.setdefault((db, subject), []).append(g)
        for (db, subject), gs in by_db.items():
            try:
                conn = self._connect(dbname=db, subject=subject) if subject else self._connect(dbname=db)
            except (Exception, SystemExit) as exc:
                out += [Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                              f"cannot connect to {db or 'maintenance db'}: {type(exc).__name__}") for g in gs]
                continue
            with conn:
                how = HOW
                if subject:
                    try:
                        user = conn.execute("SELECT session_user, current_user").fetchone()
                        if not user or tuple(user) != (subject, subject):
                            raise ValueError("credential does not log in as the requested subject")
                    except Exception:
                        out += [Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                                      "subject login identity could not be verified") for g in gs]
                        continue
                    how = "subject TCP login + server-evaluated ACL (no data read or write)"
                for g in sorted(gs, key=lambda g: (g.subject, g.resource, g.priv)):
                    kind, _, rest = g.resource.partition(":")
                    subj = None if g.subject == "PUBLIC" else g.subject
                    try:
                        if kind == "role":
                            row = conn.execute("SELECT pg_has_role(%s, %s, 'MEMBER')", (subj, rest)).fetchone()
                        elif kind == "db":
                            row = conn.execute("SELECT has_database_privilege(%s, %s, %s)", (subj, rest, g.priv)).fetchone()
                        elif kind == "schema":
                            row = conn.execute("SELECT has_schema_privilege(%s, %s, %s)", (subj, rest.split(".", 1)[1], g.priv)).fetchone()
                        elif kind == "table":
                            _, schema, table = rest.split(".", 2)
                            row = conn.execute("SELECT has_table_privilege(%s, %s, %s)",
                                               (subj, f'"{schema}"."{table}"', g.priv)).fetchone()
                        else:
                            out.append(Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                                             f"no server-side evaluator for {kind}: resources")); continue
                        if subj is None:  # PUBLIC has no role to ask about
                            out.append(Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                                             "PUBLIC is not a role has_*_privilege can be asked about")); continue
                        out.append(Probe(g.system, g.subject, g.resource, g.priv,
                                         "allow" if row and row[0] else "deny", how))
                    except Exception as exc:
                        out.append(Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                                         f"evaluation failed: {str(exc).splitlines()[0]}"))
        return out

    grant_cmd = staticmethod(grant_cmd)
    revoke_cmd = staticmethod(revoke_cmd)

    def write_ready(self):
        return env_ready(self.cfg, "admin_dsn_env")

    def apply(self, change):
        # Each command is routed to the database it belongs to: GRANT ... ON
        # DATABASE works from anywhere, but schema/table/default-privilege
        # statements only exist inside their database. Connections are
        # autocommit, so statements that refuse transaction blocks (e.g.
        # CREATE DATABASE, if a future version plans one) also run fine.
        with self._connect(admin=True, dbname=_resource_db(change.grant)) as conn:
            conn.execute(change.cmd.split("  --")[0])
