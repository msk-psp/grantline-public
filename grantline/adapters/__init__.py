"""Adapter registry + the fixture adapter used for demo / tests.

An adapter answers three questions for one system:
  observe()      -> what is actually on the server: (Grants, Findings,
                    Unobserved scopes the observer could not read — "could not
                    check" is a fact, distinct from "no access")
  grant_cmd(g) / revoke_cmd(g) -> the *native* command that would create/remove it
  apply(change)  -> execute that native command (only ever called with --write)

Native enforcement stays where it is — the tool never becomes a second
authorization plane; it only speaks each system's own GRANT/REVOKE dialect.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..model import Finding, Grant, Unobserved


class Adapter:
    system: str
    # Filled by observe() when the system can tell: subject -> "account" | "role" |
    # "group" | "policy". The map colours by it; nothing else reads it.
    kinds: dict[str, str] = {}
    # Structural hops the grant table flattens away (an S3 identity's group, the
    # policy the group attaches). Map-only: (system, src, dst, label).
    routes: list[tuple[str, str, str, str]] = []
    # The dialect's privilege vocabulary, for the change form's dropdown. Observed
    # privileges alone would only ever offer what someone already holds, so the first
    # INSERT anywhere could not be picked from a list.
    privs: tuple[str, ...] = ()

    def observe(self) -> tuple[set[Grant], list[Finding], list[Unobserved]]:
        raise NotImplementedError

    def grant_cmd(self, g: Grant) -> str:
        raise NotImplementedError

    def coalesce(self, changes: list) -> list:
        """Fold changes that one command can carry out together.

        Default: none — one grant, one command, which is true of `GRANT`/`REVOKE`.
        A system whose unit of change is a *document* (S3 IAM policies) overrides
        this, or the plan reads as N times the work it is and apply writes the
        same document N times.
        """
        return changes

    def revoke_cmd(self, g: Grant) -> str:
        raise NotImplementedError

    def apply(self, change) -> None:
        raise NotImplementedError

    def probe(self, grants, write: bool = False):
        """N4. Default: this adapter cannot ask the service as the subject — every row is
        `unknown`, with the reason. Never fabricate allow/deny from the table."""
        from ..probe import Probe
        return [Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                      f"no login-path probe for {type(self).__name__}")
                for g in sorted(grants, key=lambda g: (g.subject, g.resource, g.priv))]

    def refuse_write(self, g: Grant, action: str) -> str:
        """Why this write must not run, though the command itself is well-formed.
        Empty string = no objection.

        `write_scope = "roles"` narrows the console to **role membership**, and the
        point of the narrowing is the credential it buys. To hand out an arbitrary
        privilege, a writer must hold that privilege itself — that is the rule in both
        PostgreSQL (ownership or grant option) and ClickHouse ("you may grant privileges
        of the same scope you have"). "May grant anything" therefore means "holds
        everything", and no amount of splitting accounts changes that arithmetic.

        Membership is the exception: ClickHouse `ROLE ADMIN` and a PostgreSQL NOINHERIT
        role with ADMIN OPTION both grant and revoke roles while holding **no data
        access at all**. So the console gives up expressing direct object grants, and in
        exchange its credential stops being an administrator's.

        Refused here rather than at the command builder, so the operator still sees the
        statement that would have run. "Here is the command, and here is why this console
        will not be the one to run it" is a smaller surprise than a blank screen.
        """
        if getattr(self, "cfg", {}).get("write_scope") != "roles":
            return ""
        if g.resource.startswith("role:"):
            return ""
        return (f"this console writes role membership only on {self.system}, and "
                f"'{g.resource}' is not a role. That is a deliberate limit: its "
                f"credential holds no data access, and it could not hold the "
                f"privilege to hand out without holding the privilege itself. "
                f"Put the access in a role and {action} the role — or use the "
                f"service's own client for a one-off direct grant.")

    def write_ready(self) -> tuple[bool, str]:
        """(can this adapter write, and why/why not) — **without resolving anything.**

        N1 says a read path never resolves the write credential, and the console
        asks this question on every page render. So the answer is decided by the
        shape of the config plus the *existence* of an environment variable; the
        value is read inside apply(), at the moment of the write. The note is
        shown to the operator, so it may name the variable but never its content.
        """
        return False, "this adapter has no write path configured."


class FixtureAdapter(Adapter):
    """Reads observed state from a JSON file; apply() mutates the file.

    This makes the whole plan->apply->re-observe convergence loop runnable
    with zero infrastructure, and doubles as the test double.
    """

    def __init__(self, system: str, path: str | Path, cmds, facts_findings=None):
        self.system = system
        self.path = Path(path)
        self._grant_cmd, self._revoke_cmd = cmds
        self._facts_findings = facts_findings

    def _load(self) -> dict:
        return json.loads(self.path.read_text())

    def observe(self):
        data = self._load()
        grants = {
            Grant(self.system, g["subject"], g["resource"], g["priv"], g.get("source", "explicit"),
                  g.get("grantor"))
            for g in data.get("grants", [])
        }
        # 실제 어댑터가 서버에서 읽어 오는 것(계정이냐 롤이냐)을 픽스처는 파일에 적는다.
        # 없으면 비워 두고, 지도가 이름으로 추측한다.
        self.kinds = dict(data.get("kinds", {}))
        findings = list(self._facts_findings(data)) if self._facts_findings else []
        unobserved = [Unobserved(self.system, tuple(u["prefixes"]), u["note"], tuple(u.get("subjects", ())))
                      for u in data.get("unobserved", [])]
        return grants, findings, unobserved

    def grant_cmd(self, g):
        return self._grant_cmd(g)

    def revoke_cmd(self, g):
        return self._revoke_cmd(g)

    def write_ready(self):
        return _file_ready(self.path, f"fixture file {self.path}")

    def apply(self, change):
        data = self._load()
        rec = {"subject": change.grant.subject, "resource": change.grant.resource,
               "priv": change.grant.priv}
        grants = [g for g in data.get("grants", [])
                  if not all(g.get(k) == v for k, v in rec.items())]
        if change.action == "grant":
            grants.append(rec)
        data["grants"] = grants
        self.path.write_text(json.dumps(data, indent=2) + "\n")


def env_ready(cfg: dict, key: str) -> tuple[bool, str]:
    """Is the write credential *named and present*? Presence only — see write_ready()."""
    var = cfg.get(key)
    if not var:
        return False, (f"read-only here: the config names no '{key}', so nothing tells "
                       f"this tool which credential may write.")
    if var not in os.environ:
        return False, (f"read-only here: the config names {var} for writes, but that "
                       f"environment variable is not set in this process.")
    return True, f"writes will use the credential in ${var}."


def _file_ready(path, what: str) -> tuple[bool, str]:
    """A plane backed by a local file writes if the file is writable."""
    ok = os.access(path, os.W_OK)
    return ok, (f"writes go to {what}." if ok
                else f"read-only here: {what} is not writable by this process.")


def env(cfg: dict, key: str) -> str:
    """Resolve '<key>_env' in adapter config to its environment variable value.
    Credentials never live in config files."""
    var = cfg.get(key)
    if not var:
        raise SystemExit(f"adapter config missing '{key}' (env var name)")
    val = os.environ.get(var)
    if not val:
        # 자격을 설정 파일에 두지 않는 것이 원칙이라면, **어디에 두는지**는 도구가
        # 말해야 한다. 이 메시지가 없을 때는 `serve.sh` 같은 저장소 밖 래퍼를 아는
        # 사람만 CLI 를 쓸 수 있었다.
        raise SystemExit(
            f"environment variable {var} is not set.\n"
            f"Credentials never live in the config — the config only names the variable.\n"
            f"Set it for this command, or put the exports in a launcher next to your config:\n"
            f"    {var}=… grantline -c <config> <command>\n"
            f"See `env_file` in the config to have grantline read them from a file instead.")
    return val


def build(system: str, cfg: dict) -> Adapter:
    """`system` is the config section name — the instance ("clickhouse-staging").
    `type` is the adapter; for fixtures, `kind` says which dialect the fixture speaks
    (default: the section name, so `[adapters.postgres]` with `type = "fixture"` keeps
    working). Several sections may share a type: that is how prod and staging of the
    same system sit side by side without merging."""
    from ..model import register_kind
    from . import clickhouse, postgres, s3

    typ = cfg.get("type", system)
    kind = cfg.get("kind", system if typ == "fixture" else typ)
    register_kind(system, kind)
    if typ == "fixture":
        mod = {"postgres": postgres, "clickhouse": clickhouse}.get(kind)
        if mod is None:
            raise SystemExit(f"fixture adapter '{system}': kind must be postgres or clickhouse, got '{kind}'")
        return FixtureAdapter(system, cfg["fixture"], (mod.grant_cmd, mod.revoke_cmd),
                              getattr(mod, "facts_findings", None))
    if typ == "postgres":
        return postgres.PostgresAdapter(cfg, system)
    if typ == "clickhouse":
        return clickhouse.ClickHouseAdapter(cfg, system)
    if typ == "s3":
        return s3.S3ConfigAdapter(cfg, system)
    raise SystemExit(f"unknown adapter type '{typ}' for system '{system}'")
