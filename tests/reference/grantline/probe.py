"""N4 — verify on the real auth path.

A grant table says what *should* be reachable. A probe asks the service itself, as the
subject, whether it *is*. The two disagree more often than anyone expects: a policy that
was never applied, a role the server dropped, a plane the gateway does not consult. Every
wrong answer this tool has given so far was a case of trusting the table.

Three verdicts, never two (PRD 003 F6): `allow`, `deny`, and `unknown` — the adapter had
no way to ask, or asked and got no answer. `unknown` is reported with *why*, and never
rendered as either of the others.

What each adapter can honestly probe:
  s3        the real thing — the subject's own key against the real endpoint (List, Read;
            Write only on request, and it cleans up after itself)
  postgres  server-evaluated: has_*_privilege(subject, …) runs the same ACL evaluation the
            executor runs, but it is not a login. Labelled as such.
  clickhouse server-resolved: effective SHOW GRANTS; optional subject HTTP login.

PostgreSQL/ClickHouse can use explicitly configured subject credentials. These verify
login and effective privileges, without reading rows or attempting writes.
"""
from __future__ import annotations

from dataclasses import dataclass

from .model import Finding, Grant


@dataclass(frozen=True)
class Probe:
    system: str
    subject: str
    resource: str
    priv: str
    verdict: str   # allow | deny | unknown
    how: str       # what was actually tried, in one line


def run(adapters: dict, observed: set[Grant], subjects: set[str] | None = None,
        systems: set[str] | None = None, write: bool = False) -> tuple[list[Probe], list[Finding]]:
    probes: list[Probe] = []
    for name, adapter in adapters.items():
        if systems and name not in systems:
            continue
        mine = {g for g in observed if g.system == name and (not subjects or g.subject in subjects)}
        if not mine:
            continue
        probes += adapter.probe(mine, write=write)
    return probes, compare(probes, observed)


def compare(probes: list[Probe], observed: set[Grant]) -> list[Finding]:
    """Where the path and the table disagree. Only definite verdicts count — an
    `unknown` is neither agreement nor disagreement."""
    on_paper = {(g.system, g.subject, g.resource, g.priv) for g in observed}
    out: list[Finding] = []
    for p in probes:
        key = (p.system, p.subject, p.resource, p.priv)
        if p.verdict == "deny" and key in on_paper:
            out.append(Finding(p.system, "granted on paper, denied on the path",
                               f"{p.subject} holds {p.priv} on {p.resource} in the grant table, "
                               f"but the probe was refused ({p.how}). The table is wrong or the "
                               f"path consults something the table does not show.",
                               entities=(p.subject, p.priv, p.resource)))
        elif p.verdict == "allow" and key not in on_paper:
            out.append(Finding(p.system, "reachable, but no grant explains it",
                               f"{p.subject} can {p.priv} on {p.resource} ({p.how}) and no observed "
                               f"grant says so. Something outside the table confers it.",
                               entities=(p.subject, p.priv, p.resource)))
    return out


def summary(probes: list[Probe]) -> dict[str, int]:
    out = {"allow": 0, "deny": 0, "unknown": 0}
    for p in probes:
        out[p.verdict] += 1
    return out
