"""Authorization paths — how authority reaches a resource, not just who holds it.

The matrix answers "who can touch what". It cannot answer "by what route", and the
route is where the surprises live:

  * A person rarely holds a grant directly. They hold a *role*, and the role holds the
    grant. Remove the person from one role and several resources go dark at once —
    the matrix shows the resources, never the hinge.
  * Some hops leave the system entirely. A researcher querying object storage through
    a database extension does not use their own storage credential; the server uses one
    it was configured with. Their database login is the only thing they present, yet
    the blast radius is that server-held key. Nothing in the grant tables says so, so
    those hops are declared (`[[bridges]]`) rather than discovered.

Nodes and edges come from the observed grant set — a grant on `role:X` is an edge into
node `X`, which may in turn hold grants of its own. No extra collection needed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

from .model import Grant

# What a node *is*. The adapters know account-vs-role (PostgreSQL's rolcanlogin,
# ClickHouse's user_name vs role_name, an S3 identity vs group vs policy). Whether an
# account is a person or a service nothing observes — that is the one thing the config
# says, as glob patterns (`[graph] services = ["svc-*", "airflow*"]`).
# `service` is a running thing that is not itself an account anywhere — Airflow's DAG
# runner, the pg_duckdb extension — known only because a bridge names it. A `svc-account`
# is the login such a thing presents to a system (svc-airflow, airflow_loader).
KINDS = ("human", "service", "svc-account", "role", "group", "policy")

# resource kinds that name another subject, i.e. a hop rather than a destination
_HOP_PREFIX = "role:"


@dataclass
class Edge:
    src: str
    dst: str
    system: str
    privs: set[str] = field(default_factory=set)
    kind: str = "grant"          # grant | bridge
    note: str = ""

    @property
    def label(self) -> str:
        if self.kind == "bridge":
            return self.note or "bridge"
        p = sorted(self.privs)
        return ", ".join(p[:3]) + (f" +{len(p) - 3}" if len(p) > 3 else "")


@dataclass
class Graph:
    edges: list[Edge]
    principals: set[str]         # leaf subjects — nothing grants *into* them
    hops: set[str]               # subjects that are also somebody's resource
    terminals: set[str]          # resources that are not subjects
    kind: dict[str, str] = field(default_factory=dict)   # node -> one of KINDS
    names: dict[str, str] = field(default_factory=dict)  # account -> the person's name
    envs: dict[str, tuple[str, ...]] = field(default_factory=dict)  # instance -> environments
    teams: dict[str, str] = field(default_factory=dict)  # account -> team it belongs to

    def env_of(self, system: str) -> tuple[str, ...]:
        """Which environments an instance serves. Unlisted: guessed from the name."""
        if system in self.envs:
            return self.envs[system]
        return ("staging",) if "staging" in system else ("prod",)

    def label(self, node: str) -> str:
        """`researcher_b (Example Researcher)` for a human with a known name; otherwise the node itself."""
        n = self.names.get(node)
        return f"{node} ({n})" if n else node

    def kind_of(self, node: str) -> str:
        return self.kind.get(node, "role" if node in self.hops else "human")

    def depth(self, node: str, _seen: frozenset[str] = frozenset()) -> int:
        """Longest hop distance from any principal. Cycles are cut, not followed."""
        if node in _seen:
            return 0
        parents = [e.src for e in self.edges if e.dst == node]
        if not parents:
            return 0
        return 1 + max(self.depth(p, _seen | {node}) for p in parents)

    def routes_from(self, subject: str, limit: int | None = None) -> list[list[str]]:
        """Every route that starts at `subject`, principal-first.

        F2 asks for *every distinct route*, not one — a subject often reaches the same
        resource two ways, and removing one role fixes nothing if the other remains.
        """
        out: list[list[str]] = []

        def walk(node: str, trail: list[str]) -> None:
            if (limit is not None and len(out) >= limit) or node in trail:
                return
            trail = [*trail, node]
            children = [e.dst for e in self.edges if e.src == node]
            if not children:
                if len(trail) > 1:
                    out.append(trail)
                return
            for c in children:
                walk(c, trail)

        walk(subject, [])
        return out

    def paths_to(self, terminal: str, limit: int | None = None) -> list[list[str]]:
        """Every route by which authority reaches `terminal` (principal-first)."""
        out: list[list[str]] = []

        def walk(node: str, trail: list[str]) -> None:
            if (limit is not None and len(out) >= limit) or node in trail:
                return
            trail = [node, *trail]
            parents = [e.src for e in self.edges if e.dst == node]
            if not parents:
                out.append(trail)
                return
            for p in parents:
                walk(p, trail)

        walk(terminal, [])
        return out


def build(grants: set[Grant], bridges: list[dict] | None = None,
          kinds: dict[str, str] | None = None,
          routes: list[tuple[str, str, str, str]] | None = None,
          services: tuple[str, ...] = ("svc-*",),
          names: dict[str, str] | None = None,
          envs: dict[str, tuple[str, ...]] | None = None,
          teams: dict[str, str] | None = None) -> Graph:
    """Collapse grant atoms into edges; a `role:` resource becomes a hop node."""
    # Bridge sources count as subjects. A bridge exists *because* the onward hop is
    # absent from the grant tables — if we only looked at grant subjects, the node a
    # bridge departs from would never be recognised as a hop and the chain would break
    # exactly where it matters most.
    routes = routes or []
    subjects = ({g.subject for g in grants} | {b["from"] for b in (bridges or [])}
                | {r[1] for r in routes} | {r[2] for r in routes if not r[2].startswith("bucket:")})
    merged: dict[tuple[str, str, str], Edge] = {}
    # An identity whose access comes through a policy is drawn through it — its flat
    # grants in that system would be the same lines twice.
    routed = {(r[0], r[1]) for r in routes}

    for g in grants:
        # `role:analytics_reader` is the node `analytics_reader` when that name is itself a
        # subject somewhere; otherwise it is a dead end and stays a terminal.
        dst = g.resource
        if dst.startswith(_HOP_PREFIX) and dst.removeprefix(_HOP_PREFIX) in subjects:
            dst = dst.removeprefix(_HOP_PREFIX)
        key = (g.subject, dst, g.system)
        # An identity whose access comes through a policy is *drawn* through it; its
        # flat grant is kept as kind "flat" — not a line on the map, but the only
        # place the grade (Read/Write) on each bucket survives, which the resources
        # column needs.
        kind = "flat" if (g.system, g.subject) in routed and not dst.startswith(_HOP_PREFIX) else "grant"
        merged.setdefault(key, Edge(g.subject, dst, g.system, kind=kind)).privs.add(g.priv)

    for system, src, dst, label in routes:
        merged.setdefault((src, dst, system), Edge(src, dst, system, kind="route", note=label))

    for b in bridges or []:
        # Declared, not discovered: no grant table records that a database extension
        # reaches storage with a server-held key.
        merged[(b["from"], b["to"], b.get("system", "*"))] = Edge(
            b["from"], b["to"], b.get("system", "*"), kind="bridge", note=b.get("note", ""))

    edges = list(merged.values())
    dsts = {e.dst for e in edges}
    srcs = {e.src for e in edges}
    kind: dict[str, str] = {}
    for n in srcs | dsts:
        k = (kinds or {}).get(n)
        is_svc = any(fnmatch(n, pat) for pat in services)
        if n.startswith("service:"):
            # A bridge may say `from = "service:airflow"`: the thing that runs DAGs, which
            # is not the PostgreSQL login also called airflow. The prefix keeps them apart.
            k = "service"
        elif k == "account":
            k = "svc-account" if is_svc else "human"
        elif k is None and n in srcs - dsts:
            # no system calls this an account: an actor declared by a bridge, or a
            # person whose account the observer could not classify
            k = "service" if is_svc else "human"
        if k in KINDS:
            kind[n] = k
    return Graph(
        edges=edges,
        principals=srcs - dsts,
        hops=srcs & dsts,
        terminals=dsts - srcs,
        kind=kind,
        names={k: v for k, v in (names or {}).items() if v},
        envs={k: tuple(v) for k, v in (envs or {}).items()},
        teams=dict(teams or {}),
    )
