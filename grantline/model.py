"""Normalized permission model shared by all adapters.

One Grant = one (system, subject, resource, priv) atom. Sets of Grants are the
whole data model: intent is a set, observed reality is a set, drift is set
difference. `source` is metadata (implicit defaults, policy-derived) and is
deliberately excluded from equality — an implicit grant that matches a declared
one is not drift.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Resource naming convention (string, adapter-interpreted):
#   role:<name>                 role/group membership        priv: MEMBER
#   db:<name>                   database scope               priv: CONNECT, TEMPORARY, SELECT, ...
#   schema:<db>.<schema>        schema scope                 priv: USAGE, CREATE
#   table:<db>.<schema>.<name>  table scope                  priv: SELECT, INSERT, ...
#   default:<db>.<schema>@<creator_role>   PostgreSQL default privileges
#   bucket:<bucket>[/<prefix>*] object storage scope         priv: Read, Write, List, Admin


# system = the *instance* a grant belongs to ("postgres", "clickhouse-staging"); kind =
# the adapter type that instance is ("postgres", "clickhouse", "s3"). One deployment
# holds prod and staging of the same kind side by side, and the two must never merge:
# a grant on staging ClickHouse is not a grant on production ClickHouse. Everything
# that depends on the *dialect* (canonical spelling, subsumption rules, lint) asks
# kind_of(); everything that depends on *identity* (equality, pages, intent) uses the
# instance name. The registry is filled when adapters are built; an unregistered name
# is its own kind, so demos and tests that name instances after their kind still work.
KINDS: dict[str, str] = {}


def register_kind(system: str, kind: str) -> None:
    KINDS[system] = kind


def kind_of(system: str) -> str:
    return KINDS.get(system, system)


def canonical(system: str, resource: str) -> str:
    """One spelling per scope, so equality means equality.

    Object-storage prefixes have two idiomatic spellings for the same set of keys:
    SeaweedFS writes native actions as `Read:personal/researcher_a`, while IAM-style policy
    documents write `personal/researcher_a/*`. They denote the same objects — the prefix is
    recursive either way.

    Left alone, this looked exactly like subsumption: 88 declared grants "already
    covered by a broader grant" that was in fact the same grant, spelled differently.
    A mismatch dressed up as coverage is worse than either, because it hides in the
    findings the steward is meant to read. Normalise at the boundary; let subsumption
    report only genuine breadth.
    """
    if kind_of(system) == "s3" and resource.startswith("bucket:"):
        body = resource.removeprefix("bucket:")
        if body != "*":
            body = body.rstrip("*").rstrip("/") or "*"
        return "bucket:" + body
    return resource


@dataclass(frozen=True)
class Grant:
    system: str
    subject: str
    resource: str
    priv: str
    source: str = field(default="explicit", compare=False)  # explicit|implicit|policy
    # Who granted it, where the source records that (PostgreSQL does — pg_auth_members.grantor,
    # aclitem's grantor; ClickHouse and S3 identity documents do not). Metadata like `source`:
    # excluded from equality, because the *same* grant is the same grant whoever gave it.
    # None means "the source does not say", never "nobody" — a page must not imply authorship
    # it cannot back (PRD 003 F1 known gap; closed by this field).
    grantor: str | None = field(default=None, compare=False)

    def __post_init__(self):
        # Canonicalise here, not at the loaders. A Grant assembled anywhere — an intent
        # file, an adapter, a form in the web UI — must compare equal to the same grant
        # read back from the server, or F3's round-trip ("grant then revoke returns the
        # system to its prior observed state") silently fails on spelling alone.
        r = canonical(self.system, self.resource)
        if r != self.resource:
            object.__setattr__(self, "resource", r)


# Built-in diagnostic kinds have stable titles; custom findings may set a level.
_FINDING_LEVELS = {
    "already covered by a broader grant": "info",
    "deny without a matching allow": "info",
    "unobserved scope": "error",
    "system could not be read": "error",
    "auth plane unreachable": "error",
    "policy document missing": "error",
    "policy evaluation incomplete": "error",
    "policy statement with an unknown effect": "error",
    "identity missing from the enforced plane": "error",
    "frozen ACL (owner locked out)": "error",
    "granted on paper, denied on the path": "error",
    "reachable, but no grant explains it": "error",
}


@dataclass(frozen=True)
class Finding:
    system: str
    title: str
    detail: str
    level: str = ""

    def __post_init__(self):
        if not self.level:
            object.__setattr__(self, "level", _FINDING_LEVELS.get(self.title, "warning"))
        if self.level not in ("info", "warning", "error"):
            raise ValueError("finding level must be info, warning or error")


@dataclass(frozen=True)
class Unobserved:
    """A scope the observer could not read (a database it cannot connect to,
    an IAM endpoint that is down). Distinct from "no grants": inside an
    unobserved scope the truth is unknown, so the diff must not plan grants
    or revokes there, and the matrix shows '?' instead of '—'."""
    system: str
    prefixes: tuple[str, ...]  # resource prefixes covered, e.g. ("table:hr.",)
    note: str

    subjects: tuple[str, ...] = ()  # empty = all subjects (legacy snapshots)

    def covers(self, g: Grant) -> bool:
        scope = any(g.resource.startswith(p) if not p.startswith("bucket:") or p == "bucket:"
                    else g.resource == p or g.resource.startswith(p + "/")
                    for p in self.prefixes)
        return g.system == self.system and scope and (not self.subjects or g.subject in self.subjects)


WRITE_PRIVS = {"INSERT", "UPDATE", "DELETE", "TRUNCATE", "CREATE", "TEMPORARY",
               "ALTER", "DROP", "Write", "WRITE"}
ADMIN_PRIVS = {"ALL", "OWNER", "ADMIN", "Admin", "GRANT"}


def level(privs: set[str]) -> str:
    """Collapse a priv set into a display grade for the matrix."""
    if not privs:
        return "none"
    if privs & ADMIN_PRIVS:
        return "admin"
    if privs & WRITE_PRIVS:
        return "write"
    return "read"
