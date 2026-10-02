"""Does a grant the subject already holds satisfy one the intent asks for?

N5. Set difference over strings reports `SELECT on table:analytics.public.x` as missing
while the server holds `SELECT on db:analytics` — and on ClickHouse that database grant
already covers the table. The front page fills with grants that would be no-ops, and
a page full of no-ops is a page nobody reads.

**The lattice is per service, and that is not a detail.** The tempting shortcut is one
scope hierarchy — database contains schema contains table — applied everywhere. On
PostgreSQL that shortcut is false and dangerous:

    GRANT ALL ON DATABASE analytics TO x;    -- CONNECT, CREATE, TEMPORARY. Not one table.

A subject with `ALL` on the database can read nothing. Suppressing the table grant as
"already covered" would hide a genuinely missing privilege and hand the steward a
console that says everything is fine. So PostgreSQL gets no cross-scope subsumption at
all, and the systems where privileges genuinely cascade get it explicitly.
"""
from __future__ import annotations

from .model import Grant, kind_of

# `ALL` is the only privilege that implies others in the systems we speak to. Notably
# absent: UPDATE does not imply SELECT on PostgreSQL (updating without reading is a
# real, if rare, grant), and Write does not imply Read on SeaweedFS.
_ALL = {"ALL", "ALL PRIVILEGES"}
_ADMIN = {"Admin", "ADMIN"}


def _priv_covers(system: str, held: str, wanted: str) -> bool:
    if held == wanted:
        return True
    if held.upper() in _ALL:
        return True
    if kind_of(system) == "s3" and held in _ADMIN:
        return True
    return False


def _scope_covers(system: str, held: str, wanted: str) -> bool:
    """Whether a grant on `held` reaches `wanted`. Identity always counts."""
    if held == wanted:
        return True

    if kind_of(system) == "clickhouse":
        # ON *.* covers everything; ON db.* covers every table in it. This is how
        # ClickHouse actually resolves, so the comparison must too.
        if held == "global:*":
            return True
        if held.startswith("db:") and wanted.startswith("table:"):
            return wanted.removeprefix("table:").startswith(held.removeprefix("db:") + ".")
        return False

    if kind_of(system) == "s3":
        # Policy resources are path prefixes. `bucket:*` is the whole store;
        # `bucket:warehouse` covers everything under it.
        h = held.removeprefix("bucket:").rstrip("*").rstrip("/")
        w = wanted.removeprefix("bucket:").rstrip("*").rstrip("/")
        if h in ("", "*"):
            return True
        return w == h or w.startswith(h + "/")

    # PostgreSQL and anything unknown: no cross-scope inheritance. See the module
    # docstring — a database grant does not confer table access, and guessing that it
    # does would suppress a real gap.
    return False


def covers(held: Grant, wanted: Grant) -> bool:
    """Does `held` make `wanted` redundant? Same system and subject required."""
    return (held.system == wanted.system
            and held.subject == wanted.subject
            and _scope_covers(held.system, held.resource, wanted.resource)
            and _priv_covers(held.system, held.priv, wanted.priv))


def satisfied_by(wanted: Grant, observed: set[Grant]) -> Grant | None:
    """The broader grant that already covers `wanted`, or None."""
    for g in observed:
        if g != wanted and covers(g, wanted):
            return g
    return None
