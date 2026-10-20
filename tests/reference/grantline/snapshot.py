"""F8 — every run leaves a snapshot, and the next run says what moved since.

"Since when" is the second question after "who", and nothing in this tool could
answer it: each run read the servers, rendered, and forgot. A snapshot is that
memory — one line-delimited JSON file per run, written beside the configuration
(so outside any repository, because the configuration names real hosts).

Three decisions carry this module.

**One snapshot per run, not per observation.** `serve` re-observes on every
request, and a file per page reload would make "your previous run" mean "when
you last hit reload" — a comparison that is always empty and a directory that
grows with browsing. So `Recorder` writes on the first observation of the
process and holds the comparison for the rest of it. A long-lived console
therefore keeps showing the same "since your previous run" answer, which is the
honest reading: the run is the process, and it started once.

**"Could not check" is not "gone" (F6).** This is the place that failure mode
hurts most. A database that refused a connection this run holds exactly the
grants it held before, but they are missing from today's observation — subtract
the two sets and a hundred grants read as revoked. So a grant that falls in an
`Unobserved` scope of *either* snapshot never lands in added/removed. It lands
in `revealed`/`obscured` instead, which say what actually happened: the scope
moved in or out of view, the access did not. The same rule covers a whole
system, since an adapter dropped from the config is unread, not empty.

**There is no schedule.** Nothing here runs the tool for you, so the gap between
two snapshots is however long it happened to be. Every surface says the elapsed
time and never a cadence — "your previous run, 3 days ago", not "since
yesterday" and never "daily".

N6: a snapshot records principals, resources and privileges. Failure notes are
copied from the adapter, so any credential a driver echoed into its error text
is stripped on the way out.
"""
from __future__ import annotations

import datetime
import getpass
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .model import Grant, Unobserved

_STAMP = "%Y-%m-%dT%H-%M-%SZ"   # lexicographic order == chronological order
_PREFIX = "snapshot-"
_SUFFIX = ".jsonl"

# `scheme://user:secret@host` — the one shape a driver's error text reliably leaks.
_CREDENTIAL = re.compile(r"(://[^\s:/@]+:)[^\s@/]+(@)")


def _redact(text: str) -> str:
    return _CREDENTIAL.sub(r"\1***\2", text)


@dataclass(frozen=True)
class Snapshot:
    """What one run saw, plus what it could not see."""
    path: Path
    ts: datetime.datetime
    user: str
    systems: frozenset[str]
    grants: frozenset[Grant]
    unobserved: tuple[Unobserved, ...]

    def blind_to(self, g: Grant) -> bool:
        """Would this run have been unable to see `g` even if it were there?"""
        return (g.system not in self.systems
                or any(u.covers(g) for u in self.unobserved))


def write(directory: str | Path, observed, unobserved, systems,
          now: datetime.datetime | None = None) -> Snapshot:
    """Append one run's observation as a new file. Returns the snapshot written."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    ts = now or datetime.datetime.now(datetime.UTC)
    systems = frozenset(systems)
    unobserved = tuple(unobserved)

    path = directory / f"{_PREFIX}{ts.strftime(_STAMP)}{_SUFFIX}"
    n = 1
    while path.exists():  # two runs inside one second: neither may overwrite the other
        path = directory / f"{_PREFIX}{ts.strftime(_STAMP)}-{n}{_SUFFIX}"
        n += 1

    lines = [{"run": {"ts": ts.isoformat(), "user": getpass.getuser(),
                      "systems": sorted(systems)}}]
    lines += [{"unobserved": {"system": u.system, "prefixes": list(u.prefixes),
                              "note": _redact(u.note), "subjects": list(u.subjects)}} for u in unobserved]
    # Sorted so two runs over unchanged state produce byte-identical bodies — a file
    # that differs only in set iteration order invites a diff of the files themselves.
    lines += [{"grant": {"system": g.system, "subject": g.subject,
                         "resource": g.resource, "priv": g.priv, "source": g.source,
                         **({"grantor": g.grantor} if g.grantor else {})}}
              for g in sorted(observed, key=lambda g: (g.system, g.subject,
                                                       g.resource, g.priv))]
    path.write_text("".join(json.dumps(x) + "\n" for x in lines))
    return Snapshot(path, ts, getpass.getuser(), systems,
                    frozenset(observed), unobserved)


def load(path: str | Path) -> Snapshot:
    path = Path(path)
    ts, user, systems = None, "", frozenset()
    grants: set[Grant] = set()
    unobserved: list[Unobserved] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if "run" in rec:
            r = rec["run"]
            ts = datetime.datetime.fromisoformat(r["ts"])
            user = r.get("user", "")
            systems = frozenset(r.get("systems", []))
        elif "unobserved" in rec:
            u = rec["unobserved"]
            unobserved.append(Unobserved(u["system"], tuple(u["prefixes"]), u["note"], tuple(u.get("subjects", ()))))
        elif "grant" in rec:
            g = rec["grant"]
            grants.add(Grant(g["system"], g["subject"], g["resource"], g["priv"],
                             g.get("source", "explicit"), g.get("grantor")))
    if ts is None:  # no header: refuse to guess a time we never recorded
        raise ValueError(f"{path} has no run header — not a snapshot this tool wrote")
    return Snapshot(path, ts, user, systems, frozenset(grants), tuple(unobserved))


def snapshots(directory: str | Path) -> list[Path]:
    directory = Path(directory)
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir()
                  if p.name.startswith(_PREFIX) and p.name.endswith(_SUFFIX))


def parse_since(text: str, now: datetime.datetime | None = None) -> datetime.datetime:
    """`7d` / `2w` / `12h` / `2026-08-01` / ISO timestamp → the point in time it names.
    Relative forms count back from now. There is still no cadence in this — the user
    names a point, and the answer is whatever run happened to be at or before it."""
    now = now or datetime.datetime.now(datetime.UTC)
    m = re.fullmatch(r"(\d+)([hdw])", text.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return now - {"h": datetime.timedelta(hours=n), "d": datetime.timedelta(days=n),
                      "w": datetime.timedelta(weeks=n)}[unit]
    ts = datetime.datetime.fromisoformat(text.strip())
    return ts if ts.tzinfo else ts.replace(tzinfo=datetime.UTC)


def at_or_before(directory: str | Path, when: datetime.datetime) -> Path | None:
    """The newest snapshot taken at or before `when` — the run that stood at that
    moment. None when every snapshot is newer (the memory does not reach that far)."""
    found = None
    for p in snapshots(directory):
        try:
            ts = datetime.datetime.strptime(p.name[len(_PREFIX):len(_PREFIX) + len("2026-01-01T00-00-00Z")], _STAMP).replace(tzinfo=datetime.UTC)
        except ValueError:
            continue
        if ts <= when:
            found = p
    return found


def latest(directory: str | Path) -> Path | None:
    found = snapshots(directory)
    return found[-1] if found else None


@dataclass(frozen=True)
class Comparison:
    """Two runs, and only what moved between them.

    `added`/`removed` are the answer. `revealed`/`obscured` exist so the answer can
    stay clean: they hold the grants whose *visibility* changed, which look exactly
    like a grant or a revoke in set arithmetic and are neither.

    Note what is structurally absent: an unchanged grant is in both sets, so it is in
    neither difference. There is no filtering step that could let one through.
    """
    prev: Snapshot
    cur: Snapshot
    added: tuple[Grant, ...]
    removed: tuple[Grant, ...]
    revealed: tuple[Grant, ...]
    obscured: tuple[Grant, ...]

    @property
    def gap(self) -> datetime.timedelta:
        return self.cur.ts - self.prev.ts

    @property
    def moved(self) -> int:
        return len(self.added) + len(self.removed)

    def ago(self) -> str:
        return ago(self.gap)


def _sorted(gs) -> tuple[Grant, ...]:
    return tuple(sorted(gs, key=lambda g: (g.system, g.subject, g.resource, g.priv)))


def compare(prev: Snapshot, cur: Snapshot) -> Comparison:
    """What changed between two runs — and nothing that did not.

    `Grant.source` is `compare=False` (model.py), so a grant that was explicit last
    run and is policy-derived this run compares equal and does not appear here. That
    is deliberate and it is the right answer for a change log too: the access is the
    same access, and a snapshot that reported it as revoked-and-regranted would be
    reporting on the adapter, not on the server.
    """
    gained, lost = cur.grants - prev.grants, prev.grants - cur.grants
    return Comparison(
        prev, cur,
        added=_sorted(g for g in gained if not prev.blind_to(g)),
        revealed=_sorted(g for g in gained if prev.blind_to(g)),
        removed=_sorted(g for g in lost if not cur.blind_to(g)),
        obscured=_sorted(g for g in lost if cur.blind_to(g)),
    )


def ago(delta: datetime.timedelta) -> str:
    """An elapsed gap in words. Never a cadence — nothing schedules this tool, and a
    phrase like "since yesterday's run" would invent a rhythm that does not exist."""
    s = max(delta.total_seconds(), 0)
    if s < 90:
        return "moments ago"
    for limit, size, unit in ((90 * 60, 60, "minute"), (86400, 3600, "hour"),
                              (45 * 86400, 86400, "day"), (None, 30 * 86400, "month")):
        if limit is None or s < limit:
            n = round(s / size)
            return f"{n} {unit}{'s' if n != 1 else ''} ago"


class Recorder:
    """Writes one snapshot for this run and remembers the comparison.

    Called from `cli._observe_and_plan`, the single place every surface observes
    through, so `plan`, `apply` and `serve` all leave the same record. `serve`
    observes per request; this records only the first of them (see module head).

    A snapshot that cannot be written must not take the run down with it — the
    steward asked to see access, not to file paperwork. The failure is kept as a
    note and surfaced where the comparison would have been.
    """

    def __init__(self, directory: str | Path | None):
        self.dir = Path(directory) if directory else None
        self.comparison: Comparison | None = None
        self.snapshot: Snapshot | None = None
        self.error: str = ""
        self._done = False

    def record(self, observed, unobserved, systems) -> Comparison | None:
        if self._done or self.dir is None:
            return self.comparison
        self._done = True
        try:
            before = latest(self.dir)          # before writing this run's file
            prev = load(before) if before else None
            self.snapshot = write(self.dir, observed, unobserved, systems)
            if prev is not None:
                self.comparison = compare(prev, self.snapshot)
        except Exception as exc:               # F6: a reason, never a traceback
            self.error = (f"no snapshot was written to {self.dir}: "
                          f"{type(exc).__name__}: {_redact(str(exc))}")
        return self.comparison
