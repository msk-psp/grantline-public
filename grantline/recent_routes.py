"""Current routes involving grant changes recorded in a bounded observation window."""
from __future__ import annotations

import datetime
import re
from dataclasses import replace
from pathlib import Path

from . import snapshot


def parse_days(value: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]{0,3}", value) or int(value) > 3650:
        raise ValueError("Days must be a whole number between 1 and 3650.")
    return int(value)


def filter_recent(graph, observed, unobserved, directory, days: int, now=None, systems=None):
    """Compare consecutive snapshots, including live data, without inventing change times.

    Snapshots record grants, not declared bridges or S3 policy attachment changes.
    Those edges provide route context only; removals are counted, never drawn as live access.
    """
    days = parse_days(str(days))
    now = now or datetime.datetime.now(datetime.UTC)
    cutoff = now - datetime.timedelta(days=days)
    history = [snapshot.load(p) for p in snapshot.snapshots(directory)] if directory else []
    history = sorted((s for s in history if s.ts <= now), key=lambda s: s.ts)
    systems = (set(systems) if systems is not None else
               {e.system for e in graph.edges if e.system != "*"}
               | {g.system for g in observed} | {u.system for u in unobserved})
    live = snapshot.Snapshot(Path("<live>"), now, "", frozenset(systems),
                             frozenset(observed), tuple(unobserved))
    before = [s for s in history if s.ts <= cutoff]
    window = [s for s in history if s.ts > cutoff]
    observations = ([before[-1]] if before else []) + window + [live]
    changed, removed = set(), set()
    for previous, current in zip(observations, observations[1:]):
        delta = snapshot.compare(previous, current)
        changed.update(delta.added)
        changed.update(delta.removed)
        removed.update(delta.removed)
    changed &= set(observed)
    seeds = set()
    for i, edge in enumerate(graph.edges):
        dst = "role:" + edge.dst if edge.dst in graph.hops else edge.dst
        if any(g.system == edge.system and g.subject == edge.src
               and g.resource == dst and g.priv in edge.privs for g in changed):
            seeds.add(i)
    selected = set(seeds)
    # Context follows ancestors into the changed edge and descendants out of it.
    for seed in seeds:
        edge = graph.edges[seed]
        for start, reverse in ((edge.src, True), (edge.dst, False)):
            pending, seen = [start], set()
            while pending:
                node = pending.pop()
                if node in seen:
                    continue
                seen.add(node)
                for i, candidate in enumerate(graph.edges):
                    if (candidate.dst if reverse else candidate.src) == node:
                        selected.add(i)
                        pending.append(candidate.src if reverse else candidate.dst)
        if edge.kind == "flat":
            # Policy attachments have no historical timestamp; show current context
            # for the identity whose effective S3 grants demonstrably changed.
            pending, seen = [edge.src], set()
            while pending:
                node = pending.pop()
                if node in seen:
                    continue
                seen.add(node)
                for i, candidate in enumerate(graph.edges):
                    if candidate.src == node:
                        selected.add(i)
                        pending.append(candidate.dst)
    edges = [edge for i, edge in enumerate(graph.edges) if i in selected]
    nodes = {n for edge in edges for n in (edge.src, edge.dst)}
    filtered = replace(graph, edges=edges, principals=graph.principals & nodes,
                       hops=graph.hops & nodes, terminals=graph.terminals & nodes)
    info = {"days": days, "baseline": observations[0].ts.isoformat() if history else None,
            "complete": bool(before), "added": len(changed), "removed": len(removed),
            "observations": len(observations)}
    return filtered, info
