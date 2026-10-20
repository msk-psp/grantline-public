#!/usr/bin/env python3
"""Compare native permission decisions to Python; no adapters or credentials used."""
import argparse
import itertools
import json
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/reference"))
from grantline.diff import plan  # noqa: E402
from grantline.intent import Intent  # noqa: E402
from grantline.model import KINDS, Grant, Unobserved  # noqa: E402
from grantline.subsume import covers  # noqa: E402


class Commands:
    """Isolate convergence decisions from command generation and coalescing."""
    def grant_cmd(self, grant):
        return "fixture grant"

    def revoke_cmd(self, grant):
        return "fixture revoke"


def atom(system="s3", resource="bucket:demo/team", priv="Read", subject="demo-user", **metadata):
    return dict(system=system, subject=subject, resource=resource, priv=priv, **metadata)


def cases():
    out = []
    resources = {
        "s3": ["bucket:*", "bucket:demo", "bucket:demo/team", "bucket:demo/team/*",
               "bucket:demo/teamwork", "bucket:demo/team/file", "bucket:other", "context:ListAllMyBuckets"],
        "postgres": ["db:demo", "schema:demo.public", "table:demo.public.events", "role:readers"],
        "clickhouse": ["global:*", "db:demo", "db:demolition", "table:demo.events", "table:other.events"],
    }
    for kind, rs in resources.items():
        for system in (kind, kind + "-staging"):
            pairs = []
            for h, w in itertools.product(rs, repeat=2):
                for hp, wp in (("Read", "Read"), ("Write", "Read"), ("Admin", "Read"),
                               ("ALL PRIVILEGES", "SELECT"), ("SELECT", "UPDATE")):
                    pairs.append([atom(system, h, hp), atom(system, w, wp)])
            pairs.extend([[atom(system), atom(kind + "-other")],
                          [atom(system), atom(system, subject="someone-else")]])
            out.append(dict(name="coverage-" + system, kinds={system: kind}, pairs=pairs))
    out.extend([
        dict(name="metadata-not-identity", intent=[atom(source="explicit")],
             observed=[atom(source="policy", grantor="demo-owner"), atom()], managed=["demo-user"]),
        dict(name="canonical-prefix", intent=[atom()], observed=[atom(resource="bucket:demo/team/*")], managed=["demo-user"]),
        dict(name="silent-system-no-revoke", intent=[atom()], observed=[atom("postgres", "db:demo", "CONNECT")], managed=["demo-user"]),
        dict(name="explicit-empty-system-revoke", observed=[atom("postgres", "db:demo", "CONNECT")], managed=["demo-user"], managed_systems=["postgres"]),
        dict(name="unmanaged-no-revoke", observed=[atom()], managed_systems=["s3"]),
    ])
    rng = random.Random(31)
    pool = [atom(k, r, p, s) for k, rs in resources.items() for r in rs
            for p in ("Read", "Write", "ALL", "SELECT") for s in ("demo-user", "demo-reviewer")]
    for i in range(160):
        out.append(dict(name=f"convergence-{i}", intent=rng.sample(pool, rng.randrange(18)),
                        observed=rng.sample(pool, rng.randrange(18)),
                        managed=rng.choice([[], ["demo-user"], ["demo-user", "demo-reviewer"]]),
                        managed_systems=rng.choice([[], ["s3"], ["postgres", "clickhouse"]]),
                        unobserved=rng.choice([[], [dict(system="s3", prefixes=["bucket:demo/team"], subjects=["demo-user"], note="fixture unavailable")],
                                                [dict(system="postgres", prefixes=["table:demo."], note="fixture unavailable")]])))
    # A blind prefix excludes both directions, but must not hide its sibling path.
    out.append(dict(name="blind-boundary-and-subject", intent=[atom(), atom(subject="demo-reviewer"), atom(resource="bucket:demo/teamwork")],
                    observed=[atom(priv="Write")], managed=["demo-user"],
                    unobserved=[dict(system="s3", prefixes=["bucket:demo/team"], subjects=["demo-user"], note="unread")] ))
    return out


def reference(case):
    KINDS.clear()
    KINDS.update(case.get("kinds", {}))
    observed = {Grant(**g) for g in case.get("observed", [])}
    intent = Intent({Grant(**g) for g in case.get("intent", [])}, set(case.get("managed", [])), [], set(case.get("managed_systems", [])))
    unknown = [Unobserved(**u) for u in case.get("unobserved", [])]
    adapters = {g.system: Commands() for g in observed | intent.grants}
    changes, _, unverified = plan(intent, observed, adapters, unknown)
    def key(g):
        return [g.system, g.subject, g.resource, g.priv]
    return dict(name=case["name"], canonical_observed=sorted(map(key, observed)),
                covers=[covers(Grant(**h), Grant(**w)) for h, w in case.get("pairs", [])],
                changes=sorted([[c.action, key(g)] for c in changes for g in c.all_grants]),
                unverified=sorted(map(key, unverified)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "rust/target/debug/grantline-rs")
    args = parser.parse_args()
    shared = cases()
    expected = [reference(case) for case in shared]
    result = subprocess.run([str(args.binary.resolve()), "parity"], input=json.dumps(shared), text=True,
                            capture_output=True, check=True, timeout=30)
    actual = json.loads(result.stdout)
    if actual != expected:
        for index, (want, got) in enumerate(itertools.zip_longest(expected, actual)):
            if want != got:
                raise AssertionError(f"parity mismatch in case {index}: expected {want!r}, got {got!r}")
    print(f"{len(shared)} cases / {sum(len(c.get('pairs', [])) for c in shared)} coverage pairs match Python")


if __name__ == "__main__":
    main()
