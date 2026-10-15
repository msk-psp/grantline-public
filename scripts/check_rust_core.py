#!/usr/bin/env python3
"""R2 differential checks: native CLI vs Python contracts, entirely offline."""
import argparse
import datetime as dt
import json
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from check_rust_parity import Commands, atom, cases  # noqa: E402

from grantline import diff, graph, intent, snapshot  # noqa: E402
from grantline.adapters import FixtureAdapter, clickhouse, postgres, s3  # noqa: E402
from grantline.model import KINDS, Grant, Unobserved  # noqa: E402


def key(g):
    return [g.system, g.subject, g.resource, g.priv] if isinstance(g, Grant) else [g[k] for k in ("system", "subject", "resource", "priv")]


def finding(f):
    f = asdict(f) if not isinstance(f, dict) else f
    # Python picks an arbitrary covering grant from a set. Compare the requested
    # atom here; the R1 suite independently checks each coverage relationship.
    entities = f["entities"][:3] if f["title"] == "already covered by a broader grant" else f["entities"]
    return f["system"], f["title"], f["level"], sorted(entities)


def save_snapshot(path, grants, unknown, systems, day=1):
    records = [{"run": {"ts": f"2026-10-{day:02}T09:00:00+00:00", "user": "demo", "systems": sorted(systems)}}]
    records += [{"unobserved": u} for u in unknown]
    records += [{"grant": g} for g in grants]
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def declarations(rows):
    return "".join("\n[[grants]]\n" + "\n".join(f"{k} = {json.dumps(g[k], ensure_ascii=False)}" for k in ("system", "subject", "resource"))
                   + f"\nprivs = {json.dumps([g['priv']])}\n" for g in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "rust/target/debug/grantline-rs")
    args = parser.parse_args()
    binary = str(args.binary.resolve())

    def native(config, *command):
        result = subprocess.run([binary, "-c", str(config), *map(str, command)], cwd="/", capture_output=True, text=True, timeout=30, check=True)
        return json.loads(result.stdout)

    with tempfile.TemporaryDirectory(prefix="grantline-rust-r2-") as folder:
        work = Path(folder)
        config, declaration, observation = (work / n for n in ("config.toml", "intent.toml", "observed.jsonl"))
        shared = cases()
        shared += [
            dict(name="unverified-declaration-metadata", intent=[atom()], observed=[atom(source="policy", grantor="demo-owner")],
                 unobserved=[dict(system="s3", prefixes=["bucket:demo"], note="unread")]),
            dict(name="quoted-identifiers", intent=[atom("postgres", "table:demo.public.odd\"table", "SELECT", 'demo"user'),
                                                   atom("clickhouse", "table:demo.odd`table\\name", "dictGet", "demo`user")]),
        ]
        for case in shared:
            KINDS.clear()
            KINDS.update(case.get("kinds", {}))
            observed = {Grant(**g) for g in case.get("observed", [])}
            wanted = {Grant(**g) for g in case.get("intent", [])}
            systems = {g.system for g in observed | wanted} | set(case.get("managed_systems", [])) | {u["system"] for u in case.get("unobserved", [])}
            declaration.write_text("managed_subjects = " + json.dumps(case.get("managed", [])) + "\nmanaged_systems = " + json.dumps(case.get("managed_systems", [])) + declarations(case.get("intent", [])))
            config.write_text('intent = "intent.toml"\nsnapshots = "history"\n' + "".join(f'\n[adapters.{json.dumps(s)}]\ntype = {json.dumps(KINDS.get(s, s))}\n' for s in sorted(systems)))
            save_snapshot(observation, case.get("observed", []), case.get("unobserved", []), systems)
            it = intent.load(declaration)
            unknown = [Unobserved(**u) for u in case.get("unobserved", [])]
            changes, findings, unverified = diff.plan(it, observed, {s: Commands() for s in systems}, unknown)
            actual = native(config, "plan", "--observed", observation, "--json")
            expected_changes = sorted([[c.action, key(c.grant)] for c in changes])
            assert sorted([[c["action"], key(c["grant"])] for c in actual["changes"]]) == expected_changes, case["name"]
            assert sorted(map(key, actual["unverified"])) == sorted(map(key, unverified)), case["name"]
            assert sorted(actual["observed"], key=key) == sorted(map(asdict, observed), key=key), case["name"]
            assert sorted(actual["unverified"], key=key) == sorted(map(asdict, unverified), key=key), case["name"]
            assert sorted(map(finding, actual["findings"])) == sorted(map(finding, findings)), case["name"]
            for change in actual["changes"]:
                g = Grant(**change["grant"])
                mod = {"postgres": postgres, "clickhouse": clickhouse}.get(KINDS.get(g.system, g.system))
                try:
                    expected = getattr(mod, change["action"] + "_cmd")(g) if mod else None
                except ValueError:
                    expected = None
                assert change["cmd"] == expected, (case["name"], change)
                assert expected is not None or change["command_error"]

        # Bundled fixtures and local S3 IAM planes; no native service connections.
        config_path = ROOT / "grantline.toml"
        cfg = tomllib.loads(config_path.read_text())
        KINDS.clear()
        adapters, observed, facts, unknown = {}, set(), [], []
        for system, acfg in cfg["adapters"].items():
            kind = acfg.get("kind", system if acfg.get("type") == "fixture" else acfg.get("type", system))
            KINDS[system] = kind
            if acfg["type"] == "fixture":
                mod = {"postgres": postgres, "clickhouse": clickhouse}[kind]
                adapter = FixtureAdapter(system, ROOT / acfg["fixture"], (mod.grant_cmd, mod.revoke_cmd), mod.facts_findings)
                gs, fs, us = adapter.observe()
                observed |= gs
                facts += fs
                unknown += us
                adapters[system] = adapter
            elif acfg["type"] == "s3":
                acfg = dict(acfg, planes={n: dict(p, file=str(ROOT / p["file"])) for n, p in acfg["planes"].items()})
                adapter = s3.S3ConfigAdapter(acfg, system)
                gs, fs, us = adapter.observe()
                observed |= gs
                facts += fs
                unknown += us
                adapters[system] = adapter
            else:
                unknown.append(Unobserved(system, ("",), "Native service observation is not implemented in R2; use a saved snapshot or the Python console"))
                adapters[system] = Commands()
        changes, findings, unverified = diff.plan(intent.load(ROOT / cfg["intent"]), observed, adapters, unknown)
        actual = native(config_path, "plan", "--json")
        assert sorted((c["action"], key(c["grant"])) for c in actual["changes"]) == sorted((c.action, key(g)) for c in changes for g in c.all_grants)
        assert sorted(map(finding, actual["findings"])) == sorted(map(finding, facts + findings))
        # Deterministic fixture diagnostics preserve their full explanation.
        for title in ("frozen ACL (owner locked out)", "stale grants on dropped database", "default privileges on a group role", "naming drift"):
            assert sorted(f["detail"] for f in actual["findings"] if f["title"] == title) == sorted(f.detail for f in facts + findings if f.title == title)
        assert sorted(c["cmd"] for c in actual["changes"] if c["grant"]["system"] != "s3") == sorted(c.cmd for c in changes if c.grant.system != "s3")

        # Python-written snapshots load natively; native copies load in Python.
        declaration.write_text("")
        config.write_text('intent="intent.toml"\nsnapshots="history"\n[adapters.postgres]\ntype="postgres"\n[adapters.s3]\ntype="s3"\n')
        KINDS.clear()
        g = {Grant("postgres", "demo", "table:hr.public.events", "SELECT", "policy", "demo-owner")}
        t0 = dt.datetime(2026, 10, 1, tzinfo=dt.UTC)
        past = snapshot.write(work / "history", g, [], {"postgres", "s3"}, now=t0)
        unread = [Unobserved("postgres", ("table:hr.",), "fixture unavailable", ("demo",))]
        cur = snapshot.write(work / "history", set(), unread, {"postgres"}, now=t0 + dt.timedelta(days=2))
        for before, after in ((past, cur), (cur, past)):
            expected = snapshot.compare(before, after)
            original_config = config.read_text()
            config.write_text(original_config.replace('snapshots="history"', 'snapshots="empty-directory"'))
            actual = native(config, "history", "--from", before.path, "--to", after.path, "--json")
            config.write_text(original_config)
            for field in ("added", "removed", "revealed", "obscured"):
                assert sorted(map(key, actual[field])) == sorted(map(key, getattr(expected, field)))
        saved = native(config, "snapshot", "--observed", past.path, "--directory", work / "copy", "--json")
        restored = snapshot.load(saved["path"])
        assert restored.ts == past.ts and restored.user == past.user and restored.grants == past.grants
        assert next(iter(restored.grants)).grantor == "demo-owner"
        assert native(config, "history", "--since", "2026-10-01", "--json")["obscured"]
        for legacy in sorted((ROOT / "examples/demo/snapshots").glob("*.jsonl")):
            expected = snapshot.load(legacy)
            save_config = 'intent="intent.toml"\nsnapshots="history"\n' + "".join(f'[adapters.{json.dumps(s)}]\ntype="{s.split("-")[0]}"\n' for s in sorted(expected.systems))
            config.write_text(save_config)
            copied = native(config, "snapshot", "--observed", legacy, "--directory", work / "copy", "--json")
            assert snapshot.load(copied["path"]).grants == expected.grants

        legacy_files = sorted((ROOT / "examples/demo/snapshots").glob("*.jsonl"))
        expected = snapshot.compare(snapshot.load(legacy_files[0]), snapshot.load(legacy_files[-1]))
        actual = native(ROOT / "examples/demo/grantline.toml", "history", "--since", "2026-08-25", "--json")
        for field in ("added", "removed", "revealed", "obscured"):
            assert sorted(map(key, actual[field])) == sorted(map(key, getattr(expected, field)))

        # Graph: distinct routes, bridge, policy-shaped routes, cycle and 205 leaves.
        graph_cases = [
            dict(grants=[dict(subject="demo", resource="role:reader", priv="MEMBER"), dict(subject="reader", resource="table:demo.public.events", priv="SELECT")],
                 kinds={"demo": "account", "reader": "role"}, routes=[["demo", "group:demo", "member"], ["group:demo", "table:demo.public.events", "allows"]]),
            dict(grants=[dict(subject="a", resource="role:b", priv="MEMBER"), dict(subject="b", resource="role:a", priv="MEMBER")]),
            dict(grants=[dict(subject="demo", resource=f"table:demo.public.t{i}", priv="SELECT") for i in range(205)]),
        ]
        for data in graph_cases:
            fixture = work / "fixture.json"
            fixture.write_text(json.dumps(data))
            config.write_text('intent="intent.toml"\n[adapters.postgres]\ntype="fixture"\nfixture="fixture.json"\n[[bridges]]\nfrom="reader"\nto="svc-data"\nsystem="s3"\nnote="server-held key"\n[graph]\nservices=["svc-*"]\n[graph.people]\ndemo="Demo User"\n[graph.teams]\ndemo="demo-team"\n[graph.environments]\n"운영"=["postgres"]\n')
            bridges = [dict(**{"from": "reader", "to": "svc-data"}, system="s3", note="server-held key")]
            expected = graph.build({Grant("postgres", **g) for g in data["grants"]}, bridges,
                                   kinds=data.get("kinds", {}), routes=[("postgres", *r) for r in data.get("routes", [])],
                                   services=("svc-*",), names={"demo": "Demo User"}, teams={"demo": "demo-team"}, envs={"postgres": ("운영",)})
            actual = native(config, "graph", "--subject", "demo", "--resource", "svc-data", "--depth", "reader", "--json")
            def edge(e):
                e = asdict(e) if not isinstance(e, dict) else e
                return e["src"], e["dst"], e["system"], sorted(e["privs"]), e["kind"], e["note"]
            assert sorted(map(edge, actual["graph"]["edges"])) == sorted(map(edge, expected.edges))
            for field in ("principals", "hops", "terminals"):
                assert actual["graph"][field] == sorted(getattr(expected, field))
            for field in ("kind", "names", "teams"):
                assert actual["graph"][field] == getattr(expected, field)
            assert actual["graph"]["envs"] == {s: list(es) for s, es in expected.envs.items()}
            assert sorted(actual["routes_from"]["demo"]["paths"]) == sorted(expected.routes_from("demo"))
            assert sorted(actual["paths_to"]["svc-data"]["paths"]) == sorted(expected.paths_to("svc-data"))
            assert actual["depths"]["reader"] == expected.depth("reader")
        # Config declaration order decides the last observer's node classification
        # and the display order of multiple literal environment labels.
        (work / "pg.json").write_text(json.dumps(dict(grants=[dict(subject="demo", resource="db:demo", priv="CONNECT")], kinds={"demo": "role"})))
        (work / "ch.json").write_text(json.dumps(dict(grants=[dict(subject="demo", resource="db:demo", priv="SELECT")], kinds={"demo": "account"})))
        config.write_text('intent="intent.toml"\n[adapters.postgres]\ntype="fixture"\nfixture="pg.json"\n[adapters.clickhouse]\ntype="fixture"\nfixture="ch.json"\n[graph.environments]\nstaging=["postgres"]\nprod=["postgres"]\n')
        actual = native(config, "graph", "--json")["graph"]
        assert actual["kind"]["demo"] == "human"
        assert actual["envs"]["postgres"] == ["staging", "prod"]
        print(f"R2: {len(shared)} plan/diagnostic/SQL cases, bundled fixtures, Python/native snapshot round trips, history and {len(graph_cases) + 1} graph scenarios match")


if __name__ == "__main__":
    main()
