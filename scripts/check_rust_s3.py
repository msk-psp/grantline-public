#!/usr/bin/env python3
"""Offline S3 migration oracle: compare effective grants, unknowns and policy previews."""
import argparse
import copy
import json
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from check_rust_core import declarations, finding, key  # noqa: E402

from grantline import diff, intent  # noqa: E402
from grantline.adapters.s3 import S3ConfigAdapter, policy_with  # noqa: E402
from grantline.model import KINDS, Grant, Unobserved  # noqa: E402


def statement(action="s3:GetObject", resource="arn:aws:s3:::demo/team/*", **extra):
    return dict({"Effect": "Allow", "Action": action, "Resource": resource}, **extra)


def document(statements, actions=()):
    return {"identities": [{"name": "demo", "actions": list(actions), "policy": {"Version": "2012-10-17", "Statement": statements}}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "rust/target/debug/grantline-rs")
    binary = str(parser.parse_args().binary.resolve())
    KINDS.clear()
    KINDS["object-store"] = "s3"
    with tempfile.TemporaryDirectory(prefix="grantline-rust-s3-") as directory:
        root = Path(directory)
        config, declared, source = (root / n for n in ("config.toml", "intent.toml", "iam.json"))
        config.write_text('intent="intent.toml"\nsnapshots="history"\n[adapters.object-store]\ntype="s3"\nenforced="dynamic"\n[adapters.object-store.planes.dynamic]\nfile="iam.json"\n')
        target = Grant("object-store", "demo", "bucket:demo/team", "Read")
        declared.write_text('managed_subjects=["demo"]\n' + declarations([asdict(target)]))

        def native(*command):
            r = subprocess.run([binary, "-c", str(config), *command], cwd="/", text=True, capture_output=True, timeout=30, check=True)
            assert "NEVER-OUTPUT-CREDENTIAL" not in r.stdout + r.stderr
            return json.loads(r.stdout)

        discovery = statement("s3:ListAllMyBuckets", "arn:aws:s3:::*")
        listing = statement(["s3:ListBucket", "s3:GetBucketLocation"], "arn:aws:s3:::demo",
                            Condition={"StringLike": {"s3:prefix": ["team", "team/*", "team-*/reports?", "a'b", 'a"b', "日本語", "\0\x7f\x85\u00a0\u2028\u200d\ue000\U000f0000"]}})
        cases = [
            {"identities": []},
            {"identities": [{"name": "demo", "actions": ["Read:demo/team/*", "s3tables:CreateTableBucket", "Admin"]}]},
            document([statement()], ["Admin"]),
            document([statement(), statement(Effect="Deny")]),
            document([statement("s3:PutObject"), statement("s3:DeleteObject", Effect="Deny")]),
            document([statement("s3:*"), statement(Effect="Deny")]),
            document([statement("s3:PutObject"), statement("s3:DeleteObject")]),
            document([statement("s3:GetObjectTagging"), statement("s3:PutObjectTagging")]),
            document([discovery, listing, statement()]),
            document([discovery, dict(discovery, Effect="Deny")]),
            document([statement(Effect="Other")]),
        ]
        for mutation in [
            {"Effect": "Deny"}, {"Action": "s3:GetObject"},
            {"Condition": {"StringEquals": {"s3:prefix": "team"}}},
            {"Condition": {"StringLike": {"s3:prefix": "${aws:username}/*"}}},
            {"Condition": {"StringLike": {"s3:prefix": "team/*", "s3:delimiter": "/"}}},
            {"Resource": "arn:aws:s3:::demo*"}, {"Resource": "arn:aws:s3:::demo/team"},
            {"NotAction": "s3:DeleteObject"},
        ]:
            cases.append(document([discovery, dict(listing, **mutation)]))
        for action in ["s3:CreateMultipartUpload", "s3:UploadPart", "s3:CompleteMultipartUpload", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads"]:
            cases.append(document([statement(action)]))
        cases += [document([statement(Resource="arn:aws:s3:::demo/*"), statement(Resource="arn:aws:s3:::demo/*", Effect="Deny")]),
                  document([statement(Resource="arn:aws:s3:::demo/*"), statement(Resource="arn:aws:s3:::demo/other/*", Effect="Deny")])]
        for number, doc in enumerate(cases):
            for ident in doc["identities"]:
                ident["credentials"] = [{"accessKey": "NEVER-OUTPUT-CREDENTIAL", "secretKey": "NEVER-OUTPUT-CREDENTIAL"}]
            source.write_text(json.dumps(doc))
            original = source.read_bytes()
            adapter = S3ConfigAdapter({"enforced": "dynamic", "planes": {"dynamic": {"file": str(source)}}}, "object-store")
            observed, facts, unknown = adapter.observe()
            # Rust additionally marks discovery/prefix capabilities unknown when
            # evaluation drops the whole identity policy. Python scopes only buckets.
            unknown = [Unobserved(u.system, (*u.prefixes, "capability:s3/"), u.note, u.subjects)
                       if u.note == "unsupported IAM policy" else u for u in unknown]
            changes, findings, unverified = diff.plan(intent.load(declared), observed, {"object-store": adapter}, unknown)
            actual = native("plan", "--json")
            assert sorted(map(key, actual["observed"])) == sorted(map(key, observed)), number
            assert sorted(actual["observed"], key=key) == sorted(map(asdict, observed), key=key), number
            expected_changes = sorted((c.action, key(g)) for c in changes for g in c.all_grants)
            assert sorted((c["action"], key(c["grant"])) for c in actual["changes"]) == expected_changes, number
            assert sorted(map(key, actual["unverified"])) == sorted(map(key, unverified)), number
            assert sorted(map(finding, actual["findings"])) == sorted(map(finding, facts + findings)), number
            assert sorted((u["prefixes"], u["subjects"]) for u in actual["unobserved"]) == sorted((list(u.prefixes), list(u.subjects)) for u in unknown), number
            for preview in actual["s3_previews"]:
                if preview["blocked"]:
                    assert preview["before"] is None and preview["after"] is None
                    continue
                ident = next((i for i in doc["identities"] if i["name"] == preview["subject"]), {})
                if preview["kind"] == "policy":
                    expected = copy.deepcopy(ident["policy"])
                    for i in preview["changes"]:
                        change = actual["changes"][i]
                        expected = policy_with(expected, Grant(**change["grant"]), change["action"] == "grant")
                    assert preview["after"] == expected, number
            assert source.read_bytes() == original, "planning mutated IAM"

        # One final document per subject, combining grants and revokes.
        source.write_text(json.dumps(document([statement("s3:GetObject", ["arn:aws:s3:::demo/old/*", "arn:aws:s3:::demo/kept/*"])])))
        declared.write_text('managed_subjects=["demo"]\n' + declarations([asdict(target), asdict(Grant("object-store", "demo", "bucket:demo/kept", "Read")), asdict(Grant("object-store", "demo", "bucket:demo/team", "Write"))]))
        plan = native("plan", "--json")
        assert len(plan["s3_previews"]) == 1 and not plan["s3_previews"][0]["blocked"]
        assert len(plan["s3_previews"][0]["changes"]) == 3

        # Mirrored tree: inline + attached policies, missing documents and routes.
        tree = root / "tree"
        for folder in ("identities", "groups", "policies"):
            (tree / folder).mkdir(parents=True)
        (tree / "identities/demo.json").write_text(json.dumps({"name": "demo", "actions": ["Admin"]}))
        (tree / "identities/loner.json").write_text(json.dumps({"name": "loner", "actions": ["Read:temp"]}))
        group = tree / "groups/research.json"
        group.write_text(json.dumps({"name": "research", "members": ["demo"], "policy_names": ["team", "ghost"]}))
        (tree / "policies/team.json").write_text(json.dumps({"Statement": [statement()]}))
        (tree / "policies.json").write_text(json.dumps({"inlinePolicies": {"demo": {"personal-demo": {"Statement": [discovery]}}}}))
        config.write_text(config.read_text().replace('file="iam.json"', 'dir="tree"'))
        for missing in (True, False):
            if not missing:
                group.write_text(group.read_text().replace(', "ghost"', ''))
            adapter = S3ConfigAdapter({"enforced": "dynamic", "planes": {"dynamic": {"dir": str(tree)}}}, "object-store")
            gs, facts, unknown = adapter.observe()
            # A missing shared document could deny capabilities as well as buckets.
            unknown = [Unobserved(u.system, ("",), u.note, u.subjects)
                       if u.note == "policy documents missing" else u for u in unknown]
            gs = {g for g in gs if not any(u.covers(g) for u in unknown)}
            plan = native("plan", "--json")
            assert sorted(map(key, plan["observed"])) == sorted(map(key, gs))
            assert sorted((u["prefixes"], u["subjects"]) for u in plan["unobserved"]) == sorted((list(u.prefixes), list(u.subjects)) for u in unknown)
            titles = [f["title"] for f in plan["findings"]]
            assert ("policy document missing" in titles) == missing
            graph = native("graph", "--json")
            routes = sorted((e["src"], e["dst"], e["kind"]) for e in graph["graph"]["edges"] if e["kind"] == "route")
            # The native graph exposes the same observer routes through Graph::build.
            from grantline.graph import build
            expected = build(gs, kinds=adapter.kinds, routes=adapter.routes)
            assert routes == sorted((e.src, e.dst, e.kind) for e in expected.edges if e.kind == "route")
            assert all(p["blocked"] for p in plan["s3_previews"]), "tree previews cannot rewrite shared policy"
        print(f"R3a: {len(cases)} S3 cases and 2 IAM-tree scenarios checked against Python (Rust additionally obscures capabilities for incomplete/missing policies); combined previews checked; sources unchanged")


if __name__ == "__main__":
    main()
