"""Bucket discovery and request-prefix listings must not imply object access."""
import copy
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from grantline.act import propose
from grantline.adapters.s3 import S3ConfigAdapter, effective_grants, policy_with
from grantline.diff import Change
from grantline.graph import build
from grantline.model import Grant
from grantline.subsume import covers
from grantline.web import graph_data, resources_data


def evaluate(statements):
    unknown = []
    grants, findings = effective_grants({"identities": [{"name": "demo-user", "policy": {
        "Statement": statements}}]}, unobserved=unknown)
    return grants, findings, unknown


discovery = {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "arn:aws:s3:::*"}
listing = {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
           "Resource": "arn:aws:s3:::demo",
           "Condition": {"StringLike": {"s3:prefix": ["team", "team/*", "team-*/reports?"]}}}
objects = {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
           "Resource": "arn:aws:s3:::demo/team/*"}
before = copy.deepcopy([discovery, listing, objects])
grants, _, unknown = evaluate(before)
assert not unknown and len(grants) == 9
assert before == [discovery, listing, objects], "reading must not rewrite the policy"
assert Grant("s3", "demo-user", "capability:s3/ListAllMyBuckets", "ListAllMyBuckets") in grants
assert Grant("s3", "demo-user", "bucket:demo/team", "Read") in grants
assert Grant("s3", "demo-user", "bucket:demo/team", "Write") in grants
assert not any(g.resource in {"bucket:*", "bucket:demo"} for g in grants)
assert any("prefix='team-*/reports?'" in g.resource for g in grants), "keep the request pattern literal"
only_listing, _, unknown = evaluate([discovery, listing])
assert not unknown and all(g.resource.startswith("capability:s3/") for g in only_listing)
assert not any(covers(g, Grant("s3", "demo-user", "bucket:demo/other", "Read")) for g in only_listing)
assert not any(covers(g, Grant("s3", "demo-user", "bucket:demo", "List")) for g in only_listing)
bare = next(g for g in only_listing if g.resource == "capability:s3/ListBucket bucket=demo prefix='team'")
child = Grant("s3", "demo-user", "capability:s3/ListBucket bucket=demo prefix='team/child'", "ListBucket")
assert not covers(bare, child), "literal request prefix does not imply child request prefixes"
cancelled, _, unknown = evaluate([discovery, {**discovery, "Effect": "Deny"}])
assert not cancelled and not unknown
for change in (
    {"Effect": "Deny"},
    {"Action": "s3:GetObject"},
    {"Condition": {"StringEquals": {"s3:prefix": "team"}}},
    {"Condition": {"StringLike": {"s3:prefix": "${aws:username}/*"}}},
    {"Condition": {"StringLike": {"s3:prefix": "team/*", "s3:delimiter": "/"}}},
    {"Resource": "arn:aws:s3:::demo*"},
    {"Resource": "arn:aws:s3:::demo/team"},
    {"NotAction": "s3:DeleteObject"},
    {"Action": {"s3:ListBucket": True}},
    {"Condition": {"StringLike": {"s3:prefix": {"team": True}}}},
    {"Action": [{"s3:ListBucket": True}]},
):
    result, _, unknown = evaluate([discovery, {**listing, **change}])
    assert not result and unknown, change
result, _, unknown = evaluate([listing, {"Effect": "Deny", "Action": "s3:ListBucket",
                                       "Resource": "arn:aws:s3:::demo"}])
assert not result and unknown, "conditional listing plus Deny remains conservative"
result, _, unknown = evaluate([{**discovery, "Resource": "arn:aws:s3:::demo"}])
assert not result and unknown

# Exercise the actual adapter, route JSON and write boundaries with fictional files.
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "iam.json"
    path.write_text(json.dumps({"identities": [{"name": "demo-user", "policy": {
        "Statement": [discovery, listing, objects]}}]}))
    adapter = S3ConfigAdapter({"enforced": "dynamic", "planes": {"dynamic": {"file": str(path)}}})
    observed, _, unknown = adapter.observe()
    assert not unknown and observed == grants
    graph = build(observed, kinds=adapter.kinds, routes=adapter.routes)
    assert graph_data(graph)["nodes"]
    items = resources_data(graph, "s3")["items"]
    assert any("prefix='team/*'" in item["res"] and item["level"] == "list" for item in items)
    capability = next(g for g in grants if g.priv == "ListAllMyBuckets")
    proposal = propose("revoke", "s3", capability.subject, capability.resource, capability.priv,
                       observed, {"s3": adapter})
    assert proposal.blocked and "observation-only" in proposal.cmd
    assert "observation-only" in adapter.coalesce([Change("revoke", capability, "unused")])[0].cmd
    for operation in (lambda: policy_with({"Statement": [discovery]}, capability, False),
                      lambda: adapter.apply(Change("revoke", capability, "unused"))):
        try:
            operation()
        except ValueError as exc:
            assert "observation-only" in str(exc)
        else:
            raise AssertionError("capability write was accepted")
    assert json.loads(path.read_text())["identities"][0]["policy"]["Statement"] == [discovery, listing, objects]

print("S3 discovery/prefix capabilities, conservative unknowns, route rendering and write guards passed")
