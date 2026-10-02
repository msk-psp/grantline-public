"""SeaweedFS advanced-IAM tree as a plane source.

The first N4 probe found four rows the table over-claimed: bucket-wide Read rendered
from native actions, because identities were read without the policies that shadow
them. This test pins the enforcement rule: any policy → policies only; no policy →
native actions.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline.adapters import build
from grantline.adapters.s3 import merge_iam_tree

with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "identities").mkdir(); (root / "groups").mkdir(); (root / "policies").mkdir()
    (root / "identities/researcher_b.json").write_text(json.dumps({"name": "researcher_b", "actions": ["Read:projects", "List:projects"],
                                                         "credentials": [{"access_key": "AK", "secret_key": "SK"}]}))
    (root / "identities/loner.json").write_text(json.dumps({"name": "loner", "actions": ["Read:temp"]}))
    (root / "groups/research.json").write_text(json.dumps({"name": "research", "members": ["researcher_b"], "policy_names": ["team-research", "ghost"]}))
    (root / "policies/team-research.json").write_text(json.dumps({"Statement": [
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::projects"]},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:CreateMultipartUpload"], "Resource": ["arn:aws:s3:::projects/research/*"]}]}))
    (root / "policies.json").write_text(json.dumps({"policies": {}, "inlinePolicies": {"researcher_b": {"personal-researcher_b": {"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::personal/researcher_b/*"]}]},
        # IAM allows a bare string where a list is usual — iterating it yields characters
        "list-all": {"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::*"}]}}}}))
    doc = merge_iam_tree(root)
    by = {i["name"]: i for i in doc["identities"]}
    assert "policy" in by["researcher_b"] and "policy" not in by["loner"]
    assert doc["_gaps"] == ["group 'research' attaches policy 'ghost' which has no document"]

    ad = build("s3", {"type": "s3", "enforced": "dyn", "planes": {"dyn": {"dir": str(root)}}})
    grants, findings, unknown = ad.observe()
    assert not any(g.subject == "researcher_b" for g in grants), "missing policy may deny existing allows"
    assert unknown[0].subjects == ("researcher_b",)
    assert any(f.title == "policy document missing" for f in findings)
    assert any(g.subject == "loner" for g in grants), "healthy identity is still observed"
    (root / "groups/research.json").write_text(json.dumps(
        {"name": "research", "members": ["researcher_b"], "policy_names": ["team-research"]}))
    grants, findings, unknown = ad.observe()
    assert not unknown
    researcher_b = {(g.resource, g.priv) for g in grants if g.subject == "researcher_b"}
    assert ("bucket:projects/research", "Read") in researcher_b and ("bucket:projects", "Read") not in researcher_b, researcher_b
    assert ("bucket:projects/research", "Write") in researcher_b, "multipart is Write"
    assert ("bucket:personal/researcher_b", "Write") in researcher_b, "inline policies merge too"
    assert ("bucket:*", "List") in researcher_b and not any(len(p) == 1 for _, p in researcher_b), "string Action/Resource is one value, not characters"
    loner = {(g.resource, g.priv) for g in grants if g.subject == "loner"}
    assert loner == {("bucket:temp", "Read")}, "no policy → native actions are the enforced thing"
    assert ad.write_ready()[0] is False

# plan() asks grant_cmd once per change. On a tree source each read is a full walk
# over the network; the real console hung for minutes on 282 changes. observe() must
# leave the enforced doc behind for those asks — the tempdir is gone by now, so a
# re-read would not just be slow, it would fail.
from grantline.model import Grant

reads = [0]
_orig = ad.planes["dyn"].read
def _counted():
    reads[0] += 1
    return _orig()
ad.planes["dyn"].read = _counted
for _ in range(5):
    ad.grant_cmd(Grant("s3", "researcher_b", "bucket:projects/research", "Write", "dyn"))
assert reads[0] == 0, f"grant_cmd re-read the tree {reads[0]}x after observe()"
print("ok")
