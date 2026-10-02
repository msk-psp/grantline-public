"""IAM-API plane: the portable path (AWS-IAM-compatible query API). Parsing checked on the
wire shapes the gateway actually returns; the call layer is stubbed."""
import json
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from grantline.adapters import s3 as s3mod

X = '<?xml version="1.0"?><{r}Response xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><{r}Result>{b}</{r}Result></{r}Response>'
def m(tag, vals): return "".join(f"<member><{tag}>{v}</{tag}></member>" for v in vals)
team = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::projects/research/*"]}]}
pers = {"Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::personal/researcher_b/*"}]}
answers = {
    "ListUsers": X.format(r="ListUsers", b=f"<Users>{m('UserName', ['researcher_b', 'loner'])}</Users>"),
    ("ListUserPolicies", "researcher_b"): X.format(r="ListUserPolicies", b=f"<PolicyNames>{m('PolicyName', ['personal-researcher_b'])}</PolicyNames>"),
    ("ListUserPolicies", "loner"): X.format(r="ListUserPolicies", b="<PolicyNames/>"),
    ("GetUserPolicy", "researcher_b"): X.format(r="GetUserPolicy", b=f"<PolicyDocument>{urllib.parse.quote(json.dumps(pers))}</PolicyDocument>"),
    "ListGroups": X.format(r="ListGroups", b=f"<Groups>{m('GroupName', ['research'])}</Groups>"),
    "GetGroup": X.format(r="GetGroup", b=f"<Users>{m('UserName', ['researcher_b'])}</Users>"),
    "ListAttachedGroupPolicies": X.format(r="ListAttachedGroupPolicies", b=f"<AttachedPolicies>{m('PolicyName', ['team-research'])}</AttachedPolicies>"),
    "GetPolicy": X.format(r="GetPolicy", b="<Policy><DefaultVersionId>v1</DefaultVersionId></Policy>"),
    "GetPolicyVersion": X.format(r="GetPolicyVersion", b=f"<PolicyVersion><Document>{urllib.parse.quote(json.dumps(team))}</Document></PolicyVersion>"),
}
class FakeResp:
    def __init__(self, body): self.body = body.encode()
    def read(self): return self.body
    def __enter__(self): return self
    def __exit__(self, *a): pass
def fake_urlopen(req, timeout=30, context=None):
    form = dict(urllib.parse.parse_qsl(req.data.decode()))
    key = (form["Action"], form["UserName"]) if form["Action"] in ("ListUserPolicies", "GetUserPolicy") else form["Action"]
    return FakeResp(answers[key])
# Patched for this file only — every other test that touches the network must see the
# real thing (or fail loudly), not this stub. Restored at the bottom.
_real_urlopen = s3mod.urllib.request.urlopen
s3mod.urllib.request.urlopen = fake_urlopen
tree = s3mod.iam_api_tree("https://s3.example", "AK", "SK")
doc = s3mod.merge_iam_tree(tree)
by = {i["name"]: i for i in doc["identities"]}
stmts = by["researcher_b"]["policy"]["Statement"]
assert any(s["Resource"] == ["arn:aws:s3:::projects/research/*"] for s in stmts), "group policy attached"
assert any(s["Resource"] == "arn:aws:s3:::personal/researcher_b/*" for s in stmts), "inline policy merged"
assert "policy" not in by["loner"] and by["loner"]["actions"] == []
assert by["researcher_b"]["credentials"] == [], "the IAM API never returns secrets — probe will say so"
print("ok")

s3mod.urllib.request.urlopen = _real_urlopen
