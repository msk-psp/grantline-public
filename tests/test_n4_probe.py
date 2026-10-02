"""N4 — verify on the real auth path.

(1) The SigV4 signer matches the AWS-published example byte for byte — a probe that says
"deny" must be a real 403, not a signing mistake. (2) compare() only speaks on definite
verdicts. (3) Adapters that cannot ask say `unknown` with a reason, never allow/deny.
"""
import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline import probe
from grantline.adapters import build
from grantline.adapters.sigv4 import sign
from grantline.model import Grant

# 1. AWS "Example: GET Object" from the SigV4 S3 test vectors
h = sign("GET", "https://examplebucket.s3.amazonaws.com/test.txt",
         "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
         now=datetime.datetime(2013, 5, 24, 0, 0, 0, tzinfo=datetime.UTC),
         extra_headers={"Range": "bytes=0-9"})
assert h["authorization"].endswith(
    "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"), h["authorization"]

# 2. compare: only definite verdicts speak
obs = {Grant("s3", "a", "bucket:x", "Read"), Grant("s3", "a", "bucket:x", "List")}
P = probe.Probe
f = probe.compare([P("s3", "a", "bucket:x", "Read", "deny", "HEAD → 403"),
                   P("s3", "a", "bucket:x", "List", "unknown", "no endpoint"),
                   P("s3", "a", "bucket:y", "Read", "allow", "HEAD → 200")], obs)
titles = sorted(x.title for x in f)
assert titles == ["granted on paper, denied on the path", "reachable, but no grant explains it"], titles

# 3. honest unknowns
root = Path(__file__).resolve().parent.parent
ch = build("clickhouse", {"type": "fixture", "fixture": str(root / "examples/fixtures/clickhouse.json")})
g, _, _ = ch.observe()
ps = ch.probe(g)
assert ps and {p.verdict for p in ps} == {"unknown"} and all("probe" in p.how for p in ps)
s3 = build("s3", {"type": "s3", "enforced": "dynamic",
                  "planes": {"dynamic": {"file": str(root / "examples/fixtures/s3_dynamic.json")}}})
g, _, _ = s3.observe()
ps = s3.probe(g)
assert {p.verdict for p in ps} == {"unknown"} and "endpoint_env" in ps[0].how
print("ok")
