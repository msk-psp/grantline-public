"""Several instances of one adapter type, side by side (PRD 001 Phase 3 item).

The section name is the instance; `type` is the dialect. The two must not merge, and
dialect-dependent logic (canonical spelling, subsumption, lint) must still recognise
the instance as its kind.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline import adapters, subsume
from grantline.model import Grant, kind_of, register_kind

root = Path(__file__).resolve().parent.parent
pg_fx = root / "examples/fixtures/postgres.json"

# 1. two fixture instances of one kind → distinct systems, each observed on its own
prod = adapters.build("postgres", {"type": "fixture", "fixture": str(pg_fx)})
stg = adapters.build("postgres-staging", {"type": "fixture", "kind": "postgres", "fixture": str(pg_fx)})
assert prod.system == "postgres" and stg.system == "postgres-staging"
gp, _, _ = prod.observe(); gs, _, _ = stg.observe()
assert {g.system for g in gp} == {"postgres"} and {g.system for g in gs} == {"postgres-staging"}
assert not (gp & gs), "same fixture, different instance: not one grant in common"
assert kind_of("postgres-staging") == "postgres" and kind_of("never-registered") == "never-registered"

# 2. live-type instances carry their section name too (constructed, not connected)
from grantline.adapters.clickhouse import ClickHouseAdapter

assert ClickHouseAdapter({}, "clickhouse-staging").system == "clickhouse-staging"
with tempfile.TemporaryDirectory() as d:
    f = Path(d) / "s.json"; f.write_text(json.dumps({"identities": [{"name": "a", "actions": ["Read:x/y/"]}]}))
    s3 = adapters.build("s3-staging", {"type": "s3", "enforced": "dyn", "planes": {"dyn": {"file": str(f)}}})
    g, _, _ = s3.observe()
    assert {x.system for x in g} == {"s3-staging"}
    # 3. dialect logic follows the kind: canonical spelling and prefix subsumption
    assert Grant("s3-staging", "a", "bucket:x/y/*", "Read") == Grant("s3-staging", "a", "bucket:x/y", "Read")
    assert subsume._scope_covers("s3-staging", "bucket:x", "bucket:x/y")
register_kind("ch2", "clickhouse")
assert subsume._scope_covers("ch2", "db:product", "table:product.t")
print("ok")
