"""ClickHouse probe: server-resolved via SHOW GRANTS … WITH IMPLICIT FINAL."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from grantline.adapters.clickhouse import ClickHouseAdapter, parse_show_grants
from grantline.model import Grant, register_kind

eff = parse_show_grants([
    "GRANT SELECT, SHOW ON research_silver.* TO researcher_b",
    "GRANT SELECT(a, b) ON research_meta.runs TO researcher_b",
    "GRANT READ ON S3 TO researcher_b",
    "GRANT research_maintainer TO researcher_b",
    "GRANT ALL ON *.* TO researcher_b WITH GRANT OPTION",
])
assert ("priv", "SELECT", "db:research_silver") in eff and ("priv", "SHOW", "db:research_silver") in eff
assert ("priv", "SELECT", "table:research_meta.runs") in eff
assert ("priv", "READ", "global:S3") in eff and ("role", "research_maintainer", "") in eff
assert ("priv", "ALL", "global:*") in eff

# verdicts via a stubbed server
class Stub(ClickHouseAdapter):
    def __init__(self): self.cfg = {}; self.system = "clickhouse"
    def _query(self, sql, admin=False, key=None):
        assert "SHOW GRANTS FOR `researcher_b`" in sql
        return [["GRANT SELECT, SHOW ON research_silver.* TO researcher_b"], ["GRANT research_reader TO researcher_b"]]
register_kind("clickhouse", "clickhouse")
ps = Stub().probe({Grant("clickhouse", "researcher_b", "table:research_silver.operations", "SELECT"),
                   Grant("clickhouse", "researcher_b", "db:research_gold", "SELECT"),
                   Grant("clickhouse", "researcher_b", "role:research_reader", "MEMBER")})
v = {(p.resource, p.priv): p.verdict for p in ps}
assert v[("table:research_silver.operations", "SELECT")] == "allow", "db.* covers the table — the server resolved it"
assert v[("db:research_gold", "SELECT")] == "deny" and v[("role:research_reader", "MEMBER")] == "allow"

class NoPriv(ClickHouseAdapter):
    def __init__(self): self.cfg = {}; self.system = "clickhouse"
    def _query(self, sql, admin=False, key=None): raise RuntimeError("Code: 497. Not enough privileges ... SHOW USERS ON *.*")
ps = NoPriv().probe({Grant("clickhouse", "researcher_b", "db:x", "SELECT")})
assert ps[0].verdict == "unknown" and "SHOW USERS" in ps[0].how
print("ok")
