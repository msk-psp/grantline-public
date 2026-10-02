"""N5 — a broader privilege satisfies a narrower one, per service.

The dangerous half of this feature is the false positive: suppressing a grant that is
genuinely missing because a lattice was assumed where the service has none. Most of
these tests assert that subsumption does *not* happen.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline.model import Grant
from grantline.subsume import covers, satisfied_by


def t(name, cond):
    assert cond, name
    print("  ok", name)


def test_postgres_has_no_cross_scope_inheritance():
    """GRANT ALL ON DATABASE is CONNECT/CREATE/TEMPORARY — it reads nothing.
    Treating it as covering a table would hide a real gap behind a green screen."""
    db = Grant("postgres", "x", "db:analytics", "ALL")
    tbl = Grant("postgres", "x", "table:analytics.public.vitals", "SELECT")
    t("db ALL does not cover a table", not covers(db, tbl))
    sch = Grant("postgres", "x", "schema:analytics.public", "ALL")
    t("schema ALL does not cover a table", not covers(sch, tbl))


def test_postgres_all_covers_same_resource():
    tbl_all = Grant("postgres", "x", "table:analytics.public.vitals", "ALL")
    tbl_sel = Grant("postgres", "x", "table:analytics.public.vitals", "SELECT")
    t("ALL covers SELECT on the same table", covers(tbl_all, tbl_sel))


def test_postgres_update_does_not_imply_select():
    up = Grant("postgres", "x", "table:t.p.v", "UPDATE")
    se = Grant("postgres", "x", "table:t.p.v", "SELECT")
    t("UPDATE is not SELECT", not covers(up, se))


def test_clickhouse_scope_does_cascade():
    """ClickHouse resolves ON *.* and ON db.* down to tables — so must we."""
    g = Grant("clickhouse", "x", "global:*", "SELECT")
    d = Grant("clickhouse", "x", "db:product", "SELECT")
    tb = Grant("clickhouse", "x", "table:product.events", "SELECT")
    t("global covers db", covers(g, d))
    t("global covers table", covers(g, tb))
    t("db covers its table", covers(d, tb))
    t("db does not cover another db's table",
      not covers(d, Grant("clickhouse", "x", "table:analytics.events", "SELECT")))
    t("db prefix is not a string prefix",
      not covers(d, Grant("clickhouse", "x", "table:product_staging.events", "SELECT")))


def test_s3_prefix_cascade():
    star = Grant("s3", "x", "bucket:*", "Read")
    b = Grant("s3", "x", "bucket:warehouse", "Read")
    p = Grant("s3", "x", "bucket:warehouse/analytics.silver/*", "Read")
    t("* covers a bucket", covers(star, b))
    t("bucket covers a prefix under it", covers(b, p))
    t("prefix does not cover the whole bucket", not covers(p, b))
    t("sibling bucket not covered",
      not covers(b, Grant("s3", "x", "bucket:warehouse-2/x", "Read")))
    t("Admin covers Read", covers(Grant("s3", "x", "bucket:warehouse", "Admin"), p))
    t("Write does not cover Read",
      not covers(Grant("s3", "x", "bucket:warehouse", "Write"),
                 Grant("s3", "x", "bucket:warehouse", "Read")))


def test_never_crosses_subject_or_system():
    a = Grant("clickhouse", "alice", "global:*", "SELECT")
    t("other subject", not covers(a, Grant("clickhouse", "bob", "db:product", "SELECT")))
    t("other system", not covers(a, Grant("postgres", "alice", "db:product", "SELECT")))


def test_satisfied_by_reports_the_wider_grant():
    held = {Grant("clickhouse", "x", "db:product", "SELECT")}
    w = satisfied_by(Grant("clickhouse", "x", "table:product.events", "SELECT"), held)
    t("names the covering grant", w is not None and w.resource == "db:product")
    t("nothing covers an unrelated grant",
      satisfied_by(Grant("clickhouse", "x", "table:analytics.e", "SELECT"), held) is None)


def test_prefix_spelling_is_normalised_not_subsumed():
    """The two idiomatic spellings of one prefix must compare equal — otherwise the
    mismatch surfaces as 88 findings claiming a broader grant covers a narrower one,
    when both are the same grant. Live data made this the first thing N5 'found'."""
    from grantline.model import canonical
    t("policy spelling normalises",
      canonical("s3", "bucket:personal/researcher_a/*") == "bucket:personal/researcher_a")
    t("native spelling unchanged",
      canonical("s3", "bucket:personal/researcher_a") == "bucket:personal/researcher_a")
    t("whole store survives", canonical("s3", "bucket:*") == "bucket:*")
    t("bare bucket survives", canonical("s3", "bucket:warehouse") == "bucket:warehouse")
    t("other systems untouched",
      canonical("postgres", "table:analytics.public.x") == "table:analytics.public.x")


def test_canonical_survives_a_write_roundtrip():
    """F3 requires grant-then-revoke to return the observation to its prior state.
    Canonical form is for comparison; the emitted policy must still spell the prefix
    the way the service enforces it, or the grant permits nothing."""
    from grantline.adapters.s3 import _arn, effective_grants, policy_with
    g = Grant("s3", "svc", "bucket:data/raw/*", "Read")
    t("stored canonical", g.resource == "bucket:data/raw")
    t("emitted with prefix", _arn(g.resource) == "arn:aws:s3:::data/raw/*")
    t("List targets the bucket itself",
      _arn(g.resource, objects=False) == "arn:aws:s3:::data/raw")

    pol = policy_with({"Statement": []}, g, add=True)
    back, _ = effective_grants({"identities": [{"name": "svc", "policy": pol}]})
    t("observation round-trips to the same grant", g in back)
    t("revoke undoes it", policy_with(pol, g, add=False).get("Statement") == [])


for fn in [v for k, v in dict(globals()).items() if k.startswith("test_")]:
    print(fn.__name__)
    fn()
print("all tests passed")
