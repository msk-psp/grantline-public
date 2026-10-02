"""Matrix columns group at the level people reason at, not one per resource."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grantline.model import Grant  # noqa: E402
from grantline.web import _strength, group_of, render  # noqa: E402


def test_storage_prefixes_collapse_to_their_bucket():
    """One bucket must not become dozens of columns.

    Real cluster: storage grants are prefix-scoped (`warehouse/analytics.silver/*`,
    `warehouse/analytics.gold/*`, …). Enumerating them produced 760 columns. The bucket is
    the unit people reason about; the prefix is detail behind it.
    """
    assert group_of("s3", "bucket:warehouse/analytics.silver/*") == ("s3", "bucket:warehouse")
    assert group_of("s3", "bucket:warehouse/analytics.gold/*") == ("s3", "bucket:warehouse")
    assert group_of("s3", "bucket:raw-data") == ("s3", "bucket:raw-data")


def test_other_resources_group_by_kind():
    assert group_of("postgres", "db:analytics") == ("postgres", "db")
    assert group_of("postgres", "table:analytics.registry.x") == ("postgres", "table")
    assert group_of("postgres", "role:analytics_reader") == ("postgres", "role")


def test_cell_shows_the_strongest_privilege_not_the_first():
    """A cell covers many resources; a read among writes must not read as read-only."""
    assert _strength({"Read", "List"}) == "read"
    assert _strength({"Read", "Write"}) == "write"
    assert _strength({"Read", "Admin"}) == "admin"
    assert _strength({"SELECT", "INSERT"}) == "write"


def test_matrix_column_count_follows_groups_not_resources():
    grants = {Grant("s3", "alice", f"bucket:warehouse/ns{i}/*", "Read") for i in range(30)}
    html = render(grants, [], [])
    # 30 resources, one bucket -> one column (plus the subject header column)
    assert html.count('/g/s3/bucket%3Awarehouse') == 1, "one linked column per bucket"
    assert "30</span>" in html, "the count of collapsed resources stays visible"


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
    print("all tests passed")


def test_service_qualified_actions_are_not_buckets():
    """`s3tables:CreateTableBucket` is a capability, not a bucket named CreateTableBucket.

    Native actions (`Read:warehouse`) and service-qualified IAM actions
    (`s3tables:CreateTableBucket`) share a shape and mean different things. Splitting on
    ":" blindly invented four buckets on a real cluster.
    """
    from grantline.adapters.s3 import _action_grant
    g = _action_grant("svc", "s3tables:CreateTableBucket")
    assert (g.resource, g.priv) == ("capability:s3tables", "CreateTableBucket")

    g = _action_grant("svc", "Read:warehouse/analytics.silver/*")
    assert (g.resource, g.priv) == ("bucket:warehouse/analytics.silver/*", "Read")

    g = _action_grant("svc", "Admin")          # bare verb = everything
    assert (g.resource, g.priv) == ("bucket:*", "Admin")
