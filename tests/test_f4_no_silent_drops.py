"""F4 — 공통 모델에 안 들어가는 사실은 침묵하지 않는다.

세 어댑터가 각각 앞 페이지에 틀린 답을 내고 있었다. 전부 "모델에 안 맞으니 걸러낸다"
라는 같은 실수다. 걸러낸 자리에 남는 것은 '없음' 이고, 관리자는 그걸 '권한 없음' 으로
읽는다.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grantline.adapters.s3 import effective_grants  # noqa: E402


def _ident(name, **kw):
    return {"identities": [{"name": name, **kw}]}


def test_explicit_deny_cancels_the_allow():
    """Deny 를 건너뛰면 **막힌 접근이 허용으로 렌더된다** — 재고 화면에서 틀린 답이다."""
    doc = _ident("alice", policy={"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::vault"]},
        {"Effect": "Deny", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::vault"]},
    ]})
    grants, findings = effective_grants(doc)
    assert grants == set(), [ (g.resource, g.priv) for g in grants ]
    assert any(f.title == "explicit deny overrides an allow" for f in findings), \
        "취소했다는 사실이 사라지면 안 된다 — 왜 권한이 없는지 설명이 필요하다"


def test_deny_only_narrows_nothing_but_is_reported():
    """아무것도 취소하지 않는 Deny 는 무해하지만, 정책이 제한하는 것처럼 읽힌다."""
    doc = _ident("bob", policy={"Statement": [
        {"Effect": "Deny", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::vault"]},
    ]})
    grants, findings = effective_grants(doc)
    assert grants == set()
    assert any(f.title == "deny without a matching allow" for f in findings)


def test_deny_on_one_action_leaves_the_others():
    doc = _ident("carol", policy={"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
         "Resource": ["arn:aws:s3:::vault"]},
        {"Effect": "Deny", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::vault"]},
    ]})
    grants, _ = effective_grants(doc)
    assert {g.priv for g in grants} == {"Read"}, {g.priv for g in grants}


def test_unknown_effect_is_reported_not_assumed():
    """Allow 도 Deny 도 아닌 것을 조용히 무시하면 어느 방향으로든 틀릴 수 있다."""
    doc = _ident("dave", policy={"Statement": [
        {"Effect": "Maybe", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::vault"]},
    ]})
    _, findings = effective_grants(doc)
    assert any(f.title == "policy statement with an unknown effect" for f in findings)


def test_clickhouse_global_grant_is_not_filtered_away():
    """`GRANT … ON *.*` 은 database 가 비어 있다. 그걸 거르면 **가장 강한 권한**이 사라진다.

    실측: 프로덕션에서 12건(researcher 4 · airflow_loader 4 · inspector 3 · default 1)이
    매트릭스에 없었다.
    """
    from grantline.adapters.clickhouse import ClickHouseAdapter
    a = ClickHouseAdapter.__new__(ClickHouseAdapter)
    a.cfg = {}
    # columns as the adapter's query returns them: subject, is_user, access, db, table
    rows = [["researcher", "1", "SELECT", "", ""],          # ON *.*
            ["loader", "1", "INSERT", "logs", ""],          # ON logs.*
            ["loader", "1", "SELECT", "logs", "events"]]    # ON logs.events
    a._query = lambda sql, admin=False: (
        rows if "system.grants" in sql else
        [] if "role_grants" in sql else [["logs"]])
    grants, _, _ = a._observe()
    got = {(g.subject, g.resource, g.priv) for g in grants}
    assert ("researcher", "global:*", "SELECT") in got, got
    assert ("loader", "db:logs", "INSERT") in got
    assert ("loader", "table:logs.events", "SELECT") in got, \
        "테이블 단위 grant 가 DB 단위로 뭉개지면 실제보다 넓게 보고된다"


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
    print("all tests passed")


def test_postgres_table_grants_come_from_the_catalog_not_a_filtered_view():
    """`information_schema.role_table_grants` 는 **관찰자 시야로 잘린다.**

    그 뷰는 현재 활성 롤이 grantor/grantee 인 행만 돌려준다. 읽기 전용 계정으로 보면
    남들끼리의 grant 가 통째로 빠지고, 그 부재가 '권한 없음' 으로 렌더된다.

    실측(analytics DB, inspector 계정):
        information_schema  20 건
        pg_class.relacl    628 건      ← 96.8% 가 안 보이고 있었다
    """
    from grantline.adapters import postgres as pg
    sql = pg._TABLE_GRANT_SQL
    assert "information_schema.role_table_grants" not in sql, \
        "관찰자 시야로 잘리는 뷰를 쓰면 안 된다"
    assert "pg_class" in sql and "aclexplode" in sql, \
        "db·schema ACL 과 같은 방식(pg_catalog + aclexplode)으로 읽어야 한다"
    # relacl 이 NULL 이면 '소유자만' 이다 — 실체화하지 않으면 소유자 권한이 빠진다.
    assert "acldefault('r'" in sql
    # 그 사실이 explicit 과 구분돼야 한다.
    assert "relacl IS NULL" in sql
