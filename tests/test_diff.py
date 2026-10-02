"""Self-check for the convergence engine. Run: python tests/test_diff.py"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from grantline.adapters import postgres
from grantline.diff import plan
from grantline.intent import DEFAULT_SYNONYMS, Intent
from grantline.model import Grant


class Cmds:  # minimal adapter double
    grant_cmd = staticmethod(postgres.grant_cmd)
    revoke_cmd = staticmethod(postgres.revoke_cmd)


ADAPTERS = {"postgres": Cmds()}


def make_intent(grants, managed, managed_systems=None):
    return Intent(set(grants), set(managed), DEFAULT_SYNONYMS,
                  managed_systems=managed_systems)


def test_revokes_are_enumerated_by_name():
    intent = make_intent([Grant("postgres", "alice", "role:analyst_read", "MEMBER")],
                         ["alice", "bob"])
    observed = {Grant("postgres", "alice", "role:analyst_read", "MEMBER"),
                Grant("postgres", "bob", "role:analyst_write", "MEMBER")}
    changes, _, _ = plan(intent, observed, ADAPTERS)
    assert [(c.action, c.cmd) for c in changes] == \
        [("revoke", 'REVOKE "analyst_write" FROM "bob";')]


def test_implicit_defaults_are_revoked_and_unmanaged_is_only_reported():
    # 빈 선언 + managed_systems — "postgres 에서 PUBLIC 은 아무것도 갖지 않아야 한다".
    # managed_systems 없이 빈 intent 면 침묵이지 회수 명령이 아니다(diff.py 주석 참조).
    intent = make_intent([], ["PUBLIC"], managed_systems={"postgres"})
    observed = {Grant("postgres", "PUBLIC", "db:analytics", "TEMPORARY", "implicit"),
                Grant("postgres", "superuser", "db:analytics", "CONNECT")}
    changes, findings, _ = plan(intent, observed, ADAPTERS)
    assert [c.cmd for c in changes] == \
        ["REVOKE TEMPORARY ON DATABASE \"analytics\" FROM PUBLIC;"]
    assert any(f.title == "unmanaged drift" and "superuser" in f.detail for f in findings)


def test_implicit_source_matching_intent_is_not_drift():
    g = Grant("postgres", "PUBLIC", "db:analytics", "CONNECT")
    intent = make_intent([g], ["PUBLIC"])
    observed = {Grant("postgres", "PUBLIC", "db:analytics", "CONNECT", "implicit")}
    changes, _, _ = plan(intent, observed, ADAPTERS)
    assert changes == []


def test_default_privs_on_group_role_is_linted():
    intent = make_intent(
        [Grant("postgres", "bob", "role:analyst_write", "MEMBER"),
         Grant("postgres", "analyst_read", "default:analytics.public@analyst_write", "SELECT")],
        ["bob"])
    _, findings, _ = plan(intent, intent.grants, ADAPTERS)
    assert any(f.title == "default privileges on a group role" for f in findings)


def test_naming_drift_between_synonym_suffixes():
    intent = make_intent([Grant("postgres", "alice", "role:analyst_read", "MEMBER")], [])
    observed = {Grant("postgres", "bob", "role:analyst_reader", "MEMBER")}
    _, findings, _ = plan(intent, observed, ADAPTERS)
    assert any(f.title == "naming drift" and "'analyst'" in f.detail for f in findings)



def test_silence_about_a_system_is_not_a_mandate_to_revoke():
    """선언하지 않은 시스템의 권한은 회수하지 않는다.

    실측: S3 만 선언한 intent 가 같은 사람들의 PostgreSQL 권한 61건을 회수 계획에
    올렸다. 그 롤들은 다른 곳에서 관리되고 있었다. "이 파일이 postgres 얘기를 안 한다"
    와 "postgres 는 비어야 한다" 는 다른 말이고, 뒤엣것만 명령이다.
    """
    intent = make_intent([Grant("s3", "alice", "bucket:data", "Read")], ["alice"])
    observed = {Grant("s3", "alice", "bucket:data", "Read"),
                Grant("postgres", "alice", "role:analyst_read", "MEMBER")}
    changes, findings, _ = plan(intent, observed, ADAPTERS)
    assert changes == [], [c.cmd for c in changes]
    assert any(f.title == "undeclared system for a managed subject" for f in findings)


def test_declaring_anything_in_a_system_makes_it_described():
    """그 시스템에 한 줄이라도 쓰면 '기술한다' 는 뜻이다 — 나머지는 회수된다."""
    intent = make_intent([Grant("postgres", "alice", "role:analyst_read", "MEMBER")],
                         ["alice", "bob"])
    observed = {Grant("postgres", "alice", "role:analyst_read", "MEMBER"),
                Grant("postgres", "bob", "role:analyst_write", "MEMBER")}
    changes, _, _ = plan(intent, observed, ADAPTERS)
    assert [c.action for c in changes] == ["revoke"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all tests passed")
