"""`write_scope = "roles"` — 콘솔이 표현할 수 있는 것을 좁혀 자격을 좁힌다.

임의의 권한을 부여하려면 그 권한을 **스스로 들고 있어야 한다**. PostgreSQL 도
(소유자이거나 grant option) ClickHouse 도("가진 범위 안에서만 넘겨줄 수 있다") 같다.
그러니 "아무거나 줄 수 있다" 는 곧 "전부 들고 있다" 이고, 계정을 몇 개로 쪼개도
이 계산은 안 바뀐다.

예외가 하나 있다 — **역할 멤버십**. ClickHouse `ROLE ADMIN` 과 PostgreSQL 의
NOINHERIT + ADMIN OPTION 은 **데이터 접근을 하나도 안 들고** 역할을 부여·회수한다.
그래서 콘솔은 직접 객체 권한을 포기하고, 그 대가로 자격이 관리자가 아니게 된다.

여기서 확인하는 것: 좁혔을 때 **거부하되 명령은 보여준다**. 빈 화면보다 "이게 돌
명령이고, 이 콘솔이 그걸 돌리지 않는 이유는 이것" 이 놀라움이 작다.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grantline.act import propose  # noqa: E402
from grantline.adapters.postgres import PostgresAdapter  # noqa: E402


def t(name, cond):
    assert cond, name
    print("ok ", name)


def _pg(**cfg):
    return {"postgres": PostgresAdapter({"dsn_env": "NOPE", **cfg}, "postgres")}


def test_unscoped_console_still_proposes_a_direct_grant():
    """기본값은 안 바뀐다 — 좁히기는 설정으로 켜는 것이다."""
    p = propose("grant", "postgres", "researcher_d", "db:analytics", "CONNECT", set(), _pg())
    t("명령이 나온다", "GRANT" in p.cmd and "analytics" in p.cmd)
    t("막지 않는다", p.blocked == "")


def test_roles_scope_refuses_a_direct_object_grant_but_shows_the_command():
    p = propose("grant", "postgres", "researcher_d", "db:analytics", "CONNECT", set(),
                _pg(write_scope="roles"))
    t("명령은 그대로 보여준다", "GRANT" in p.cmd and "analytics" in p.cmd)
    t("막는다", p.blocked != "")
    t("무엇이 역할이 아닌지 말한다", "db:analytics" in p.blocked)
    t("자격이 좁다는 이유를 말한다", "credential" in p.blocked)
    t("대안을 말한다", "role" in p.blocked)


def test_roles_scope_allows_membership():
    p = propose("grant", "postgres", "researcher_d", "role:research_researcher", "MEMBER", set(),
                _pg(write_scope="roles"))
    t("역할 부여는 통과한다", p.blocked == "")
    t("멤버십 명령이다", "GRANT" in p.cmd and "research_researcher" in p.cmd)


def test_revoke_is_narrowed_the_same_way():
    p = propose("revoke", "postgres", "researcher_d", "db:analytics", "CONNECT", set(),
                _pg(write_scope="roles"))
    t("회수도 똑같이 막힌다", p.blocked != "")
    t("동사가 문장에 반영된다", "revoke" in p.blocked)


def test_scope_refusal_wins_over_the_other_verdicts():
    """이미 갖고 있든 아니든 결론은 같다 — 이 콘솔은 그걸 안 만진다."""
    from grantline.model import Grant

    held = {Grant("postgres", "researcher_d", "db:analytics", "CONNECT")}
    p = propose("grant", "postgres", "researcher_d", "db:analytics", "CONNECT", held,
                _pg(write_scope="roles"))
    t("범위 거부가 먼저다", "already holds" not in p.blocked)
    t("여전히 막혀 있다", p.blocked != "")


for fn in list(globals().values()):
    if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
        fn()
print("ok")
