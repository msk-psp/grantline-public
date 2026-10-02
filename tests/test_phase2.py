"""Phase 2 self-checks: unobserved scopes, S3 dual planes, policy-over-actions.
Run: python3 tests/test_phase2.py"""
import json
import os
import pathlib
import sys
import tempfile
import types

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from grantline.adapters import postgres
from grantline.adapters.s3 import S3ConfigAdapter, effective_grants, policy_with
from grantline.diff import plan
from grantline.intent import DEFAULT_SYNONYMS, Intent
from grantline.model import Grant, Unobserved


class Cmds:
    grant_cmd = staticmethod(postgres.grant_cmd)
    revoke_cmd = staticmethod(postgres.revoke_cmd)


def test_unobserved_is_not_no_access():
    """'could not check' must neither plan grants (spurious) nor revokes
    (unenumerable), and must be reported separately from 'no access'."""
    intent = Intent({
        Grant("postgres", "carol", "table:hr.public.salaries", "SELECT"),   # blind scope
        Grant("postgres", "carol", "table:analytics.public.events", "SELECT"),  # visible
    }, {"carol", "mallory"}, DEFAULT_SYNONYMS)
    observed = {  # stale data inside the blind scope must NOT be revoked either
        Grant("postgres", "mallory", "table:hr.public.salaries", "SELECT"),
    }
    blind = [Unobserved("postgres", ("table:hr.", "schema:hr.", "default:hr."),
                        "connection refused")]
    changes, findings, unverified = plan(intent, observed, {"postgres": Cmds()}, blind)

    assert [c.grant.resource for c in changes] == ["table:analytics.public.events"], \
        "only the visible scope is planned"
    assert all(not c.grant.resource.startswith("table:hr.") for c in changes), \
        "no grant AND no revoke inside the unobserved scope"
    assert [g.resource for g in unverified] == ["table:hr.public.salaries"]
    assert any(f.title == "unobserved scope" for f in findings)


def test_matrix_shows_enforced_not_declared():
    """An identity with both native actions and a policy: the policy is what
    the server enforces, so observation must return policy grants only."""
    doc = {"identities": [{
        "name": "svc_etl",
        "actions": ["Admin"],  # written, but dead — policy shadows it
        "policy": {"Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"],
                                  "Resource": ["arn:aws:s3:::data-lake/raw/*"]}]},
    }]}
    grants, findings = effective_grants(doc)
    # Both spellings land on one canonical resource (model.canonical), so this
    # compares equal whichever way it is written.
    assert grants == {Grant("s3", "svc_etl", "bucket:data-lake/raw/*", "Write")}
    assert all(g.source == "policy" for g in grants)
    assert not any(g.priv == "Admin" for g in grants), "shadowed Admin must not appear"
    assert any(f.title == "native actions shadowed by policy" for f in findings)


def test_policy_with_roundtrip():
    pol = {"Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"],
                          "Resource": ["arn:aws:s3:::b/raw/*"]}]}
    g = Grant("s3", "x", "bucket:b/curated/*", "Read")
    added = policy_with(pol, g, add=True)
    assert {"Effect": "Allow", "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::b/curated/*"]} in added["Statement"]
    assert policy_with(added, g, add=False) == pol, "revoke undoes grant"
    assert pol["Statement"][0]["Action"] == ["s3:PutObject"], "input not mutated"


def test_s3_write_targets_policy_when_policy_exists():
    """Granting to a policy-bearing identity must mutate the POLICY (and the
    plan must show a policy diff); touching the dead action list would lie."""
    with tempfile.TemporaryDirectory() as tmp:
        enforced = pathlib.Path(tmp) / "dynamic.json"
        enforced.write_text(json.dumps({"identities": [{
            "name": "svc_etl", "actions": ["Admin"],
            "policy": {"Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"],
                                      "Resource": ["arn:aws:s3:::data-lake/raw/*"]}]},
        }]}))
        adapter = S3ConfigAdapter({
            "enforced": "dynamic",
            "planes": {"dynamic": {"file": str(enforced)}},
        })
        g = Grant("s3", "svc_etl", "bucket:data-lake/curated/*", "Read")

        cmd = adapter.grant_cmd(g)
        assert "PUT policy" in cmd and "+++ svc_etl.policy (planned)" in cmd, \
            "plan shows an old->new policy diff"

        adapter.apply(types.SimpleNamespace(action="grant", grant=g, cmd=cmd))

        after = json.loads(enforced.read_text())["identities"][0]
        assert after["actions"] == ["Admin"], "dead action list left untouched"
        grants, _ = effective_grants({"identities": [after]})
        assert Grant("s3", "svc_etl", "bucket:data-lake/curated/*", "Read") in grants, \
            "apply -> observe converges through the policy"


def test_s3_plane_mismatch_and_enforced_source():
    with tempfile.TemporaryDirectory() as tmp:
        static = pathlib.Path(tmp) / "static.json"
        dynamic = pathlib.Path(tmp) / "dynamic.json"
        static.write_text(json.dumps({"identities": [{"name": "alice", "actions": ["Read:b"]},
                                                     {"name": "ghost", "actions": ["Read:b"]}]}))
        dynamic.write_text(json.dumps({"identities": [{"name": "alice", "actions": ["List:b"]}]}))
        adapter = S3ConfigAdapter({
            "enforced": "dynamic",
            "planes": {"static": {"file": str(static)}, "dynamic": {"file": str(dynamic)}},
        })
        grants, findings, unobserved = adapter.observe()
        assert grants == {Grant("s3", "alice", "bucket:b", "List")}, \
            "grants come from the ENFORCED plane only"
        assert any(f.title == "identity missing from the enforced plane" and "ghost" in f.detail
                   for f in findings)
        assert unobserved == []



def test_enforced_plane_only_identity_is_not_flagged():
    """강제 평면에만 있는 신원은 **정상**이다 — 그게 게이트웨이가 보는 평면이다.

    이걸 경고로 올리면 실환경에서 신원 수만큼 finding 이 나온다(실측: 20개가
    나머지 전부를 묻어버렸다). 위험한 것은 반대 방향뿐이다.
    """
    with tempfile.TemporaryDirectory() as tmp:
        static = pathlib.Path(tmp) / "static.json"
        dynamic = pathlib.Path(tmp) / "dynamic.json"
        # 실제 배치의 모양: 정적 평면에는 부트스트랩용 admin 하나뿐이고
        # 사람·서비스 신원은 전부 동적(=강제) 평면에 산다.
        static.write_text(json.dumps({"identities": [{"name": "root", "actions": ["Admin"]}]}))
        dynamic.write_text(json.dumps({"identities": [
            {"name": "root", "actions": ["Admin"]},
            {"name": "alice", "actions": ["Read:b"]},
            {"name": "bob", "actions": ["Read:b"]},
        ]}))
        adapter = S3ConfigAdapter({
            "enforced": "dynamic",
            "planes": {"static": {"file": str(static)}, "dynamic": {"file": str(dynamic)}},
        })
        _, findings, _ = adapter.observe()
        assert not [f for f in findings if "enforced plane" in f.title], \
            [f.detail for f in findings]

def test_s3_enforced_plane_down_is_unobserved():
    adapter = S3ConfigAdapter({
        "enforced": "dynamic",
        "planes": {"dynamic": {"file": "/nonexistent/iam.json"}},
    })
    grants, _, unobserved = adapter.observe()
    assert grants == set()
    assert len(unobserved) == 1 and unobserved[0].prefixes == ("bucket:",), \
        "enforced plane down -> whole system unobserved, not silently empty"


def test_postgres_command_routing():
    rdb = postgres._resource_db
    assert rdb(Grant("postgres", "a", "table:analytics.public.events", "SELECT")) == "analytics"
    assert rdb(Grant("postgres", "a", "schema:hr.public", "USAGE")) == "hr"
    assert rdb(Grant("postgres", "a", "default:hr.public@writer", "SELECT")) == "hr"
    assert rdb(Grant("postgres", "a", "db:analytics", "CONNECT")) is None
    assert rdb(Grant("postgres", "a", "role:analyst_read", "MEMBER")) is None


def test_unreachable_clickhouse_is_unknown_not_empty():
    """도달 못 한 서버는 '권한 없음' 이 아니라 '모름' 이다.

    실측: staging 비밀번호를 프로덕션 호스트에 쓰면 403 이 나는데, 예외가 그대로
    올라와 페이지 전체가 죽었다. 반대로 조용히 빈 집합으로 삼키면 매트릭스가 '—' 로
    가득 차 '아무도 권한이 없다' 로 읽힌다 — 그게 더 나쁘다.
    """
    from grantline.adapters.clickhouse import ClickHouseAdapter
    # 설정 누락(env 미설정)은 잡지 않는다 — 사람 실수라 즉시 실패하는 편이 맞다.
    # 여기서 재현하는 것은 **도달 실패**다: 값은 있는데 서버가 거부하거나 없는 경우.
    os.environ["GRANTLINE_TEST_CH_DOWN"] = "http://u:p@127.0.0.1:1/"
    a = ClickHouseAdapter({"url_env": "GRANTLINE_TEST_CH_DOWN"})
    grants, findings, unobserved = a.observe()
    assert grants == set()
    assert unobserved and unobserved[0].system == "clickhouse"
    assert any(f.title == "system could not be read" for f in findings)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all tests passed")

