"""filer 트리에 쓰기 — 신원 파일 하나만, 정책을 든 신원은 거부.

트리 플레인은 통째로 읽기 전용이었다. 열되, 열리는 것은 딱 하나여야 한다:
**그 신원 자신의 파일의 `actions`**.

두 가지가 이 테스트의 존재 이유다.

1. `read()` 가 돌려주는 것은 *합본*이다 — 신원의 `policy` 는 인라인 문서와 그가 속한
   모든 그룹이 붙인 관리형 문서의 합이다. 그걸 그대로 어딘가에 되쓰면 상속받은
   접근이 그 신원 자신의 것으로 굳는다.
2. 정책을 든 신원은 SeaweedFS 가 `actions` 를 아예 무시한다. 그러니 고쳐야 할 것은
   정책 문서인데 **그 문서는 그룹 전원이 공유한다.** 한 사람의 grant 로 그걸 다시
   쓰면 같은 그룹의 다른 사람들 접근이 조용히 함께 바뀐다.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grantline.adapters.s3 import S3ConfigAdapter  # noqa: E402
from grantline.diff import Change  # noqa: E402
from grantline.model import Grant  # noqa: E402


def t(name, cond):
    assert cond, name
    print("ok ", name)


TREE = {
    "identities": [
        # 정책이 없다 → native actions 가 곧 집행되는 것. 쓰기 대상.
        {"name": "plain", "actions": ["Read:bucket-a"], "credentials": [], "groups": []},
        # 그룹이 붙인 정책을 든다 → actions 는 무시된다. 쓰기 거부 대상.
        {"name": "policied", "actions": [], "credentials": [], "groups": ["team"],
         "policy": {"Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                                   "Resource": ["arn:aws:s3:::warehouse/*"]}]}},
    ],
}


class _Plane:
    """filer 플레인 흉내 — 무엇이 어디로 쓰였는지만 기록한다."""

    filer_url_key = "filer_url_env"

    def __init__(self):
        self.written: list[dict] = []
        self.merged: list[dict] = []

    def read(self):
        return json.loads(json.dumps(TREE))  # 깊은 사본: 호출자가 고쳐도 원본은 그대로

    def write_identity(self, ident):
        self.written.append(json.loads(json.dumps(ident)))

    def write(self, doc):
        self.merged.append(doc)


def _adapter():
    a = S3ConfigAdapter({"enforced": "dynamic", "planes": {"dynamic": {"file": "/dev/null"}}})
    a.planes = {"dynamic": _Plane()}
    return a


def test_grant_writes_one_identity_file_not_the_merged_document():
    a = _adapter()
    g = Grant("s3", "plain", "bucket:bucket-b", "Write")
    a.apply(Change("grant", g, "cmd"))
    plane = a.planes["dynamic"]
    t("합본 문서를 쓰지 않는다", plane.merged == [])
    t("신원 파일 하나를 쓴다", len(plane.written) == 1)
    w = plane.written[0]
    t("쓴 것은 그 신원이다", w["name"] == "plain")
    t("기존 action 이 남는다", "Read:bucket-a" in w["actions"])
    t("새 action 이 붙는다", "Write:bucket-b" in w["actions"])


def test_revoke_removes_only_the_named_action():
    a = _adapter()
    g = Grant("s3", "plain", "bucket:bucket-a", "Read")
    a.apply(Change("revoke", g, "cmd"))
    w = a.planes["dynamic"].written[0]
    t("회수한 action 이 사라진다", "Read:bucket-a" not in w["actions"])


def test_policy_backed_identity_is_refused_never_silently_rewritten():
    """가장 중요한 줄. 조용히 성공하는 것이 최악이다."""
    a = _adapter()
    g = Grant("s3", "policied", "bucket:warehouse/other", "Read")
    try:
        a.apply(Change("grant", g, "cmd"))
    except SystemExit as exc:
        msg = str(exc)
        t("거부한다", True)
        t("왜인지 말한다 — 정책이 actions 를 가린다", "polic" in msg.lower())
        t("그룹이 공유한다는 사실을 말한다", "group" in msg.lower() or "member" in msg.lower())
    else:
        t("정책을 든 신원에 쓰면 안 된다", False)
    t("아무것도 쓰이지 않았다",
      a.planes["dynamic"].written == [] and a.planes["dynamic"].merged == [])


def test_jwt_is_minted_only_when_the_config_names_a_key():
    """filer 는 GET 을 열어 두고 변경만 서명을 요구한다 — 그 자격은 따로 이름을 갖는다."""
    from grantline.adapters.s3 import _Plane as RealPlane

    p = RealPlane("dynamic", {"filer_url_env": "X"})
    t("키를 안 정했으면 토큰도 없다", p._filer_jwt() is None)

    os.environ["ATLAS_TEST_FILER_JWT"] = "s3cr3t-signing-key"
    try:
        p = RealPlane("dynamic", {"filer_url_env": "X",
                                  "admin_filer_jwt_env": "ATLAS_TEST_FILER_JWT"})
        tok = p._filer_jwt()
        t("세 조각짜리 JWT 다", tok is not None and tok.count(".") == 2)
        import base64
        head, claims, _ = tok.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        t("HS256 이다", json.loads(base64.urlsafe_b64decode(pad(head)))["alg"] == "HS256")
        body = json.loads(base64.urlsafe_b64decode(pad(claims)))
        # 요청 하나보다 오래 사는 토큰은 굴러다니는 자격이다.
        import time
        t("수명이 짧다", 0 < body["exp"] - int(time.time()) <= 60)
        t("서명 키가 토큰 안에 있지 않다", "s3cr3t-signing-key" not in tok)
    finally:
        os.environ.pop("ATLAS_TEST_FILER_JWT", None)


for fn in list(globals().values()):
    if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
        fn()
print("ok")
