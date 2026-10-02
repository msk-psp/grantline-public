"""N1 — 읽기 경로가 쓰기 자격을 해결하는 일은 없다. s3 도 예외가 아니다.

s3 HTTP 플레인은 읽기와 쓰기가 같은 `url_env` 를 썼다. 그 플레인이 읽히면 자동으로
쓰기 가능이라, "읽기 자격만 준 배포" 를 설정으로 표현할 방법이 없었다. postgres 는
`admin_dsn_env`, clickhouse 는 `admin_url_env` 로 갈라져 있는데 s3 만 없었다.

여기서 확인하는 것은 두 가지다 — 갈라졌는가, 그리고 **폴백이 없는가.** 조용한
폴백은 이 분리를 없애는 것과 같다.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grantline.act import propose  # noqa: E402
from grantline.adapters.s3 import S3ConfigAdapter  # noqa: E402
from grantline.model import Grant  # noqa: E402


def t(name, cond):
    assert cond, name
    print("ok ", name)


def _http(**plane):
    return S3ConfigAdapter({"enforced": "dynamic", "planes": {"dynamic": plane}})


def test_reading_a_plane_no_longer_confers_writing_it():
    """읽기 자격만 있는 배포 — 그 플레인은 읽히지만 쓰기 버튼은 살면 안 된다."""
    os.environ["GRANTLINE_TEST_S3_URL"] = "http://iam.example/config"
    a = _http(url_env="GRANTLINE_TEST_S3_URL")
    ready, note = a.write_ready()
    t("읽기 자격만 있으면 쓰기 준비가 아니다", ready is False)
    t("이유가 admin_url_env 를 지목한다", "admin_url_env" in note)
    t("읽기 변수로 대신 쓰겠다고 하지 않는다", "GRANTLINE_TEST_S3_URL" not in note)


def test_write_credential_named_but_absent_is_still_read_only():
    os.environ["GRANTLINE_TEST_S3_URL"] = "http://iam.example/config"
    os.environ.pop("GRANTLINE_TEST_S3_ADMIN", None)
    a = _http(url_env="GRANTLINE_TEST_S3_URL", admin_url_env="GRANTLINE_TEST_S3_ADMIN")
    ready, note = a.write_ready()
    t("이름만 있고 값이 없으면 쓰기 불가", ready is False)
    t("어느 변수가 비었는지 말한다", "GRANTLINE_TEST_S3_ADMIN" in note)


def test_write_credential_present_makes_the_plane_writable():
    os.environ["GRANTLINE_TEST_S3_URL"] = "http://iam.example/config"
    os.environ["GRANTLINE_TEST_S3_ADMIN"] = "http://admin@iam.example/config"
    try:
        a = _http(url_env="GRANTLINE_TEST_S3_URL", admin_url_env="GRANTLINE_TEST_S3_ADMIN")
        ready, note = a.write_ready()
        t("쓰기 자격이 있으면 쓰기 가능", ready is True)
        t("값이 아니라 변수 이름만 말한다",
          "GRANTLINE_TEST_S3_ADMIN" in note and "admin@iam.example" not in note)
    finally:
        os.environ.pop("GRANTLINE_TEST_S3_ADMIN", None)


def test_the_read_path_never_resolves_the_write_variable():
    """N1 그대로 — 관찰은 쓰기 변수가 없어도 끝까지 간다. 건드리지 않으니까.

    쓰기 변수가 설정에 이름만 있고 값이 없는 상태에서 read() 를 부른다. 읽기가
    그 변수를 해결하려 든다면 SystemExit('environment variable … is not set') 로
    죽는다. 실제로 나야 하는 것은 읽기 URL 로 나간 요청의 연결 실패다.
    """
    os.environ["GRANTLINE_TEST_S3_URL"] = "http://127.0.0.1:9/nothing-here"
    os.environ.pop("GRANTLINE_TEST_S3_ADMIN", None)
    a = _http(url_env="GRANTLINE_TEST_S3_URL", admin_url_env="GRANTLINE_TEST_S3_ADMIN",
              admin_auth_env="GRANTLINE_TEST_S3_ADMIN_TOKEN")
    try:
        a.planes["dynamic"].read()
        raised = None
    except SystemExit as exc:
        raised = ("config", str(exc))
    except OSError as exc:
        raised = ("network", str(exc))
    t("읽기가 쓰기 변수를 해결하려 들지 않는다", raised is not None and raised[0] == "network")


def test_the_write_path_does_not_fall_back_to_the_read_credential():
    """폴백이 있으면 분리는 없는 것과 같다 — 읽을 수 있으면 쓸 수 있게 되니까."""
    os.environ["GRANTLINE_TEST_S3_URL"] = "http://127.0.0.1:9/nothing-here"
    os.environ["GRANTLINE_TEST_S3_TOKEN"] = "readonly-token"
    a = _http(url_env="GRANTLINE_TEST_S3_URL", auth_env="GRANTLINE_TEST_S3_TOKEN")
    try:
        a.planes["dynamic"].write({"identities": []})
        msg = ""
    except SystemExit as exc:
        msg = str(exc)
    except OSError:
        msg = "!! a request went out"
    t("쓰기 자격이 없으면 요청 자체가 안 나간다", msg.startswith("adapter config missing"))
    t("빠진 것이 admin_url_env 라고 말한다", "admin_url_env" in msg)


def test_preview_still_works_without_any_write_credential():
    """읽기 전용 배포에서도 명령은 보여야 한다 — 붙여넣을 수 있는 것이 이 도구의 최소값(N3)."""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "identities.json"
        f.write_text('{"identities": [{"name": "researcher_a", "actions": ["Read:warehouse"]}]}')
        a = S3ConfigAdapter({"enforced": "static", "planes": {"static": {"file": str(f)}}})
        f.chmod(0o444)
        try:
            p = propose("grant", "s3", "researcher_a", "bucket:warehouse", "Write",
                        set(), {"s3": a})
            t("명령은 나온다", "warehouse" in p.cmd)
            t("버튼은 안 산다", p.ready is False)
            t("파일 권한이 자격이라고 말한다", "credential" in p.ready_note)
        finally:
            f.chmod(0o644)


def test_a_writable_file_plane_writes():
    """파일 플레인은 파일 권한이 곧 자격이다 — 별도 opt-in 키를 두지 않는다.

    쓸 수 있는 것은 OS 가 정하고, 설정의 `writable = true` 같은 플래그는 OS 가
    언제든 반박할 수 있는 주장이다. 읽기 전용 배포는 파일을 읽기 전용으로 만들어
    한다 (위 테스트).
    """
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "identities.json"
        f.write_text('{"identities": [{"name": "researcher_a", "actions": []}]}')
        a = S3ConfigAdapter({"enforced": "static", "planes": {"static": {"file": str(f)}}})
        t("쓸 수 있는 파일은 쓰기 가능", a.write_ready()[0] is True)

        from grantline.diff import Change
        g = Grant("s3", "researcher_a", "bucket:warehouse", "Read")
        a.apply(Change("grant", g, a.grant_cmd(g)))
        t("실제로 파일에 반영된다", "Read:warehouse" in f.read_text())


def test_the_non_enforced_plane_is_never_the_one_asked_about():
    """쓰기는 게이트웨이가 참조하는 플레인에만 간다. 다른 플레인의 자격은 답이 아니다."""
    os.environ["GRANTLINE_TEST_S3_OTHER_ADMIN"] = "http://admin@other/config"
    try:
        a = S3ConfigAdapter({"enforced": "dynamic", "planes": {
            "static": {"admin_url_env": "GRANTLINE_TEST_S3_OTHER_ADMIN"},
            "dynamic": {"url_env": "GRANTLINE_TEST_S3_URL"}}})
        ready, note = a.write_ready()
        t("다른 플레인의 쓰기 자격으로 쓰기 가능이 되지 않는다", ready is False)
        t("지목된 플레인은 enforced 쪽이다", "admin_url_env" in note)
    finally:
        os.environ.pop("GRANTLINE_TEST_S3_OTHER_ADMIN", None)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("all tests passed")
