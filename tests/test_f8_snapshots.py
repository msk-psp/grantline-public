"""F8 — 실행마다 스냅샷, 그리고 다음 실행이 무엇이 움직였는지 말한다.

성공기준은 두 줄이다. 변화를 사이에 둔 두 실행의 diff 가 그 변화를 짚을 것,
그리고 **변하지 않은 것은 하나도 담기지 않을 것.** 수백 건 사이에 섞여 나오는
한 건은 못 찾는 한 건이다.

가장 틀리기 쉬운 자리는 `Unobserved` 다. 오늘 연결이 거절된 DB 의 권한은 어제
그대로 거기 있는데 오늘 관찰에는 없다. 두 집합을 빼면 대량 회수로 보인다.
"""
from __future__ import annotations

import datetime
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from grantline import snapshot as snap  # noqa: E402
from grantline.model import Grant, Unobserved  # noqa: E402
from grantline.pages import render_inventory  # noqa: E402


def t(name, cond):
    assert cond, name
    print("ok ", name)


UTC = datetime.UTC


def _g(subject, resource, priv="SELECT", system="postgres", source="explicit"):
    return Grant(system, subject, resource, priv, source)


def _bulk(n, priv="SELECT"):
    """관찰 한 번에 흔히 있는 규모 — 변화 한 건이 이 안에 묻히면 실패다."""
    return {_g(f"user{i % 7}", f"table:analytics.public.t{i}", priv) for i in range(n)}


def _at(d, when, observed, unobserved=()):
    return snap.write(d, observed, unobserved, {"postgres", "s3"}, now=when)


T0 = datetime.datetime(2026, 8, 15, 9, 0, tzinfo=UTC)
T1 = datetime.datetime(2026, 8, 18, 9, 0, tzinfo=UTC)   # 3일 뒤


# ── 남는가 ────────────────────────────────────────────────────────────────────
def test_a_run_leaves_one_file_and_it_reads_back():
    with tempfile.TemporaryDirectory() as d:
        grants = {_g("researcher_a", "db:analytics", "CONNECT"), _g("researcher_c", "role:analyst", "MEMBER")}
        un = [Unobserved("postgres", ("table:hr.",), "connection refused")]
        written = _at(d, T0, grants, un)
        t("실행 하나가 파일 하나를 남긴다", len(snap.snapshots(d)) == 1)
        t("파일은 line-delimited JSON 이다",
          all(line.startswith("{") for line in written.path.read_text().splitlines()))

        back = snap.load(written.path)
        t("권한이 그대로 돌아온다", back.grants == frozenset(grants))
        t("확인 못 한 스코프도 같이 돌아온다",
          [(u.system, u.prefixes) for u in back.unobserved] == [("postgres", ("table:hr.",))])
        t("시각은 기록된 것을 읽지, 파일 mtime 을 추측하지 않는다", back.ts == T0)


def test_snapshots_go_beside_the_config_and_carry_no_secret():
    """N6 — 스냅샷은 주체·리소스·권한만 적는다. 드라이버가 에러 문자열에 흘린
    자격은 지우고 적는다."""
    with tempfile.TemporaryDirectory() as d:
        un = [Unobserved("postgres", ("db:hr",),
                         "could not connect: postgresql://grantline:hunter2@db:5432/hr")]
        written = _at(d, T0, {_g("researcher_a", "db:analytics", "CONNECT")}, un)
        body = written.path.read_text()
        t("비밀번호가 스냅샷에 남지 않는다", "hunter2" not in body)
        t("무엇이 안 읽혔는지는 남는다", "could not connect" in body and "grantline:***@" in body)


# ── 변한 것만 ────────────────────────────────────────────────────────────────
def test_diff_names_the_change_and_carries_nothing_else():
    """성공기준 그대로 — 300건 사이에 섞인 변화 두 건, 그리고 그 둘뿐."""
    with tempfile.TemporaryDirectory() as d:
        base = _bulk(300)
        gone = _g("user3", "table:analytics.public.t3")
        added = _g("newcomer", "bucket:warehouse", "Write", system="s3")

        a = snap.load(_at(d, T0, base).path)
        b = snap.load(_at(d, T1, (base - {gone}) | {added}).path)
        c = snap.compare(a, b)

        t("추가된 것을 짚는다", c.added == (added,))
        t("없어진 것을 짚는다", c.removed == (gone,))
        t("변하지 않은 것은 0건", c.moved == 2)
        t("주체·리소스가 함께 나온다",
          c.added[0].subject == "newcomer" and c.added[0].resource == "bucket:warehouse")
        t("양쪽 타임스탬프가 붙는다", (c.prev.ts, c.cur.ts) == (T0, T1))


def test_nothing_moved_is_an_empty_diff_not_a_full_listing():
    with tempfile.TemporaryDirectory() as d:
        base = _bulk(120)
        c = snap.compare(snap.load(_at(d, T0, base).path),
                         snap.load(_at(d, T1, base).path))
        t("같은 상태 두 번은 0건", c.moved == 0 and not c.revealed and not c.obscured)


def test_source_is_metadata_and_not_a_change():
    """`Grant.source` 는 compare=False 다 (model.py). 같은 접근을 어댑터가 다르게
    설명했다고 회수+부여로 적으면, 그건 서버가 아니라 어댑터에 대한 보고다."""
    with tempfile.TemporaryDirectory() as d:
        a = snap.load(_at(d, T0, {_g("researcher_a", "bucket:warehouse", "Read",
                                     system="s3", source="explicit")}).path)
        b = snap.load(_at(d, T1, {_g("researcher_a", "bucket:warehouse", "Read",
                                     system="s3", source="policy")}).path)
        t("출처가 바뀐 것은 변화가 아니다", snap.compare(a, b).moved == 0)


# ── 확인 못 한 것을 '없음' 으로 읽지 않는다 (F6) ───────────────────────────────
def test_unreadable_scope_is_not_a_mass_revoke():
    """오늘 DB 하나가 연결을 거절했다. 어제 본 그 안의 권한 40건은 **회수된 게 아니다.**"""
    with tempfile.TemporaryDirectory() as d:
        hr = {_g(f"u{i}", f"table:hr.public.t{i}") for i in range(40)}
        analytics = {_g("researcher_a", "db:analytics", "CONNECT")}
        real = _g("researcher_a", "db:analytics", "TEMPORARY")

        a = snap.load(_at(d, T0, hr | analytics).path)
        b = snap.load(_at(d, T1, analytics | {real},
                         [Unobserved("postgres", ("table:hr.",),
                                     "connection refused")]).path)
        c = snap.compare(a, b)

        t("못 읽은 스코프의 권한이 회수 목록에 들어가지 않는다", c.removed == ())
        t("진짜 변화 한 건만 남는다", c.added == (real,) and c.moved == 1)
        t("사라진 게 아니라 모르는 것으로 따로 센다", len(c.obscured) == 40)


def test_scope_coming_back_into_view_is_not_a_mass_grant():
    """반대 방향도 같다 — 어제 못 읽은 스코프가 오늘 읽혔다고 40건을 새로 부여받은 게 아니다."""
    with tempfile.TemporaryDirectory() as d:
        hr = {_g(f"u{i}", f"table:hr.public.t{i}") for i in range(40)}
        a = snap.load(_at(d, T0, set(),
                         [Unobserved("postgres", ("table:hr.",), "connection refused")]).path)
        b = snap.load(_at(d, T1, hr).path)
        c = snap.compare(a, b)
        t("다시 보인 것은 새 부여가 아니다", c.added == () and len(c.revealed) == 40)


def test_a_system_dropped_from_the_config_is_unread_not_empty():
    """어댑터를 설정에서 뺀 실행은 그 시스템을 '비었다' 고 관찰한 게 아니라 안 본 것이다."""
    with tempfile.TemporaryDirectory() as d:
        s3 = {_g("researcher_a", "bucket:warehouse", "Read", system="s3")}
        a = snap.load(snap.write(d, s3, [], {"postgres", "s3"}, now=T0).path)
        b = snap.load(snap.write(d, set(), [], {"postgres"}, now=T1).path)
        c = snap.compare(a, b)
        t("안 본 시스템의 권한은 회수로 적지 않는다", c.removed == () and len(c.obscured) == 1)


# ── 없는 주기를 있는 척하지 않는다 ────────────────────────────────────────────
def test_the_gap_is_stated_as_elapsed_time_never_as_a_cadence():
    t("3일", snap.ago(datetime.timedelta(days=3)) == "3 days ago")
    t("1일 (복수형 아님)", snap.ago(datetime.timedelta(days=1)) == "1 day ago")
    t("4시간", snap.ago(datetime.timedelta(hours=4)) == "4 hours ago")
    t("방금", snap.ago(datetime.timedelta(seconds=20)) == "moments ago")
    t("두 달", snap.ago(datetime.timedelta(days=61)) == "2 months ago")
    words = " ".join(snap.ago(datetime.timedelta(seconds=s))
                     for s in (30, 600, 7200, 3 * 86400, 200 * 86400))
    t("주기를 뜻하는 말이 안 나온다",
      not any(w in words for w in ("daily", "hourly", "weekly", "nightly",
                                   "schedule", "yesterday", "every")))


class _Rec:
    def __init__(self, comparison=None, error=""):
        self.comparison, self.error, self.snapshot = comparison, error, None


def test_the_page_says_the_interval_is_irregular():
    with tempfile.TemporaryDirectory() as d:
        base = {_g("researcher_a", "db:analytics", "CONNECT")}
        moved = _g("researcher_a", "db:analytics", "TEMPORARY")
        a = snap.load(_at(d, T0, base).path)
        b = snap.load(_at(d, T1, base | {moved}).path)
        html = render_inventory(base | {moved}, _Rec(snap.compare(a, b)))

        t("직전 실행과의 경과를 말한다", "3 days ago" in html)
        t("양쪽 시각을 보여준다", T0.isoformat() in html and T1.isoformat() in html)
        t("없는 주기를 암시하지 않는다", "no schedule" in html
          and not any(w in html for w in ("daily", "yesterday", "every day")))
        t("변화만 화면에 오른다 — 변화 한 건이 한 번만", html.count("TEMPORARY") == 1)
        t("변하지 않은 것은 변화 자리에 안 나온다",
          "+ [postgres] researcher_a CONNECT" not in html)


def test_the_first_run_does_not_pretend_to_have_a_previous_one():
    html = render_inventory({_g("researcher_a", "db:analytics", "CONNECT")}, _Rec(None))
    t("첫 실행이라고 말한다", "first run recorded" in html)
    t("비교한 척하지 않는다", "ago" not in html.split("</header>")[1].split("<h2>")[1][:400]
      or "nothing to compare" in html.lower())


def test_a_snapshot_that_could_not_be_written_does_not_take_the_run_down():
    """기록 못 한 것과 관찰 못 한 것은 다르다 — 뒤엣것만 접근에 대한 사실이다."""
    rec = snap.Recorder("/proc/definitely-not-writable/grantline")
    rec.record({_g("researcher_a", "db:analytics", "CONNECT")}, [], {"postgres"})
    t("예외가 밖으로 새지 않는다", rec.comparison is None)
    t("이유를 남긴다", "no snapshot was written" in rec.error)
    html = render_inventory({_g("researcher_a", "db:analytics", "CONNECT")}, rec)
    t("화면은 그래도 뜬다", "What is granted, by service" in html)
    t("기록이 없다는 사실을 말한다", "not recorded" in html)


# ── 실행 경로 ────────────────────────────────────────────────────────────────
def test_serve_snapshots_once_per_process_not_once_per_request():
    """serve 는 매 요청 관찰한다. 요청마다 스냅샷이면 '직전 실행' 은 '직전 새로고침'
    이 되고, 비교는 언제나 비어 있게 된다."""
    with tempfile.TemporaryDirectory() as d:
        rec = snap.Recorder(d)
        for _ in range(5):  # 페이지 다섯 번 열기
            rec.record({_g("researcher_a", "db:analytics", "CONNECT")}, [], {"postgres"})
        t("프로세스당 한 파일", len(snap.snapshots(d)) == 1)


def test_plan_run_leaves_a_snapshot_through_the_cli_path():
    """관찰이 지나는 한 지점(cli._observe_and_plan)에 걸려 있어야 plan·serve 양쪽이 남긴다."""
    import grantline.cli as cli
    with tempfile.TemporaryDirectory() as d:
        class _A:
            def observe(self):
                return {_g("researcher_a", "db:analytics", "CONNECT")}, [], []
            def grant_cmd(self, g): return "GRANT"
            def revoke_cmd(self, g): return "REVOKE"

        class _I:
            grants, managed, managed_systems, naming_synonyms = set(), set(), set(), []

        rec = snap.Recorder(d)
        out = cli._observe_and_plan(_I(), {"postgres": _A()}, rec)
        # 관측·계획·비교·못 읽은 범위가 한 호출에서 같이 나온다 (지도가 F6 을
        # 말하려면 마지막 것이 필요하다 — web.graph_data)
        t("관찰과 비교가 같은 호출에서 나온다", len(out) == 6 and out[4] is None)
        t("못 읽은 범위도 같이 나온다", out[5] == [])
        t("plan 이 스냅샷을 남긴다", len(snap.snapshots(d)) == 1)
        t("남긴 것이 관찰한 것과 같다",
          snap.load(snap.latest(d)).grants == out[0])


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("all tests passed")
