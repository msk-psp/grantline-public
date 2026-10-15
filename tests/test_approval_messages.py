"""Localized approvals keep raw identities and private bearer links intact."""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline.approvals import Approvals, Request
from grantline.i18n import catalog, language
from grantline.pages import queue_sections, render_approve, render_requested


def test_localized_messages_and_identity():
    with tempfile.TemporaryDirectory() as directory:
        reviewer = "U_REVIEWER"
        display = "@demo-reviewer"
        names = {reviewer: display, "demo-user": display}
        ap = Approvals({"admin": [reviewer], "names": names}, Path(directory),
                       {"language": "ko", "channel": "C_TEAM", "redirect_to": "U_OTHER"})
        req = Request("20261012T120000Z-abcdef", "2026-10-12T12:00:00Z", "demo-user", "grant",
                      "s3", "demo-user", "bucket:projects/demo/<unsafe>", "Read", "read <unsafe>",
                      required={reviewer: "private-approval-token"}, names=names)
        ap.save(req)
        original_language = language.get()
        with patch("grantline.approvals.slack.post", return_value="1.0") as post:
            statuses = ap.notify(req)
        assert language.get() == original_language
        dm, channel = post.call_args_list
        assert dm.args[1] == reviewer
        assert "redirect_to" not in dm.args[0]
        assert f"요청자: `{display}`" in dm.args[2]
        assert "리소스: `s3://projects/demo/&lt;unsafe&gt;`" in dm.args[2]
        assert "권한: `Read`" in dm.args[2]
        assert "승인 또는 거절" in dm.args[2]
        assert req.required[reviewer] in dm.args[2]
        assert req.required[reviewer] not in channel.args[2]
        assert statuses == [f"{display}: 전송 완료"]
        assert "private-approval-token" not in str(statuses)
        tok = language.set("ko")
        try:
            page = render_approve(req, reviewer)
            assert f"{display} 이름으로 승인" in page
            assert reviewer not in page
            assert "&lt;unsafe&gt;" in page and "<unsafe>" not in page
            assert display in render_requested(req, statuses)
            assert display in "".join(queue_sections([req]))
            approved, who = ap.decide(req.id, req.required[reviewer], True)
            assert who == reviewer and who in approved.approved
        finally:
            language.reset(tok)
        # Requests stored before display-name support still load with current names.
        old = json.loads(ap._path(req.id).read_text())
        old.pop("names")
        ap._path(req.id).write_text(json.dumps(old))
        assert ap.load(req.id).display_name(who) == display
        assert ap.all()[0].display_name(who) == display


def test_notification_restores_language_on_error():
    ap = Approvals({"admin": ["U1"]}, Path("."), {"language": "ko"})
    req = Request("20261012T120000Z-abcdef", "", "me", "grant", "postgres", "me", "db:analytics", "SELECT", "cmd", required={"U1": "secret"})
    previous = language.get()
    with patch("grantline.approvals.slack.post", side_effect=RuntimeError("network")):
        try:
            ap.notify(req)
        except RuntimeError:
            pass
    assert language.get() == previous


def test_catalog_key_parity():
    assert set(catalog("ko")) == set(catalog("ja")) == set(catalog("zh-CN"))


if __name__ == "__main__":
    test_localized_messages_and_identity()
    test_notification_restores_language_on_error()
    test_catalog_key_parity()
    print("ok localized approval messages, identities and private links")
