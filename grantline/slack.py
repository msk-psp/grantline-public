"""Slack, stdlib only. One function: post a message (channel or a user's DM by user ID).
No token → returns an empty status. Approval callers never print bearer links by default."""
from __future__ import annotations

import json
import os
import urllib.request


def post(cfg: dict | None, to: str, text: str) -> str | None:
    """-> message ts on success, "" if no token configured, or an error string.

    `redirect_to` sends every message to one person instead — for piloting the flow
    before the real approvers are told about it. The approver list is unchanged and
    each approver's own link still exists; they all arrive in one inbox, each saying
    who it was meant for. Silently swallowing the intended recipient would make the
    pilot lie about who is being asked."""
    if not cfg or not cfg.get("bot_token_env"):
        return ""
    token = os.environ.get(cfg["bot_token_env"])
    if not token:
        return ""
    if cfg.get("redirect_to") and cfg["redirect_to"] != to:
        text = f"(for {to} — piloting, all notifications come here)\n{text}"
        to = cfg["redirect_to"]
    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage",
        data=json.dumps({"channel": to, "text": text}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json; charset=utf-8"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = json.loads(r.read())
    except Exception as exc:  # network is the caller's problem to report, not to hide
        return f"error: {exc}"
    return body.get("ts", "") if body.get("ok") else f"error: {body.get('error')}"
