"""Approval flow — a change is proposed, the people the config names approve it, then it
runs. Two rules from PRD 003 carry over unchanged: the preview *is* the command (N2 —
the request stores the exact string and execution refuses anything else), and only the
named atom is touched (F3).

Who must approve is configuration, not code:

    [approvals]
    store = "approvals"                 # one JSON file per request, beside the config
    console_url = "http://127.0.0.1:8420"
    admin = ["operator"]                  # always required — every request, every system
    [[approvals.rules]]                 # a rule adds approvers when it matches
    match = ["postgres:db:analytics*", "s3:bucket:projects/analytics*"]   # fnmatch on "system:resource"
    approvers = ["U_ANALYTICS_LEAD"]

Required = admin ∪ approvers of every matching rule. Nobody matching means admin alone.
Each approver gets a link carrying their own token; the token is the identity — the
console has no login of its own, and the DM that delivered the link is the proof.

Slack is optional: with `[notify.slack] bot_token_env` set, approvers are DM'd and the
channel is told. Without Slack, a trusted operator securely relays links using
`grantline request --links ID`; requester responses never contain approval tokens.
"""
from __future__ import annotations

import datetime
import fnmatch
import getpass
import json
import os
import re
import secrets
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import slack
from .act import ActError, Proposal, execute


@dataclass
class Request:
    id: str
    ts: str
    requester: str
    action: str
    system: str
    subject: str
    resource: str
    priv: str
    cmd: str
    required: dict = field(default_factory=dict)   # approver -> token
    approved: dict = field(default_factory=dict)   # approver -> ts
    status: str = "pending"                        # pending | approved | executed | denied | failed
    note: str = ""

    @property
    def missing(self) -> list[str]:
        return sorted(a for a in self.required if a not in self.approved)


class Approvals:
    def __init__(self, cfg: dict | None, base: Path, slack_cfg: dict | None = None):
        cfg = cfg or {}
        self.enabled = bool(cfg)
        self.store = (base / cfg.get("store", "approvals")).expanduser()
        self.console_url = cfg.get("console_url", "").rstrip("/")
        self.admin = list(cfg.get("admin", []))
        self.rules = list(cfg.get("rules", []))
        self.slack_cfg = slack_cfg or {}

    # ── who ──────────────────────────────────────────────────────────────────
    def approvers_for(self, system: str, resource: str) -> list[str]:
        key = f"{system}:{resource}"
        who = set(self.admin)
        for rule in self.rules:
            if any(fnmatch.fnmatch(key, pat) for pat in rule.get("match", [])):
                who.update(rule.get("approvers", []))
        return sorted(who)

    # ── store ────────────────────────────────────────────────────────────────
    def _path(self, rid: str) -> Path:
        if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", rid):
            raise ActError("invalid request id")
        return self.store / f"{rid}.json"

    def save(self, req: Request) -> None:
        path = self._path(req.id)
        self.store.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store.chmod(0o700)
        with tempfile.NamedTemporaryFile(mode="w", dir=self.store, delete=False) as tmp:
            try:
                os.chmod(tmp.name, 0o600)
                tmp.write(json.dumps(asdict(req), indent=2) + "\n")
                tmp.flush()
                os.replace(tmp.name, path)
            finally:
                Path(tmp.name).unlink(missing_ok=True)

    def load(self, rid: str) -> Request:
        p = self._path(rid)
        if not p.exists():
            raise ActError(f"no request '{rid}'")
        return Request(**json.loads(p.read_text()))

    def all(self) -> list[Request]:
        if not self.store.is_dir():
            return []
        return [Request(**json.loads(p.read_text())) for p in sorted(self.store.glob("*.json"))]

    # ── flow ─────────────────────────────────────────────────────────────────
    def create(self, prop: Proposal, requester: str | None = None) -> Request:
        if not self.enabled:
            raise ActError("no [approvals] section in the config — nothing says who approves.")
        if prop.blocked:
            raise ActError(prop.blocked)
        who = self.approvers_for(prop.grant.system, prop.grant.resource)
        if not who:
            raise ActError("no approver resolves for this change — set [approvals] admin at least.")
        req = Request(
            id=datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3),
            ts=datetime.datetime.now(datetime.UTC).isoformat(),
            requester=requester or getpass.getuser(),
            action=prop.action, system=prop.grant.system, subject=prop.grant.subject,
            resource=prop.grant.resource, priv=prop.grant.priv, cmd=prop.cmd,
            required={a: secrets.token_urlsafe(18) for a in who})
        self.save(req)
        return req

    def link(self, req: Request, approver: str) -> str:
        return f"{self.console_url or 'http://127.0.0.1:8420'}/approve/{req.id}?t={req.required[approver]}"

    def notify(self, req: Request) -> list[str]:
        """DM private links; return delivery status only, never bearer tokens."""
        lines = []
        head = (f"[grantline] approval requested by {req.requester}: {req.action} "
                f"{req.subject} {req.priv} on {req.resource} [{req.system}]\n`{req.cmd}`")
        for a in req.required:
            msg = f"{head}\napprove or deny: {self.link(req, a)}"
            # Approval credentials cannot be redirected into a pilot inbox.
            cfg = {k: v for k, v in self.slack_cfg.items() if k != "redirect_to"}
            r = slack.post(cfg, a, msg)
            status = "sent" if r and not r.startswith("error") else "not delivered; contact the operator"
            lines.append(f"{a}: {status}")
        ch = self.slack_cfg.get("channel")
        if ch:
            slack.post(self.slack_cfg, ch, f"{head}\nawaiting: {', '.join(req.required)}")
        return lines

    def decide(self, rid: str, token: str, approve: bool) -> tuple[Request, str]:
        req = self.load(rid)
        who = next((a for a, t in req.required.items() if secrets.compare_digest(t, token)), None)
        if who is None:
            raise ActError("that link is not one of this request's approver links.")
        if req.status in ("executed", "denied", "failed"):
            raise ActError(f"request {rid} is already {req.status}.")
        if not approve:
            req.status = "denied"; req.note = f"denied by {who}"
        else:
            req.approved[who] = datetime.datetime.now(datetime.UTC).isoformat()
            if not req.missing:
                req.status = "approved"
        self.save(req)
        return req, who

    def run(self, req: Request, adapters: dict, audit_path: str | None, observed) -> Request:
        """Execute an approved request — the stored command, nothing else (N2). Refuses
        while approvals are missing, and records failure instead of pretending."""
        from .act import propose
        if req.status != "approved":
            raise ActError(f"request {req.id} is {req.status}; missing: {', '.join(req.missing) or '—'}")
        prop = propose(req.action, req.system, req.subject, req.resource, req.priv, observed, adapters)
        try:
            execute(prop, adapters, audit_path, expect_cmd=req.cmd)
            req.status = "executed"; req.note = f"ran: {req.cmd}"
        except ActError as exc:
            req.status = "failed"; req.note = str(exc)
            self.save(req)
            raise
        self.save(req)
        ch = self.slack_cfg.get("channel")
        if ch:
            slack.post(self.slack_cfg, ch, f"[grantline] executed {req.id}: `{req.cmd}` (approved by {', '.join(req.approved)})")
        return req
