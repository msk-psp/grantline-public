"""Approval flow: who must approve is config; each approver's link is their identity; the
stored command is the one that runs; nothing runs before everyone says yes."""
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline.act import ActError, propose
from grantline.adapters import FixtureAdapter
from grantline.adapters import postgres as pgmod
from grantline.approvals import Approvals

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory() as d:
    base = Path(d)
    fx = base / "postgres.json"; shutil.copy(root / "examples/fixtures/postgres.json", fx)
    adapters = {"postgres": FixtureAdapter("postgres", fx, (pgmod.grant_cmd, pgmod.revoke_cmd))}
    observed, _, _ = adapters["postgres"].observe()
    ap = Approvals({"store": "approvals", "console_url": "http://c", "admin": ["operator"],
                    "rules": [{"match": ["postgres:role:analyst*"], "approvers": ["analytics_lead"]},
                              {"match": ["s3:*"], "approvers": ["s3_lead"]}]}, base)
    assert ap.approvers_for("postgres", "role:analyst_read") == ["analytics_lead", "operator"]
    assert ap.approvers_for("postgres", "db:x") == ["operator"], "no rule → admin alone"

    prop = propose("grant", "postgres", "carol", "role:analyst_read", "MEMBER", observed, adapters)
    req = ap.create(prop, requester="me")
    assert set(req.required) == {"analytics_lead", "operator"} and req.status == "pending" and req.cmd == prop.cmd
    links = ap.notify(req)
    assert len(links) == 2 and all("?t=" not in l for l in links)
    assert not any(token in "\n".join(links) for token in req.required.values())
    assert ap.link(req, "operator") != ap.link(req, "analytics_lead"), "one token per approver"

    # wrong token is refused; one approval is not enough; the run refuses until approved
    try: ap.decide(req.id, "nope", True); assert False
    except ActError: pass
    r, who = ap.decide(req.id, req.required["analytics_lead"], True)
    assert who == "analytics_lead" and r.status == "pending" and r.missing == ["operator"]
    try: ap.run(r, adapters, str(base / "audit.jsonl"), observed); assert False
    except ActError: pass
    r, who = ap.decide(req.id, req.required["operator"], True)
    assert r.status == "approved"
    r = ap.run(r, adapters, str(base / "audit.jsonl"), observed)
    assert r.status == "executed"
    after, _, _ = adapters["postgres"].observe()
    assert any(g.subject == "carol" and g.resource == "role:analyst_read" for g in after), "the command ran"
    assert (base / "audit.jsonl").exists()
    # deny ends it; a second decision on a finished request is refused
    prop2 = propose("revoke", "postgres", "carol", "role:analyst_read", "MEMBER", after, adapters)
    req2 = ap.create(prop2)
    r2, _ = ap.decide(req2.id, req2.required["operator"], False)
    assert r2.status == "denied"
    try: ap.decide(req2.id, req2.required["analytics_lead"], True); assert False
    except ActError: pass
    assert {r.id for r in ap.all()} == {req.id, req2.id}
print("ok")


# ── piloting: every notification goes to one inbox, still naming its recipient ──
sent = []
def _fake(req, timeout=20):
    import json as _j
    sent.append(_j.loads(req.data))
    class R:
        def read(self): return b'{"ok": true, "ts": "1.0"}'
        def __enter__(self): return self
        def __exit__(self, *a): return False
    return R()
import urllib.request as _u

from grantline import slack as _slack

_real, _u.urlopen = _u.urlopen, _fake
os.environ["TOK"] = "xoxb-test"
cfg = {"bot_token_env": "TOK", "redirect_to": "UPILOT"}
_slack.post(cfg, "UAPPROVER", "please approve")
_u.urlopen = _real
assert sent[0]["channel"] == "UPILOT", sent
assert "UAPPROVER" in sent[0]["text"] and "please approve" in sent[0]["text"], sent
print("ok slack redirect")
