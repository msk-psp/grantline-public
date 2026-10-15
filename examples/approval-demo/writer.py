"""Local PR simulation only: no GitHub, credentials, network or IAM calls."""
import hashlib
import json
import re
import sys
from pathlib import Path

PR_PREFIX = "https://github.com/example/approval-demo/pull/"


def handle(state, req):
    rid = req.get("request_id", "")
    if (not re.fullmatch(r"[A-Za-z0-9-]{8,64}", rid)
            or req.get("operation") not in {"preview", "submit"}
            or req.get("action") != "grant" or req.get("system") != "s3"
            or req.get("subject") != "demo-user" or req.get("resource") != "bucket:demo/team"
            or req.get("priv") != "Read"):
        raise ValueError("Use the sample demo-user / bucket:demo/team / Read grant")
    patch = json.dumps({k: req[k] for k in ("request_id", "subject", "resource", "priv")}, indent=2) + "\n"
    plan = {"base_commit": hashlib.sha1(b"local demo baseline").hexdigest(),
            "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
            "summary": "SIMULATION: demo-user receives Read on bucket:demo/team. No real permission changes."}
    if req["operation"] == "preview":
        return plan
    if req.get("expected_plan") != plan:
        raise ValueError("Approved plan changed")
    prs = state / "prs"
    prs.mkdir(exist_ok=True)
    path = prs / (rid + ".json")
    if path.exists():
        saved = json.loads(path.read_text())
        if saved["plan"] != plan:
            raise ValueError("Existing simulated PR differs from approved plan")
    else:
        saved = {"number": len(list(prs.glob("*.json"))) + 1, "plan": plan, "patch": patch}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(saved), encoding="utf-8")
        tmp.replace(path)
    return {**plan, "pr_url": PR_PREFIX + str(saved["number"])}


if __name__ == "__main__":
    print(json.dumps(handle(Path(sys.argv[1]), json.loads(sys.stdin.read(65537)))))
