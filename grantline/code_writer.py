"""Trusted, shell-free writer: approved plan in, one repository PR out."""
import json
import re
import subprocess
from urllib.parse import urlsplit

from .act import ActError


class CodeWriter:
    def __init__(self, cfg):
        self.command = cfg.get("command")
        self.repository = cfg.get("repository", "")
        self.systems = cfg.get("systems", [])
        self.timeout = cfg.get("timeout", 60)
        if (not isinstance(self.command, list) or not self.command
                or any(not isinstance(x, str) or not x for x in self.command)
                or not self.command[0].startswith("/")
                or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository)
                or not isinstance(self.systems, list) or not self.systems
                or not isinstance(self.timeout, int) or not 1 <= self.timeout <= 120):
            raise ValueError("invalid approvals.code_writer configuration")

    def call(self, req, operation):
        if req.system not in self.systems:
            raise ActError("This service is not enabled for code proposals.")
        payload = {"schema_version": 1, "operation": operation, "request_id": req.id,
                   "action": req.action, "system": req.system, "subject": req.subject,
                   "resource": req.resource, "priv": req.priv, "requester": req.requester,
                   "approvers": sorted(req.required)}
        if operation == "submit":
            payload["expected_plan"] = req.code_plan
        try:
            result = subprocess.run(self.command, input=json.dumps(payload), text=True,
                                    capture_output=True, timeout=self.timeout, check=True)
            if len(result.stdout) > 65536:
                raise ValueError("oversized response")
            data = json.loads(result.stdout)
            if not isinstance(data, dict):
                raise ValueError("invalid response")
            base, digest = data.get("base_commit", ""), data.get("patch_sha256", "")
            if not re.fullmatch(r"[0-9a-f]{40}", base) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("invalid plan identity")
            if operation == "preview":
                if not isinstance(data.get("summary"), str) or not data["summary"].strip():
                    raise ValueError("missing summary")
                return {"base_commit": base, "patch_sha256": digest, "summary": data["summary"]}
            if base != req.code_plan["base_commit"] or digest != req.code_plan["patch_sha256"]:
                raise ValueError("approved plan changed")
            url = urlsplit(data.get("pr_url", ""))
            pattern = "/" + re.escape(self.repository) + r"/pull/[1-9][0-9]*"
            if (url.scheme != "https" or url.netloc != "github.com"
                    or not re.fullmatch(pattern, url.path) or url.query or url.fragment):
                raise ValueError("untrusted PR URL")
            return data["pr_url"]
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError):
            # Writer output can contain credentials: never expose stderr or raw JSON.
            raise ActError("Code proposal failed. No permission was applied; ask the operator to check the writer.") from None
