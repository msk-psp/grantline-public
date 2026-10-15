"""The local playground exercises actual approvals without SSO, Slack or GitHub credentials."""
import http.client
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "examples/approval-demo/run.py"
SAMPLE = {"action": "grant", "system": "s3", "subject": "demo-user",
          "resource": "bucket:demo/team", "priv": "Read",
          "cmd": "code PR: grant Read on bucket:demo/team to demo-user (s3)"}

with tempfile.TemporaryDirectory() as directory:
    log = Path(directory) / "output"
    with log.open("w+") as output:
        process = subprocess.Popen([sys.executable, str(SCRIPT), "--port", "0"], stdout=output,
                                   env={**os.environ, "GH_TOKEN": "must-not-reach-demo"})
        try:
            import time
            deadline = time.monotonic() + 15
            while "DEMO_STATE=" not in log.read_text():
                assert process.poll() is None, "demo exited before startup"
                assert time.monotonic() < deadline, "demo did not start"
                time.sleep(.05)
            lines = dict(line.split("=", 1) for line in log.read_text().splitlines() if line.startswith("DEMO_"))
            base = lines["DEMO_URL"].removesuffix("/demo")
            state = Path(lines["DEMO_STATE"])
            port = urlsplit(base).port

            def call(path, role="", fields=None, origin=None, extra=None):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                headers = dict(extra or {})
                if role: headers["Cookie"] = "grantline_demo_role=" + role
                if fields is not None:
                    headers.update({"Origin": origin or base, "Content-Type": "application/x-www-form-urlencoded"})
                conn.request("POST" if fields is not None else "GET", path,
                             body=urlencode(fields) if fields is not None else None, headers=headers)
                response = conn.getresponse()
                result = response.status, dict(response.getheaders()), response.read().decode()
                conn.close()
                return result

            status, headers, _ = call("/demo")
            assert status == 200 and headers["Referrer-Policy"] == "strict-origin"
            assert call("/demo/login", fields={"role": "requester"}, origin="https://example.com")[0] == 403
            assert call("/demo/login", fields={"role": "unknown"})[0] == 400
            status, headers, _ = call("/demo/login", fields={"role": "requester", "next": "//example.com"})
            assert status == 303 and headers["Location"] == "/demo"
            assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
            status, headers, _ = call("/demo/logout", "reviewer")
            assert status == 303 and "Max-Age=0" in headers["Set-Cookie"]
            assert call("/act", extra={"X-Forwarded-Email": "reviewer"})[0] == 303
            assert call("/request", "reviewer", SAMPLE)[0] == 409, "reviewer cannot request their own approval"
            assert call("/request", "requester", {**SAMPLE, "resource": "bucket:other/secret"})[0] == 409
            original = (state / "iam/identities/demo-user.json").read_bytes()

            def create():
                status, headers, _ = call("/request", "requester", SAMPLE)
                assert status == 303
                rid = headers["Location"].rsplit("/", 1)[-1]
                path = state / "approvals" / (rid + ".json")
                req = json.loads(path.read_text())
                assert req["requester"] == "DEMO_REQUESTER"
                return rid, path, req["required"]["DEMO_REVIEWER"]

            rid, request_file, token = create()
            inbox = list((state / "inbox").glob("*.json"))
            assert len(inbox) == 1 and json.loads(inbox[0].read_text())["to"] == "DEMO_REVIEWER"
            assert "승인 요청 열기" in call("/demo")[2]
            fields = {"t": token, "decision": "approve"}
            assert call("/approve/" + rid, "requester", fields)[0] == 409
            assert not json.loads(request_file.read_text())["approved"]
            assert call("/approve/" + rid, "reviewer", {**fields, "decision": "deny"})[0] == 303
            assert json.loads(request_file.read_text())["status"] == "denied"
            assert not list((state / "prs").glob("*.json"))

            rid, request_file, token = create()
            fields = {"t": token, "decision": "approve"}
            assert call("/approve/" + rid, "reviewer", fields)[0] == 303
            req = json.loads(request_file.read_text())
            assert req["status"] == "proposed" and req["pr_url"].endswith("/1")
            assert call("/approve/" + rid, "reviewer", fields)[0] == 409
            assert len(list((state / "prs").glob("*.json"))) == 1
            assert '/demo/pr/1' in call("/approve/" + rid + "?t=" + token, "reviewer")[2]
            status, _, page = call("/demo/pr/1")
            assert status == 200 and "시뮬레이션 PR #1" in page and "demo-user" in page
            assert "실제 GitHub PR·IAM 적용은 아닙니다" in page
            assert (state / "iam/identities/demo-user.json").read_bytes() == original
            assert call("/demo/pr/999")[0] == 404
        finally:
            process.terminate()
            process.wait(timeout=10)
        assert not state.exists(), "shutdown must remove disposable test state"
print("ok local role switching, forwarded-header stripping, approval/deny, simulated PR and isolated state cleanup")
