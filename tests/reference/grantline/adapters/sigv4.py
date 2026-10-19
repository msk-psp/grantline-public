"""AWS Signature V4 for plain HTTP requests — stdlib only (N4: no dependency the target
environment must accept). Enough for the probes: GET/HEAD/PUT/DELETE with an empty or
small body, path-style URLs, region "us-east-1", service "s3".

Verified against the AWS-published example (tests/test_n4_probe.py) so a probe that says
"deny" is a real 403, not a signing mistake dressed as one.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import urllib.parse


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sign(method: str, url: str, access_key: str, secret_key: str, body: bytes = b"",
         now: datetime.datetime | None = None, region: str = "us-east-1",
         service: str = "s3", extra_headers: dict | None = None) -> dict:
    """-> headers to send. Canonicalisation follows the S3 rules: URI path is
    URI-encoded once (S3 does not double-encode), query keys sorted, signed headers are
    host + x-amz-* (+ any extra given)."""
    u = urllib.parse.urlsplit(url)
    ts = (now or datetime.datetime.now(datetime.UTC)).strftime("%Y%m%dT%H%M%SZ")
    date = ts[:8]
    payload = _sha(body)
    headers = {"host": u.netloc, "x-amz-content-sha256": payload, "x-amz-date": ts}
    headers.update({k.lower(): v for k, v in (extra_headers or {}).items()})
    signed = ";".join(sorted(headers))
    canon_headers = "".join(f"{k}:{headers[k].strip()}\n" for k in sorted(headers))
    path = urllib.parse.quote(u.path or "/", safe="/-_.~")
    query = "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
                     for k, v in sorted(urllib.parse.parse_qsl(u.query, keep_blank_values=True)))
    canonical = "\n".join([method, path, query, canon_headers, signed, payload])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", ts, scope, _sha(canonical.encode())])
    k = ("AWS4" + secret_key).encode()
    for part in (date, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                                f"SignedHeaders={signed}, Signature={sig}")
    return {k: v for k, v in headers.items() if k != "host"}
