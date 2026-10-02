"""Optional identity supplied by an authenticated, header-stripping reverse proxy.

The proxy owns OIDC, cookies and access policy. This process still binds to loopback.
"""
import re
from contextvars import ContextVar
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

current = ContextVar("console_identity", default=None)


def local_path(value: str, fallback: str = "/") -> str:
    if not isinstance(value, str) or len(value) > 4096: return fallback
    decoded = value
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded: break
        decoded = expanded
    if (not value.startswith("/") or not decoded.startswith("/") or decoded.startswith("//")
            or "\\" in decoded or any(ord(c) < 32 or ord(c) == 127 for c in decoded)):
        return fallback
    try:
        url = urlsplit(decoded)
    except ValueError:
        return fallback
    return value if not url.scheme and not url.netloc else fallback


def proxy_config(raw):
    if raw is None: return None
    if not isinstance(raw, dict): raise ValueError("web.auth must be a configuration table")
    if raw.get("mode") != "proxy": raise ValueError("web.auth.mode must be 'proxy'")
    header = raw.get("identity_header", "X-Forwarded-Email")
    if not isinstance(header, str) or not re.fullmatch(r"X-[A-Za-z0-9-]+", header):
        raise ValueError("web.auth.identity_header must name a proxy identity header")
    cfg = {"mode": "proxy", "identity_header": header, "login_url": raw.get("login_url", "/oauth2/start"),
           "logout_url": raw.get("logout_url", "/oauth2/sign_out")}
    for key in ("login_url", "logout_url"):
        value = cfg[key]
        if not isinstance(value, str) or not value or local_path(value, "") != value or "#" in value:
            raise ValueError(f"web.auth.{key} must be a local proxy endpoint")
    return cfg


def proxy_user(headers, cfg):
    if cfg is None: return ""
    values = headers.get_all(cfg["identity_header"], [])
    if len(values) != 1: return ""
    user = values[0].strip()
    return user if user and len(user) <= 256 and not any(ord(c) < 32 or ord(c) == 127 for c in user) else ""


def proxy_target(endpoint: str, destination: str) -> str:
    url = urlsplit(endpoint)
    params = dict(parse_qsl(url.query)); params["rd"] = local_path(destination)
    return url.path + "?" + urlencode(params)
