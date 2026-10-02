"""F3 — grant and revoke from the console, with N1/N2/N5 held down.

The interesting failures of a write feature are not "the write did not happen". They
are: a preview that flatters the command it runs, a GET that changes something because
a browser reloaded it, a revoke button on a row where revoking is a no-op, and a write
credential resolved by a page that only meant to read. Each of those gets a test here.

Run: python3 tests/test_f3_grant_revoke.py
"""
import json
import os
import pathlib
import sys
import tempfile
from urllib.parse import urlencode

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from grantline.act import ActError, execute, propose
from grantline.adapters import FixtureAdapter
from grantline.adapters import clickhouse as ch_mod
from grantline.adapters import postgres as pg_mod
from grantline.adapters.clickhouse import ClickHouseAdapter
from grantline.adapters.postgres import PostgresAdapter
from grantline.graph import build
from grantline.model import Grant
from grantline.pages import render_act, render_subject


def t(name, cond):
    assert cond, name
    print("  ok", name)


def fixtures(tmp: str, grants=(), system="postgres"):
    """A fixture-backed adapter, writable, in a throwaway directory."""
    path = pathlib.Path(tmp) / f"{system}.json"
    path.write_text(json.dumps({"grants": [
        {"subject": g.subject, "resource": g.resource, "priv": g.priv} for g in grants]}))
    mod = {"postgres": pg_mod, "clickhouse": ch_mod}[system]
    return path, FixtureAdapter(system, path, (mod.grant_cmd, mod.revoke_cmd))


SEED = [Grant("postgres", "svc_etl", "db:analytics", "CONNECT")]


def test_preview_is_the_command_that_runs():
    """N2. Not a summary, not a paraphrase — the audit log must be able to quote it."""
    with tempfile.TemporaryDirectory() as tmp:
        path, ad = fixtures(tmp, SEED)
        adaps, audit = {"postgres": ad}, str(pathlib.Path(tmp) / "audit.jsonl")
        observed = ad.observe()[0]

        p = propose("grant", "postgres", "alice", "db:analytics", "CONNECT",
                    observed, adaps)
        t("preview is the adapter's own command",
          p.cmd == pg_mod.grant_cmd(Grant("postgres", "alice", "db:analytics", "CONNECT")))
        page = render_act({"action": "grant", "system": "postgres", "subject": "alice",
                           "resource": "db:analytics", "priv": "CONNECT"}, observed, adaps)
        t("the page shows that exact string", p.cmd in page.replace("&quot;", '"'))

        execute(p, adaps, audit, expect_cmd=p.cmd)
        entry = json.loads(pathlib.Path(audit).read_text().splitlines()[-1])
        t("audit records the previewed command", entry["cmd"] == p.cmd)
        t("audit keys match the CLI's",
          set(entry) == {"ts", "user", "system", "action", "cmd", "ok"})
        t("the grant landed",
          Grant("postgres", "alice", "db:analytics", "CONNECT") in ad.observe()[0])


def test_a_stale_preview_is_refused():
    """Approving a command approves *that* command. If the world moved, ask again."""
    with tempfile.TemporaryDirectory() as tmp:
        _, ad = fixtures(tmp, SEED)
        adaps, audit = {"postgres": ad}, str(pathlib.Path(tmp) / "audit.jsonl")
        p = propose("grant", "postgres", "alice", "db:analytics", "CONNECT",
                    ad.observe()[0], adaps)
        try:
            execute(p, adaps, audit, expect_cmd='GRANT CONNECT ON DATABASE "other" TO x;')
            t("stale preview refused", False)
        except ActError as exc:
            t("stale preview refused", "changed between the preview" in str(exc))
        t("nothing was written", not os.path.exists(audit))


def test_get_has_no_side_effect():
    """A rendered preview must be safe to reload, prefetch, or link to."""
    with tempfile.TemporaryDirectory() as tmp:
        path, ad = fixtures(tmp, SEED)
        adaps, audit = {"postgres": ad}, str(pathlib.Path(tmp) / "audit.jsonl")
        before = path.read_text()
        for _ in range(3):
            render_act({"action": "revoke", "system": "postgres", "subject": "svc_etl",
                        "resource": "db:analytics", "priv": "CONNECT"},
                       ad.observe()[0], adaps)
        t("fixture untouched by rendering", path.read_text() == before)
        t("no audit line written by rendering", not os.path.exists(audit))
        t("the grant is still observed",
          SEED[0] in ad.observe()[0])


def test_no_write_credential_means_no_run_path():
    """N1. The read path decides the button from config shape + env presence only —
    it never resolves the credential, and with none configured there is no button
    and no execute path either."""
    ro = PostgresAdapter({"dsn_env": "GRANTLINE_TEST_DSN"})            # reads only
    ready, why = ro.write_ready()
    t("unconfigured system is not write-ready", ready is False)
    t("and says why", "admin_dsn_env" in why)

    named = PostgresAdapter({"dsn_env": "A", "admin_dsn_env": "GRANTLINE_TEST_ADMIN_DSN"})
    os.environ.pop("GRANTLINE_TEST_ADMIN_DSN", None)
    t("named but absent is not write-ready", named.write_ready()[0] is False)
    os.environ["GRANTLINE_TEST_ADMIN_DSN"] = "postgresql://nobody@127.0.0.1/none"
    try:
        ok, note = named.write_ready()
        t("named and present is write-ready", ok is True)
        t("the note names the variable, never the value",
          "GRANTLINE_TEST_ADMIN_DSN" in note and "nobody" not in note)
    finally:
        os.environ.pop("GRANTLINE_TEST_ADMIN_DSN", None)

    adaps = {"postgres": ro}
    observed = {Grant("postgres", "svc_etl", "db:analytics", "CONNECT")}
    fields = {"action": "grant", "system": "postgres", "subject": "alice",
              "resource": "db:analytics", "priv": "CONNECT"}
    page = render_act(fields, observed, adaps)
    t("the command is still shown", 'GRANT CONNECT ON DATABASE' in page)
    t("but there is no way to run it from the page", 'method="post"' not in page)
    t("and the page says what to do instead", "own client" in page)

    p = propose(*[fields[k] for k in ("action", "system", "subject", "resource", "priv")],
                observed, adaps)
    try:
        execute(p, adaps, "/dev/null")
        t("execute refuses without a write credential", False)
    except ActError as exc:
        t("execute refuses without a write credential", "read-only here" in str(exc))


def test_grant_then_revoke_returns_the_observation():
    """F3's success criterion, taken literally: the observation comes back identical."""
    with tempfile.TemporaryDirectory() as tmp:
        _, ad = fixtures(tmp, SEED)
        adaps, audit = {"postgres": ad}, str(pathlib.Path(tmp) / "audit.jsonl")
        before = ad.observe()[0]

        g = ("postgres", "alice", "table:analytics.public.events", "SELECT")
        execute(propose("grant", *g, ad.observe()[0], adaps), adaps, audit)
        after = ad.observe()[0]
        t("the grant is visible in the observation", after - before ==
          {Grant(*g)})

        execute(propose("revoke", *g, ad.observe()[0], adaps), adaps, audit)
        t("revoke returns the observation to its prior state", ad.observe()[0] == before)
        t("both writes are on the record",
          len(pathlib.Path(audit).read_text().splitlines()) == 4)


# ── the subject page ──────────────────────────────────────────────────────────
G = [
    Grant("postgres", "researcher_a", "role:analytics_reader", "MEMBER"),
    Grant("postgres", "analytics_reader", "table:analytics.public.vitals", "SELECT"),
    Grant("postgres", "researcher_a", "db:analytics", "CONNECT"),
]
BR = [{"from": "researcher_a", "to": "warehouse_ro", "system": "s3", "note": "server-held key"}]
BRIDGED = [*G, Grant("s3", "warehouse_ro", "bucket:warehouse", "Read")]


def _href(**kw):
    return "/act?" + urlencode(kw)


def test_direct_rows_offer_a_revoke():
    h = render_subject(set(G), build(set(G), []), "researcher_a")
    want = _href(action="revoke", system="postgres", subject="researcher_a",
                 resource="db:analytics", priv="CONNECT")
    t("direct grant is revocable from here", want.replace("&", "&amp;") in h)


def test_inherited_rows_do_not_offer_a_revoke_from_this_subject():
    """The grant belongs to analytics_reader. A REVOKE naming researcher_a would report success and
    change nothing — the exact 'I revoked it and nothing happened' this page exists to
    prevent. What it offers instead is the hop that actually carries the access."""
    h = render_subject(set(G), build(set(G), []), "researcher_a")
    wrong = _href(action="revoke", system="postgres", subject="researcher_a",
                  resource="table:analytics.public.vitals", priv="SELECT")
    t("no revoke aimed at the wrong holder", wrong.replace("&", "&amp;") not in h)
    cut = _href(action="revoke", system="postgres", subject="researcher_a",
                resource="role:analytics_reader", priv="MEMBER")
    t("the hop to cut is offered", cut.replace("&", "&amp;") in h)
    t("and the holder is named", "/s/analytics_reader" in h and "revoke on analytics_reader" in h)


def test_a_declared_bridge_is_not_a_grant_to_revoke():
    """A bridge is a hop nothing granted, so there is no command that removes it."""
    h = render_subject(set(BRIDGED), build(set(BRIDGED), BR), "researcher_a")
    t("bridge destination is listed", "bucket:warehouse" in h)
    t("no revoke pretends to cut the bridge",
      _href(action="revoke", system="s3", subject="researcher_a",
            resource="bucket:warehouse", priv="Read").replace("&", "&amp;") not in h)
    t("it points at the configuration instead", "declared bridge" in h)


def test_grant_entry_points_carry_their_context():
    """Both directions of entry F3 asks for: from a subject, and from a resource."""
    from grantline.pages import render_group
    h = render_subject(set(G), build(set(G), []), "researcher_a")
    t("subject page prefills the subject", "action=grant&amp;subject=researcher_a" in h)
    g = render_group(set(G), "postgres", "table")
    t("resource page prefills system and resource",
      _href(action="grant", system="postgres",
            resource="table:analytics.public.vitals").replace("&", "&amp;") in g)


# ── guards ────────────────────────────────────────────────────────────────────
def test_a_grant_already_covered_is_warned_and_blocked():
    """N5. The command would succeed, change no access, and leave an audit line
    claiming otherwise."""
    with tempfile.TemporaryDirectory() as tmp:
        _, ad = fixtures(tmp, [Grant("clickhouse", "researcher_c", "db:product", "SELECT")],
                         system="clickhouse")
        adaps = {"clickhouse": ad}
        observed = ad.observe()[0]
        p = propose("grant", "clickhouse", "researcher_c", "table:product.events", "SELECT",
                    observed, adaps)
        t("blocked", bool(p.blocked))
        t("names the covering grant", "db:product" in p.blocked)
        page = render_act({"action": "grant", "system": "clickhouse", "subject": "researcher_c",
                           "resource": "table:product.events", "priv": "SELECT"},
                          observed, adaps)
        t("page offers no run button", 'method="post"' not in page)
        try:
            execute(p, adaps, str(pathlib.Path(tmp) / "audit.jsonl"))
            t("execute refuses a no-op", False)
        except ActError:
            t("execute refuses a no-op", True)

        same = propose("grant", "clickhouse", "researcher_c", "db:product", "SELECT", observed, adaps)
        t("an identical held grant is blocked too", "already holds" in same.blocked)


def test_a_revoke_of_something_unobserved_warns_but_is_allowed():
    """'not observed' is not 'not there' — it may sit in a scope this observer cannot
    read (F6), so the tool says so rather than deciding for the operator."""
    with tempfile.TemporaryDirectory() as tmp:
        _, ad = fixtures(tmp, SEED)
        adaps = {"postgres": ad}
        p = propose("revoke", "postgres", "ghost", "db:analytics", "CONNECT",
                    ad.observe()[0], adaps)
        t("not blocked", not p.blocked)
        t("but noted", "was not observed" in p.note)


def test_failures_are_sentences_not_stack_traces():
    """F6. Every refusal a steward can trigger reads as a reason."""
    adaps = {"postgres": PostgresAdapter({"dsn_env": "X"})}
    cases = [
        (("grant", "postgres", "researcher_a", "global:*", "SELECT"), "no grant statement"),
        (("grant", "elasticsearch", "researcher_a", "db:x", "read"), "no adapter is configured"),
        (("grant", "postgres", "", "db:x", "CONNECT"), "fill in subject"),
        (("sudo", "postgres", "researcher_a", "db:x", "CONNECT"), "unknown action"),
    ]
    for args, expect in cases:
        try:
            propose(*args, set(), adaps)
            t(f"{args[0]}/{args[3]} refused", False)
        except ActError as exc:
            t(f"refused: {expect}", expect in str(exc))
            t("no traceback in the message", "Traceback" not in str(exc))

    page = render_act({"action": "grant", "system": "postgres", "subject": "researcher_a",
                       "resource": "global:*", "priv": "SELECT"}, set(), adaps)
    t("the page shows the reason, not a 500", "Cannot preview" in page)


def test_clickhouse_and_fixture_write_readiness():
    ch = ClickHouseAdapter({"url_env": "GRANTLINE_TEST_CH"})
    t("clickhouse without an admin url is read-only", ch.write_ready()[0] is False)
    with tempfile.TemporaryDirectory() as tmp:
        path, ad = fixtures(tmp, SEED)
        t("a writable fixture is write-ready", ad.write_ready()[0] is True)
        os.chmod(path, 0o444)
        try:
            t("a read-only file is not", ad.write_ready()[0] is False)
        finally:
            os.chmod(path, 0o644)


for fn in [v for k, v in dict(globals()).items() if k.startswith("test_")]:
    print(fn.__name__)
    fn()
print("all tests passed")


# ── IAM 의 "값 하나는 대괄호 없이" 를 쓰기 쪽도 지켜야 한다 ──────────────
# 읽기 쪽(_listed)은 고쳐져 있었는데 policy_with 는 list() 를 그대로 써서 문자열을
# 글자 단위로 쪼갰다. 실환경 plan 에서 발견: "s3:ListAllMyBuckets" → ["s","3",":",…].
from grantline.adapters.s3 import policy_with as _pw
from grantline.model import Grant as _G

_before = {"Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "arn:aws:s3:::*"}]}
_after = _pw(_before, _G("s3", "x", "bucket:data", "Read"), add=True)
_first = _after["Statement"][0]
assert _first["Action"] == ["s3:ListAllMyBuckets"], _first
assert _first["Resource"] == ["arn:aws:s3:::*"], _first
assert not any(len(a) == 1 for st in _after["Statement"] for a in st["Action"]), _after
# 지울 때도 같다 — 문자열 Action 을 가진 statement 가 통째로 사라지면 안 된다
_rm = _pw(_before, _G("s3", "x", "bucket:*", "List"), add=False)
assert _rm["Statement"] and _rm["Statement"][0]["Action"] == ["s3:ListAllMyBuckets"], _rm
print("ok policy_with: 문자열 Action/Resource")
