"""The two pages a steward actually opens (PRD 003 F1, F2).

The matrix answers "who × what" at a glance, and that is the wrong first screen. The
question that starts a session is one of two:

  F1  "what have I granted on ClickHouse?"     — enter by service
  F2  "what can researcher_c reach, and how?"           — enter by person

Both are inventories, so neither may collapse a service to a single number. A count is
where an audit *ends*, not where it starts: "PostgreSQL: 3,522" tells a steward nothing
they can act on. Each page keeps the resource kinds separate and stays one click away
from the individual resources, because the thing that gets revoked is a resource, not a
total.
"""
from __future__ import annotations

import html
from urllib.parse import quote, unquote, urlencode

from .act import ActError, Proposal, propose
from .auth import current, local_path, proxy_target
from .model import Grant
from .web import _strength, asset, group_of

e = html.escape


def _act_href(action: str, **fields) -> str:
    """Link into the grant/revoke form with the context the reader is already in.

    The form is reached from wherever the answer was found — a resource row, a
    subject's page — because retyping a resource name that is already on screen is
    how the wrong resource gets revoked.
    """
    q = {k: v for k, v in fields.items() if v}
    return e("/act?" + urlencode({"action": action, **q}))  # goes into an attribute


def _shell(title: str, *parts: str, wide: bool = False) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} &middot; Grantline</title>
<link rel="stylesheet" href="{asset("grantline.css")}">
<script src="{asset("console.js")}" defer></script></head><body>
<a class="skip-link" href="#main">Skip to content</a>
<main id="main" class="page{' wide' if wide else ''}">{"".join(parts)}
<footer>grantline &middot; read-only observation &middot;
every write is previewed as the native command first</footer>
</main></body></html>"""


def render_error(status: int, message: str) -> str:
    title = {400: "Check your request", 401: "Sign in to continue", 403: "Access unavailable", 404: "Page not found",
             409: "The request changed", 413: "Request too large", 500: "Unable to load this page",
             503: "Service temporarily unavailable"}.get(status, "Request unavailable")
    return _shell(title, _nav(""), f'<header class="glass"><h1>{title}</h1>'
                  f'<p class="lede" role="alert">{e(message)}</p>'
                  '<p><a class="chip" href="/login">Sign in / access details</a> '
                  '<a class="chip" href="/">Return to the access map</a> '
                  '<a class="chip" href="/act">View changes</a></p></header>')


def render_login(cfg, destination="/") -> str:
    destination = local_path(destination)
    user = (current.get() or {}).get("user", "")
    if user:
        message = f'Signed in as <strong>{e(user)}</strong>.'
        href, button = destination, "Continue to console"
    elif cfg:
        message = 'Use your organization\'s sign-in provider. Grantline does not receive or store your password.'
        href, button = proxy_target(cfg["login_url"], destination), "Continue with SSO"
    else:
        message = 'This local console does not require sign-in. Shared deployments use an authenticated proxy.'
        href, button = destination, "Explore the console"
    return _shell("Access Grantline", '<header class="glass login"><a class="brand" href="/">Grantline</a>'
                  '<h1>Untangle access.<br>Follow the grants.</h1>'
                  '<p class="lede">Understand PostgreSQL, ClickHouse and S3 access in one place.</p>'
                  f'<p class="login-state">{message}</p><a class="primary" href="{e(href)}">{button} &rarr;</a>'
                  '<p class="hint">Observation and permission changes stay separate. Every change is previewed first.</p></header>')




PENDING_COUNT = 0     # serve() 가 매 요청 전에 채운다. 0 이면 큐 탭에 배지가 없다.
# serve() 가 기동 때 한 번 채운다: 어느 어댑터든 쓰기 자격이 있으면 True, 하나도 없으면
# False, 안 물어봤으면 None(CLI 렌더·테스트). 클러스터 배포본은 항상 False 다.
WRITE_READY: bool | None = None


def _nav(here: str) -> str:
    # 제안 폼과 큐가 한 화면이라 탭도 하나다 — 요청을 낸 뒤 어디로 갔는지 보려고
    # 탭을 옮기지 않는다.
    q = f"changes ({PENDING_COUNT})" if PENDING_COUNT else "changes"
    # 첫 화면(`/`)은 routes 다. 「누가 무엇에 닿는가」가 이 도구에서 가장 값이 큰 답이고,
    # 실제로 그것 때문에 배포했다. services 는 `/services` 로 옮겼고, 옛 `/graph` 는
    # 그대로 지도를 낸다 — 북마크와 `/graph?focus=` 링크가 안 깨지게.
    # 쓰기 자격이 없는 배포(클러스터본)에서 changes 는 명령을 **보여주는** 화면이지
    # 실행하는 화면이 아니다. 눌렀는데 아무 일도 안 일어나는 탭으로 보이지 않게,
    # 탭이 미리 그렇게 말한다. 본문 머리에도 같은 문장이 있다.
    act_title = ("this deployment holds no write credential — the page shows the native "
                 "command to run elsewhere, and runs nothing"
                 if WRITE_READY is False else "propose a change; everything proposed is queued here")
    items = [("/", "routes", "how authority reaches a resource"),
             ("/services", "services", "what is granted, by service"),
             ("/matrix", "matrix", "subjects × resource groups"),
             ("/act", q + ("" if WRITE_READY is not False else " — read-only"), act_title)]
    session = current.get() or {}
    if session.get("user"):
        identity = (f'<span class="identity" title="{e(session["user"])}">{e(session["user"])}</span>'
                    f'<a href="{e(session["logout"])}">Sign out</a>')
    else:
        identity = '<a class="identity" href="/login">Sign in</a>' if session.get("enabled") else '<a class="identity" href="/login">Local console</a>'
    return '<nav class="nav" aria-label="Main navigation"><a class="brand" href="/">Grantline</a>' + "".join(
        f'<a href="{h}" class="{"on" if h == here else ""}"'
        + (' aria-current="page"' if h == here else '') + f' title="{e(ti)}">{t}</a>' for h, t, ti in items
    ) + '<a class="refresh" href="?refresh" title="Re-read access from every service">&#x21bb; refresh</a>' + identity + '</nav>'


def _chips(subjects, limit=8) -> str:
    s = sorted(subjects)
    def chip(x): return f'<a class="chip" href="/s/{quote(x, safe="")}">{e(x)}</a>'
    out = "".join(chip(x) for x in s[:limit])
    if len(s) > limit:
        out += (f'<details class="more-chips"><summary class="chip more">+{len(s) - limit} more</summary>'
                + "".join(chip(x) for x in s[limit:]) + '</details>')
    return out


# ── F8 ────────────────────────────────────────────────────────────────────────
def _since_run(rec) -> str:
    """What moved since the previous run — on the front page, above the inventory.

    Here and not on its own page: "what is granted" and "what changed" are the same
    question asked at two distances, and a steward who has to click to find the second
    one will read the first as if it had always been that way. It sits above the
    services because it is the shorter list, and a short list of what moved is what
    turns a standing surface into something worth opening twice.

    The gap is stated as elapsed time, never as a cadence. Nothing schedules this
    tool, and "since yesterday" would describe a rhythm that does not exist.
    """
    if rec is None:
        return ""
    if getattr(rec, "error", ""):
        return (f'<section class="glass"><h2>Since your previous run</h2>'
                f'<div class="warn"><b>not recorded</b>{e(rec.error)} '
                f'The access shown below was still read live; only the record of this '
                f'run is missing, so the next run has nothing to compare against.'
                f'</div></section>')
    cmp = getattr(rec, "comparison", None)
    if cmp is None:
        return ('<section class="glass"><h2>Since your previous run</h2>'
                '<p class="ok">This is the first run recorded, so there is nothing to '
                'compare it with. Nothing here runs on a schedule &mdash; the next '
                'comparison will cover however long it happens to be until you run '
                'this again.</p></section>')

    lines = "".join(
        f'<code class="add">+ [{e(g.system)}] {e(g.subject)} {e(g.priv)} '
        f"on {e(g.resource)}</code>" for g in cmp.added)
    lines += "".join(
        f'<code class="rm">&minus; [{e(g.system)}] {e(g.subject)} {e(g.priv)} '
        f"on {e(g.resource)}</code>" for g in cmp.removed)
    body = (f'<div class="cmd">{lines}</div>' if lines else
            '<p class="ok">Nothing changed. Every grant seen then was seen now, and no '
            'new one appeared &mdash; unchanged access is not listed here at all.</p>')

    # A scope that moved in or out of view is not access that moved. Kept out of the
    # list above and counted separately, because in set arithmetic they are
    # indistinguishable from a revoke and a grant (F6).
    blind = ""
    if cmp.obscured:
        blind += (f'<div class="warn"><b>unknown, not revoked</b>{len(cmp.obscured)} '
                  f"grant(s) sat in a scope this run could not read. They are not "
                  f"listed as removed, because nothing says they were.</div>")
    if cmp.revealed:
        blind += (f'<div class="warn"><b>visible, not new</b>{len(cmp.revealed)} '
                  f"grant(s) became readable again after a scope the previous run "
                  f"missed. They are not listed as added.</div>")

    return f"""<section class="glass"><h2>Since your previous run
<span class="cnt">{cmp.moved} changed</span></h2>
<p class="lede">Compared with your previous run, {e(cmp.ago())} &mdash;
<span class="via">{e(cmp.prev.ts.isoformat())} &rarr; {e(cmp.cur.ts.isoformat())}</span>.
There is no schedule behind that interval; it is however long it was between the two
times you ran this. Only what differs appears below.</p>
{body}{blind}</section>"""


# ── F1 ────────────────────────────────────────────────────────────────────────
def render_inventory(observed: set[Grant], recorder=None, unobserved=()) -> str:
    """One section per service, one row per resource kind (`/services`).

    Deliberately *not* one row per service. A service's grants are not one thing —
    a database grant and a role membership are revoked differently and mean different
    things — so flattening them into a total destroys the only distinction that makes
    the number actionable.
    """
    by_sys: dict[str, dict[str, dict]] = {}
    for g in observed:
        _, grp = group_of(g.system, g.resource)
        cell = by_sys.setdefault(g.system, {}).setdefault(
            grp, {"res": set(), "subj": set(), "privs": set()})
        cell["res"].add(g.resource)
        cell["subj"].add(g.subject)
        cell["privs"].add(g.priv)

    sections = []
    for system in sorted(by_sys):
        groups = by_sys[system]
        rows = "".join(
            f'<tr><td><a class="res" href="/g/{quote(system, safe="")}/{quote(grp, safe="")}">{e(grp)}</a></td>'
            f'<td class="num">{len(c["res"])}</td>'
            f'<td class="num">{len(c["subj"])}</td>'
            f'<td class="lvl {_strength(c["privs"])}">{_strength(c["privs"])}</td>'
            f"<td>{_chips(c['subj'])}</td></tr>"
            for grp, c in sorted(groups.items(), key=lambda kv: -len(kv[1]["res"])))
        total_r = len({r for c in groups.values() for r in c["res"]})
        total_s = len({s for c in groups.values() for s in c["subj"]})
        sections.append(f"""<section class="glass">
<h2>{e(system)} <span class="cnt">{total_r} resources &middot; {total_s} subjects</span></h2>
<div class="scroll"><table>
<thead><tr><th>resource kind</th><th class="num">resources</th><th class="num">subjects</th>
<th>strongest</th><th>who</th></tr></thead>
<tbody>{rows}</tbody></table></div></section>""")

    return _shell("services", _nav("/services") + """<header class="glass">
<h1>What is granted, by service</h1>
<p class="lede">Browse access by service. Open a resource kind to inspect its resources,
or an account to see its direct and inherited access.</p></header>"""
                  + _since_run(recorder)
                  + "".join(f'<section class="glass"><div class="warn stop" role="status"><b>Could not read {e(u.system)}</b>'
                            f'{e(u.note)}. This is unknown access, not an empty service.</div></section>' for u in unobserved)
                  + ("".join(sections) if sections else '<section class="glass"><h2>No observed grants</h2>'
                     '<p class="ok">No grants are available to browse. Check service connections and any read errors above, '
                     'then refresh.</p></section>'))


# ── F1 drill ──────────────────────────────────────────────────────────────────
def render_group(observed: set[Grant], system: str, group: str) -> str:
    """One resource kind, resource by resource — the "one step" F1 promises."""
    res: dict[str, dict[str, set[str]]] = {}
    for g in observed:
        if g.system != system or group_of(g.system, g.resource)[1] != group:
            continue
        res.setdefault(g.resource, {}).setdefault(g.subject, set()).add(g.priv)

    # The grant link carries the resource that is already on the row. F3 starts from
    # something the steward is looking at, not from an empty form where the resource
    # name is retyped — a mistyped resource is a grant on the wrong thing.
    rows = "".join(
        f'<tr><td class="res">{e(r)}</td>'
        f'<td class="lvl {_strength({p for ps in subs.values() for p in ps})}">'
        f'{_strength({p for ps in subs.values() for p in ps})}</td>'
        f"<td>{_chips(subs)}</td>"
        f'<td><a class="chip go" href="{_act_href("grant", system=system, resource=r)}">'
        f"grant on this</a></td></tr>"
        for r, subs in sorted(res.items()))
    return _shell(f"{system} · {group}", _nav("/services"), f"""<header class="glass">
<a class="back" href="/services">&larr; All services</a>
<h1>{e(group)} <span class="cnt">on {e(system)}</span></h1>
<p class="lede">{len(res)} resources. This is the level a revoke acts on. Granting starts
from a row here, with the resource already filled in; revoking starts from the subject
who holds it, because that is where the route is visible.</p></header>
<section class="glass"><div class="scroll"><table>
<thead><tr><th>resource</th><th>strongest</th><th>who</th><th></th></tr></thead>
<tbody>{rows}</tbody></table></div>
{'<p class="ok">No resources were observed in this group. Return to services or refresh to check again.</p>' if not rows else ''}</section>""")


# ── F2 ────────────────────────────────────────────────────────────────────────
def render_subject(observed: set[Grant], graph, subject: str, unobserved=()) -> str:
    """One person (or service account): everything they reach, and by which routes.

    Routes matter more than the list. A resource reached two ways survives the removal
    of either one, so a steward who revokes the role they can see has changed nothing.
    """
    # "Everything they reach" — not "everything granted to their name". Almost nobody
    # holds a grant directly; they hold a role that holds it. A table listing only
    # direct grants shows researcher_a two databases and calls it complete, while the 25 tables
    # they actually read sit one hop away. Inherited rows carry the hop that confers
    # them, so the table stays honest about *why* the access exists.
    blind = "".join(f'<div class="warn">unknown: {e(u.system)} · {e(", ".join(u.prefixes))} '
                    f'({e(u.note)})</div>' for u in unobserved
                    if not u.subjects or subject in u.subjects)
    holders: dict[str, tuple[str, str]] = {subject: ("", "")}  # holder -> (chain, 1st hop)
    for route in graph.routes_from(subject):
        for i, hop in enumerate(route[1:], start=1):
            holders.setdefault(hop, (" &rarr; ".join(route[1:i + 1]), route[1]))

    # Which grant makes the first hop possible — that is the one a revoke can act on
    # from *this* page. A bridge has no such grant, and saying so is the point.
    memberships = {g.resource.removeprefix("role:"): g for g in observed
                   if g.subject == subject and g.resource.startswith("role:")}

    by_sys: dict[str, dict[str, tuple[set[str], str, str, str]]] = {}
    mine = []
    # Who granted each (holder, resource): the source's answer, or nothing. Shown as a
    # column only when at least one row has an answer — a column of blanks would read as
    # "nobody", which is the implication F1's known gap forbids.
    grantors: dict[tuple[str, str], set[str]] = {}
    for g in observed:
        if g.subject not in holders:
            continue
        mine.append(g)
        if g.grantor:
            grantors.setdefault((g.subject, g.resource), set()).add(g.grantor)
        chain, hop = holders[g.subject]
        privs, via, first, holder = by_sys.setdefault(g.system, {}).setdefault(
            g.resource, (set(), chain, hop, g.subject))
        privs.add(g.priv)
        if not via:  # a direct grant outranks the same resource reached via a hop
            by_sys[g.system][g.resource] = (privs, "", "", subject)

    def held_cell(system: str, resource: str, privs: set[str],
                  via: str, first: str, holder: str) -> str:
        if not via:
            # Held in this subject's own name: revoke is exactly what it looks like,
            # one link per privilege because a privilege is the unit REVOKE takes.
            links = "".join(
                f'<a class="chip rm" href="'
                f'{_act_href("revoke", system=system, subject=subject, resource=resource, priv=p)}'
                f'">revoke {e(p)}</a>' for p in sorted(privs))
            return f'directly<span class="acts">{links}</span>'
        # Inherited. Revoking it *from this subject* is not a thing the systems can
        # do — the grant is held by the role, and a REVOKE naming this subject would
        # succeed against nothing while the access stays exactly where it was. So the
        # page offers the two hops that would actually change something.
        m = memberships.get(first)
        if m is not None:
            cut = (f'<a class="chip rm" href="'
                   f'{_act_href("revoke", system=m.system, subject=subject, resource=m.resource, priv=m.priv)}'
                   f'">cut {e(subject)} &rarr; {e(first)}</a>')
        else:
            cut = ('<span class="hint">the first hop is a declared bridge, not a grant '
                   '&mdash; it is removed in the server\'s own configuration</span>')
        return (f'via {via}<span class="acts">{cut}'
                f'<a class="chip" href="/s/{quote(holder, safe="")}">revoke on {e(holder)}</a>'
                f"</span>")

    show_by = bool(grantors)
    by_th = "<th>granted by</th>" if show_by else ""

    def by_cell(holder: str, resource: str) -> str:
        if not show_by:
            return ""
        who = grantors.get((holder, resource))
        return f'<td class="via">{e(", ".join(sorted(who))) if who else "&mdash;"}</td>'

    direct = "".join(
        f"""<section class="glass"><h2>{e(system)}
<span class="cnt">{len(rs)} resources</span></h2>
<div class="scroll"><table>
<thead><tr><th>resource</th><th>privileges</th><th>level</th><th>held</th>{by_th}</tr></thead><tbody>"""
        + "".join(f'<tr><td class="res">{e(r)}</td>'
                  f'<td class="res">{e(", ".join(sorted(ps)))}</td>'
                  f'<td class="lvl {_strength(ps)}">{_strength(ps)}</td>'
                  f'<td class="via">{held_cell(system, r, ps, via, first, holder)}</td>'
                  f'{by_cell(holder, r)}</tr>'
                  for r, (ps, via, first, holder) in sorted(rs.items()))
        + "</tbody></table></div></section>"
        for system, rs in sorted(by_sys.items()))

    # "What did *I* grant" — the question F1 named as its known gap. Answered from the
    # person's own page: every grant the sources attribute to this subject as grantor.
    given = sorted((g for g in observed if g.grantor == subject),
                   key=lambda g: (g.system, g.subject, g.resource, g.priv))
    given_html = ""
    if given:
        given_html = (f'<section class="glass"><h2>Granted by {e(subject)} '
                      f'<span class="cnt">{len(given)}</span></h2><div class="scroll"><table>'
                      '<thead><tr><th>system</th><th>to</th><th>resource</th><th>privilege</th></tr></thead><tbody>'
                      + "".join(f'<tr><td>{e(g.system)}</td><td><a class="chip" href="/s/{quote(g.subject, safe="")}">{e(g.subject)}</a></td>'
                                f'<td class="res">{e(g.resource)}</td><td class="res">{e(g.priv)}</td></tr>' for g in given)
                      + "</tbody></table></div></section>")

    _direct = sum(1 for rs in by_sys.values() for v in rs.values() if not v[1])
    _inherited = sum(len(rs) for rs in by_sys.values()) - _direct

    bridged = {(x.src, x.dst) for x in graph.edges if x.kind == "bridge"}
    routes = [r for r in graph.routes_from(subject) if len(r) > 2]

    # Group by the *chain*, not the destination. Live data made the reason obvious:
    # researcher_a had 36 route rows whose tails repeated — every bucket reached through the
    # same three hops got its own line, and the hop chain (the thing a revoke acts on)
    # was buried in the repetition. One chain, its destinations underneath.
    chains: dict[tuple[str, ...], set[str]] = {}
    for r in routes:
        chains.setdefault(tuple(r[:-1]), set()).add(r[-1])

    def one_chain(chain: tuple[str, ...], dests: set[str]) -> str:
        out = [e(chain[0])]
        for a, b in zip(chain, chain[1:]):
            cls = "bridge" if (a, b) in bridged else "hop"
            out.append(f'<span class="{cls}">&rarr;</span> <a class="chip" '
                       f'href="/s/{quote(b, safe="")}">{e(b)}</a>')
        return ('<div class="route">' + " ".join(out)
                + f'<span class="cnt">{len(dests)}</span>'
                + '<div class="dests">'
                + "".join(f'<span class="res">{e(d)}</span>' for d in sorted(dests))
                + "</div></div>")

    route_html = "".join(
        one_chain(c, d) for c, d in
        sorted(chains.items(), key=lambda kv: (-len(kv[0]), kv[0])))
    if not mine:
        route_html = '<p class="hint">No observed grants or routes for this account.</p>'
    elif not routes:
        route_html = ('<p class="ok">Every grant is held directly &mdash; '
                      "no role or bridge stands in between.</p>")

    return _shell(subject, _nav("/matrix"), f"""<header class="glass">
<a class="back" href="/matrix">&larr; All accounts</a>
<h1>{e(graph.label(subject) if hasattr(graph, "label") else subject)}
<a class="chip go" href="{_act_href("grant", subject=subject)}">grant something</a>
<a class="chip" href="/s/{quote(subject, safe="")}/probe" title="ask each service, as this subject, on the real path">verify on the path</a></h1>
<p class="lede">{len(mine)} grants across {len(by_sys)} services &mdash;
{_direct} held directly, {_inherited} inherited through a role or bridge. Routes below show
<em>how</em> the authority arrives.</p><details class="explain"><summary>How to read inherited access</summary><p>A name in the middle is a role or an account that must
also be removed, and an <span class="route"><span class="bridge">&rarr;</span></span>
marks a hop that leaves the system entirely &mdash; a server-held credential, not
this subject's own. Rows held <em>via</em> something carry no revoke button: the grant
belongs to the role, and revoking in this subject's name would report success and change
nothing &mdash; so the row offers the hop to cut instead.</p></details>
{'<p class="ok">No grants were observed for this account. Check the name and read errors before concluding it has no access.</p>' if not mine else ''}</header>
<section class="glass"><h2>Routes <span class="cnt">{len(chains)} chains &middot; {len(routes)} paths &middot; <a href="/?focus={quote(subject, safe="")}">show on the map</a></span></h2>
{route_html}</section>{blind}{direct}{given_html}""")


def queue_sections(reqs: list) -> list[str]:
    """Every change that has been asked for, and where each one stands.

    A request lives as a file and, until now, only its requester's link knew it
    existed. Someone asked "what is waiting on me" and there was no page to send
    them to. This is that page: the exact command, who still has to say yes, and
    what happened to the ones that are done.

    The command is shown in full. Approving is agreeing to a specific string —
    the same one execution will refuse to deviate from — so it has to be readable
    here, not just in the mail that carried the link.
    """
    order = {"pending": 0, "approved": 1, "failed": 2, "executed": 3, "denied": 4}
    reqs = sorted(reqs, key=lambda r: (order.get(r.status, 9), r.ts), reverse=False)
    live = [r for r in reqs if r.status in ("pending", "approved", "failed")]
    done = [r for r in reqs if r not in live]

    def card(r) -> str:
        waiting = [a for a in r.required if a not in r.approved]
        who = "".join(
            f'<span class="chip {"yes" if a in r.approved else "no"}" title="'
            + (f"approved {e(r.approved[a])}" if a in r.approved else "not yet")
            + f'">{e(a)}</span>'
            for a in r.required)
        head = (f'<span class="st st-{e(r.status)}">{e(r.status)}</span> '
                f'<b>{e(r.action)}</b> {e(r.priv)} for <a href="/s/{quote(r.subject, safe="")}">{e(r.subject)}</a> on <code>{e(r.resource)}</code> '
                f'<span class="cnt">{e(r.system)}</span>')
        meta = (f'{e(r.requester)} asked, {e(r.ts[:16].replace("T", " "))}'
                + (f' &middot; waiting on {len(waiting)}' if waiting else '')
                + (f' &middot; {e(r.note)}' if r.note else ''))
        return (f'<div class="req"><div class="req-h">{head}</div>'
                f'<div class="req-m">{meta}</div>'
                f'<pre class="cmd">{e(r.cmd)}</pre>'
                f'<div class="req-w">{who}<a class="chip" href="/approve/{quote(r.id, safe="")}">View request</a></div></div>')

    body = []
    if live:
        body.append('<section class="glass"><h2>Waiting <span class="cnt">'
                    f'{len(live)}</span></h2>' + "".join(card(r) for r in live) + "</section>")
    else:
        body.append('<section class="glass"><h2>Waiting</h2>'
                    '<p class="ok">Nothing is queued. Propose one above, or from a resource '
                    'row or a subject page where the fields are already filled in.</p></section>')
    if done:
        body.append('<section class="glass"><h2>Settled <span class="cnt">'
                    f'{len(done)}</span></h2>' + "".join(card(r) for r in sorted(done, key=lambda r: r.ts, reverse=True)[:20]) + "</section>")
    return body


def render_probe(subject: str, probes, findings) -> str:
    """N4 from the console: the table said it, the path answered. Read-only probes only —
    a GET must not leave a mark, so the Write probe stays on the CLI (`probe --write`)."""
    from .probe import summary
    n = summary(probes)
    mark = {"allow": ("✓", "ok"), "deny": ("✗", "rm"), "unknown": ("?", "hint")}
    rows = "".join(
        f'<tr><td>{e(p.system)}</td><td class="res">{e(p.resource)}</td><td class="res">{e(p.priv)}</td>'
        f'<td class="lvl {mark[p.verdict][1]}">{mark[p.verdict][0]} {e(p.verdict)}</td>'
        f'<td class="via">{e(p.how)}</td></tr>'
        for p in sorted(probes, key=lambda p: ({"deny": 0, "unknown": 1, "allow": 2}[p.verdict], p.system, p.resource, p.priv)))
    fnd = "".join(f'<li><b>{e(f.title)}</b> — {e(f.detail)}</li>' for f in findings)
    return _shell(f"{subject} · on the path", _nav(""), f"""<header class="glass">
<h1>{e(subject)} <span class="cnt">on the path</span>
<a class="chip" href="/s/{quote(subject, safe="")}">back to {e(subject)}</a></h1>
<p class="lede">The grant table says what <em>should</em> be reachable; this asks each service,
as {e(subject)}, whether it <em>is</em>. {n['allow']} allowed · {n['deny']} denied ·
{n['unknown']} could not be asked &mdash; <code>unknown</code> is a reason, never "no access".
S3 rows are the real thing (their own key, the real endpoint); PostgreSQL rows are
server-evaluated unless subject login credentials are configured. ClickHouse can verify
a configured subject login; otherwise it resolves grants as the observer. Write probes
leave a mark and live on the CLI only.</p></header>
{'<section class="glass"><h2>Where the path disagrees with the table</h2><ul>' + fnd + '</ul></section>' if findings else ''}
<section class="glass"><h2>Rows <span class="cnt">{len(probes)}</span></h2><div class="scroll"><table>
<thead><tr><th>service</th><th>resource</th><th>privilege</th><th>verdict</th><th>how</th></tr></thead>
<tbody>{rows}</tbody></table></div>
{'<p class="ok">No grants are available to probe for this account. Return to its access page and check observation errors.</p>' if not rows else ''}</section>""")


def render_approve(req, approver: str | None, error: str = "", done: str = "") -> str:
    """One request, seen through one approver's link. Approve and deny are POSTs; the
    page states plainly what will run and who still has to say yes."""
    rows = "".join(f'<tr><td>{e(a)}</td><td>{"✓ " + e(t[:19]) if t else "&mdash; waiting"}</td></tr>'
                   for a, t in sorted((a, req.approved.get(a, "")) for a in req.required))
    form = ""
    if approver and req.status == "pending" and approver not in req.approved:
        form = (f'<form method="post" action="/approve/{quote(req.id, safe="")}"><input type="hidden" name="t" value="{e(req.required[approver])}">'
                f'<button class="chip go" name="decision" value="approve">approve as {e(approver)}</button> '
                f'<button class="chip rm" name="decision" value="deny">deny</button></form>')
    msg = (f'<p class="ok">{e(done)}</p>' if done else "") + (f'<p class="rm">{e(error)}</p>' if error else "")
    if not approver and req.status == "pending":
        msg += '<p class="hint">Viewing only. Use your personal approval link to approve or deny this request.</p>'
    if req.status == "approved":
        msg += '<p class="hint">All approvers approved. Awaiting execution by an operator with a write credential.</p>'
    return _shell(f"approve {req.id}", _nav(""), f"""<header class="glass">
<a class="back" href="/act">&larr; All changes</a>
<h1>{e(req.action)} {e(req.subject)} <span class="cnt">{e(req.priv)} on {e(req.resource)} · {e(req.system)}</span></h1>
<p class="lede">Requested by {e(req.requester)} at {e(req.ts[:19])}. Status: <b>{e(req.status)}</b>.
Every approver must approve this exact command. Execution also requires a write credential;
denial prevents it from running.</p><pre>{e(req.cmd)}</pre>{msg}{form}</header>
<section class="glass"><h2>Approvers</h2><div class="scroll"><table><thead><tr><th>who</th><th>decision</th></tr></thead>
<tbody>{rows}</tbody></table></div>{f'<p class="hint">{e(req.note)}</p>' if req.note else ''}</section>""")


def render_requested(req, links: list[str]) -> str:
    items = "".join(f"<li><code>{e(l)}</code></li>" for l in links)
    return _shell(f"request {req.id}", _nav(""), f"""<header class="glass"><h1>Approval requested</h1>
<p class="lede">{e(req.action)} {e(req.subject)} {e(req.priv)} on {e(req.resource)} [{e(req.system)}] &mdash;
<code>{e(req.cmd)}</code>. Each approver has their own link (sent by Slack when a bot token is
configured). Delivery status:</p><ul>{items}</ul></header>""")


# ── F3 ────────────────────────────────────────────────────────────────────────
def _field(label: str, name: str, value: str, options=None, listid: str = "") -> str:
    field_id = f"field-{name}"
    if options is not None:
        opts = "".join(f'<option value="{e(o)}"{" selected" if o == value else ""}>{e(o)}'
                       f"</option>" for o in options)
        if name == "system" and value not in options:
            opts = '<option value="" selected>Choose a service</option>' + opts
        control = f'<select id="{field_id}" name="{name}" required>{opts}</select>'
    else:
        control = (f'<input id="{field_id}" name="{name}" value="{e(value)}" autocomplete="off" required'
                   + (f' list="{listid}"' if listid else "") + ">")
    return f'<div class="field"><label for="{field_id}">{e(label)}</label>{control}</div>'


def render_act(params: dict, observed: set[Grant], adapters: dict,
               error: str = "", done: str = "", requests: list | None = None) -> str:
    """The one screen that writes: fill in, preview the native command, then run it.

    The preview is unconditional (N2) and it is the command itself, not a summary —
    a steward who cannot recognise the statement cannot approve it. What varies is
    only whether the button underneath it is there: with no write credential
    configured, this page ends at a command you can paste into the service's own
    client, which is what the tool is for anyway.
    """
    action = (params.get("action") or "grant").strip()
    system = (params.get("system") or "").strip()
    subject = (params.get("subject") or "").strip()
    resource = (params.get("resource") or "").strip()
    priv = (params.get("priv") or "").strip()
    systems = sorted(adapters)
    if not system and len(systems) == 1:
        system = systems[0]

    # 무엇을 고를 수 있는지는 시스템마다 다르다 — postgres 의 CONNECT 는 S3 에 없고,
    # 버킷 경로는 ClickHouse 에 없다. 그래서 목록은 시스템별로 따로 내고, 위의
    # 시스템 선택이 바뀌면 아래 세 칸이 그 시스템 것으로 갈아탄다. datalist 라서
    # 아직 아무도 갖고 있지 않은 자원도 그대로 타이핑할 수 있다.
    opts: dict[str, dict[str, set]] = {
        s: {"subject": set(), "resource": set(), "priv": set(getattr(adapters[s], "privs", ()))}
        for s in systems}
    for g in observed:
        if g.system in opts:
            opts[g.system]["subject"].add(g.subject)
            opts[g.system]["resource"].add(g.resource)
            opts[g.system]["priv"].add(g.priv)
    slot = {s: f"s{i}" for i, s in enumerate(systems)}
    datalist = "".join(
        f'<datalist id="{slot[s]}-{f}">'
        + "".join(f'<option value="{e(v)}">' for v in sorted(vals)) + "</datalist>"
        for s, fields in opts.items() for f, vals in fields.items())
    here = slot.get(system, "s0")

    form = f"""<section class="glass"><h2>1 &middot; Describe the change</h2>
<form class="act" id="propose" method="get" action="/act">
{_field("direction", "action", action, options=["grant", "revoke"])}
{_field("system", "system", system, options=systems)}
{_field("subject", "subject", subject, listid=f"{here}-subject")}
{_field("resource", "resource", resource, listid=f"{here}-resource")}
{_field("privilege", "priv", priv, listid=f"{here}-priv")}
<button type="submit"{' disabled' if not systems else ''}>Preview the command</button>
</form>{datalist}
{'<p class="warn">No services are configured. Configure a service before preparing a change.</p>' if not systems else ''}
<p class="hint">Resources are spelled as the model spells them &mdash;
<code>role:analyst_read</code>, <code>db:analytics</code>,
<code>table:&lt;db&gt;.&lt;schema&gt;.&lt;name&gt;</code>,
<code>bucket:&lt;bucket&gt;/&lt;prefix&gt;</code>. Copy one from a resource page rather
than typing it.</p></section>"""

    blocks = []
    if done:
        blocks.append(f'<section class="glass"><h2>Done</h2>'
                      f'<div class="warn done"><b>applied</b>{e(done)}</div></section>')
    if error:
        blocks.append(f'<section class="glass"><h2>Nothing ran</h2>'
                      f'<div class="warn stop"><b>refused</b>'
                      f"<pre>{e(error)}</pre></div></section>")

    if system and subject and resource and priv and not error:
        try:
            prop = propose(action, system, subject, resource, priv, observed, adapters)
        except ActError as exc:
            blocks.append(f'<section class="glass"><h2>Cannot preview</h2>'
                          f'<div class="warn stop"><b>refused</b>'
                          f"<pre>{e(str(exc))}</pre></div></section>")
        else:
            blocks.append(_preview(prop))

    # 제안하는 자리와 제안된 것들이 한 화면에 있다. 나뉘어 있을 때는 요청을 낸 뒤
    # 그것이 어디로 갔는지 보려면 탭을 옮겨야 했고, 큐만 열면 무엇을 더 낼 수 있는지가
    # 안 보였다. 둘은 같은 질문의 앞뒤다.
    # 쓰기 자격이 없는 배포에서는 이 화면이 무엇을 하는 곳인지 먼저 말한다. 명령을
    # 보여주는 일은 그대로 되지만 여기서 실행되지는 않는다 — 그걸 눌러 보고 알게 하지
    # 않는다. 아래 preview 의 「no button here」와 같은 사실을, 누르기 전에.
    ro = ('<div class="warn"><b>read-only here</b>This console holds no write credential, '
          'so nothing on this page runs. It still spells the exact native command for the '
          'change you describe — copy it into the service\'s own client, or use the CLI '
          'with <code>--write</code> where the credential lives.</div>'
          if WRITE_READY is False else "")
    return _shell("changes", _nav("/act"), f"""<header class="glass">
<h1>Changes</h1>{ro}
<p class="lede">Describe one change, review its exact command, then submit it.
Track requests and approvals below. Nothing runs while preparing a preview.</p></header>""",
                  *blocks, form, *queue_sections(requests or []))


# Set by web.serve when the config has an [approvals] section: the preview then offers
# "request approval" next to (or instead of) the run button. A module flag, because the
# preview is rendered from several places and the alternative was threading one boolean
# through all of them.
APPROVALS_ENABLED = False


def _request_form(p: Proposal) -> str:
    hidden = "".join(f'<input type="hidden" name="{k}" value="{e(v)}">' for k, v in (
        ("action", p.action), ("system", p.grant.system), ("subject", p.grant.subject),
        ("resource", p.grant.resource), ("priv", p.grant.priv), ("cmd", p.cmd)))
    return (f'<form class="act" method="post" action="/request">{hidden}'
            f'<button class="chip go" type="submit">request approval</button>'
            f'<span class="hint">routes this exact command to the approvers the config names</span></form>')


def _preview(p: Proposal) -> str:
    klass = "add" if p.action == "grant" else "rm"
    body = [f'<div class="cmd"><code class="{klass}">{e(p.cmd)}</code></div>']

    if p.blocked:
        body.append(f'<div class="warn stop"><b>not runnable</b>{e(p.blocked)}</div>')
    elif p.note:
        body.append(f'<div class="warn"><b>worth knowing</b>{e(p.note)}</div>')

    if p.blocked:
        pass  # no button: running it would change nothing and claim it changed something
    elif APPROVALS_ENABLED:
        pass  # Only the approval route may execute in this console.
    elif p.ready:
        hidden = "".join(
            f'<input type="hidden" name="{k}" value="{e(v)}">' for k, v in (
                ("action", p.action), ("system", p.grant.system),
                ("subject", p.grant.subject), ("resource", p.grant.resource),
                ("priv", p.grant.priv), ("cmd", p.cmd)))
        body.append(f"""<form class="act" method="post" action="/act">{hidden}
<button class="run {klass}" type="submit">Run this command on {e(p.grant.system)}</button>
<span class="hint">{e(p.ready_note)}</span></form>""")
    else:
        body.append(f"""<div class="warn"><b>no button here</b>{e(p.ready_note)}
Copy the command above into {e(p.grant.system)}'s own client and run it there, or set
that variable in the environment this console runs in and the button appears.</div>""")

    if not p.blocked and APPROVALS_ENABLED:
        body.append(_request_form(p))

    verb = "would grant" if p.action == "grant" else "would revoke"
    return f"""<section class="glass" id="preview"><h2>2 &middot; Preview &middot; {e(p.grant.system)}</h2>
<p class="hint">{verb} {e(p.grant.priv)} on {e(p.grant.resource)}
{"to" if p.action == "grant" else "from"} {e(p.grant.subject)}</p>
{"".join(body)}</section>"""


def parse_path(path: str) -> tuple[str, tuple]:
    """Route a URL to (page, args). Kept here so serve() stays a transport."""
    parts = [unquote(p) for p in path.strip("/").split("/") if p]
    if not parts:
        return "graph", ()          # 첫 화면 = 지도
    if parts == ["services"]:
        return "inventory", ()
    if parts[0] == "s" and len(parts) == 2:
        return "subject", (parts[1],)
    if parts[0] == "s" and len(parts) == 3 and parts[2] == "probe":
        return "probe", (parts[1],)
    if parts[0] == "g" and len(parts) == 3:
        return "group", (parts[1], parts[2])
    if parts[0] == "approve" and len(parts) == 2:
        return "approve", (parts[1],)
    if parts == ["request"]:
        return "request", ()
    if parts == ["act"]:
        # Fields arrive in the query string (GET, no side effect) or the body (POST,
        # the only thing that writes) — not in the path.
        return "act", ()
    if parts == ["matrix"]:
        return "matrix", ()
    if parts == ["graph"]:
        return "graph", ()          # 옛 주소. 지도가 `/` 로 옮겨간 뒤에도 그대로 연다
    return "404", ()
