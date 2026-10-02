"""CLI: plan (default, read-only) · serve (web matrix) · apply (--write only)."""
from __future__ import annotations

import argparse
import tomllib
from pathlib import Path

from . import adapters, audit, diff
from . import intent as intent_mod
from . import snapshot as snap
from .model import Unobserved


def _approvals(config_path: str):
    from .approvals import Approvals
    cfg = tomllib.loads(Path(config_path).read_text())
    return Approvals(cfg.get("approvals"), Path(config_path).parent, (cfg.get("notify") or {}).get("slack"))


def _load(config_path: str):
    _load_env_file(config_path)
    cfg = tomllib.loads(Path(config_path).read_text())
    base = Path(config_path).parent

    def rel(p):  # paths in config are relative to the config file
        # `~` first: a config kept outside the repo (the usual place for a real
        # deployment, since it names real hosts) is most naturally written with `~`.
        # Without this it becomes a literal directory name and the error points at
        # a nonsense path like `<configdir>/~/.config/...`.
        if not p:
            return p
        p = str(Path(p).expanduser())
        return p if Path(p).is_absolute() else str(base / p)

    def rel_paths(d: dict) -> dict:  # file-ish keys, one level of nesting (planes)
        return {k: rel(v) if k in ("fixture", "file", "dir") else
                   rel_paths(v) if isinstance(v, dict) else v
                for k, v in d.items()}

    adaps = {}
    for system, acfg in cfg.get("adapters", {}).items():
        adaps[system] = adapters.build(system, rel_paths(acfg))
    it = intent_mod.load(rel(cfg["intent"]))
    audit = rel(cfg.get("audit_log", "audit.jsonl"))
    # F8. 설정 파일 옆 — 실제 배포에서 설정은 저장소 밖(`~/.config/grantline/`)에
    # 있고, 스냅샷은 그 옆에 쌓여야 한다. 관찰한 것을 저장소에 커밋하는 사고를
    # 구조적으로 막는다.
    snapshots = rel(cfg.get("snapshots", "snapshots"))
    # 브리지는 관찰로 알 수 없는 홉이다 — grant 테이블에 기록되지 않는 경로라
    # 선언이 유일한 출처다 (grantline/graph.py 머리말 참조).
    return it, adaps, audit, cfg.get("bridges", []), snapshots


def _load_env_file(config_path: str) -> list[str]:
    """`env_file` in the config: `KEY=value` lines, loaded into the environment.

    The rule is that credentials never sit in the config; it was never that they
    must sit in your shell history. A file next to the config (mode 600, outside
    the repository) is the same guarantee with a usable CLI. Existing environment
    variables win, so a launcher can still override.
    """
    import os
    import stat
    cfg = tomllib.loads(Path(config_path).read_text())
    raw = cfg.get("env_file")
    if not raw:
        return []
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path(config_path).parent / path
    if not path.is_file():
        raise SystemExit(f"env_file {path} does not exist")
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SystemExit(f"env_file {path} is readable by others — chmod 600 it first")
    loaded = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v
            loaded.append(k)
    return loaded


def _graph_builder(config_path: str, adaps: dict, bridges: list):
    """The map needs what observe() left on the adapters (kinds, S3 routes) plus the
    one thing nothing observes: which accounts are services (`[graph] services`)."""
    from . import graph
    gcfg = tomllib.loads(Path(config_path).read_text()).get("graph", {})
    services = tuple(gcfg.get("services", ["svc-*"]))
    people = dict(gcfg.get("people", {}))   # account -> real name, shown as `account (name)`
    teams = dict(gcfg.get("teams", {}))     # account -> team, groups the principal column
    # environment -> instances; inverted here so the graph asks per instance
    envs: dict = {}
    for env, systems in gcfg.get("environments", {}).items():
        for sy in systems:
            envs.setdefault(sy, []).append(env)

    def build(observed):
        kinds: dict = {}
        routes: list = []
        for a in adaps.values():
            kinds.update(getattr(a, "kinds", {}) or {})
            routes += getattr(a, "routes", []) or []
        return graph.build(observed, bridges, kinds=kinds, routes=routes, services=services,
                           names=people, envs=envs, teams=teams)
    return build


def _observe_and_plan(it, adaps, recorder=None):
    """Observe every adapter, then diff against intent.

    The adapters are read **concurrently**: they are independent servers and the
    wait is entirely network. Measured on a real cluster — postgres 0.86 s,
    postgres-staging 1.01 s, clickhouse 0.10 s, clickhouse-staging 0.16 s, s3
    3.25 s — serial 5.4 s, concurrent 3.3 s, the slowest one. Threads, not async:
    every adapter's client is blocking (psycopg, urllib) and each has its own
    connection, so there is nothing to share and nothing to lock.

    An adapter that raises is not allowed to take the page down with it. Its
    scope becomes unobserved — "could not read" is an answer this tool has, and
    it is the one that keeps `?` from being rendered as "no access" (F6).
    """
    from concurrent.futures import ThreadPoolExecutor

    def read(item):
        name, a = item
        try:
            return name, a.observe(), None
        except Exception as exc:                       # noqa: BLE001 - reported, not hidden
            return name, (set(), [], []), exc

    observed: set = set()
    findings: list = []
    unobserved: list = []
    with ThreadPoolExecutor(max_workers=max(1, len(adaps))) as pool:
        results = list(pool.map(read, adaps.items()))
    for name, (g, f, u), exc in results:
        observed |= g
        findings += f
        unobserved += u
        if exc is not None:
            unobserved.append(Unobserved(name, ("",), f"adapter raised: {exc}"))
    changes, lint, unverified = diff.plan(it, observed, adaps, unobserved)
    # 관찰이 지나는 유일한 지점이라 여기서 남긴다 — plan·apply·serve 가 같은 기록을
    # 남기고, serve 는 매 요청이 아니라 프로세스당 한 번만 남긴다 (Recorder 참조).
    comparison = recorder.record(observed, unobserved, adaps.keys()) if recorder else None
    # unobserved 도 그대로 넘긴다. unverified 는 「선언된 것 중 못 읽은 것」이라
    # 아무것도 선언되지 않은 시스템이 통째로 죽으면 비어 있다 — 지도가 F6 을 말하려면
    # 「무엇을 못 읽었나」가 원본 그대로 필요하다 (web.graph_data).
    return observed, changes, findings + lint, unverified, comparison, unobserved


def _print_comparison(cmp) -> None:
    if not cmp.moved:
        print("  Nothing changed. Every grant seen then was seen now, and no new one appeared.")
    for g in cmp.added:
        print(f"  + [{g.system}] {g.subject} {g.priv} on {g.resource}")
    for g in cmp.removed:
        print(f"  - [{g.system}] {g.subject} {g.priv} on {g.resource}")
    # 시야가 바뀐 것은 접근이 바뀐 것이 아니다 (F6). 개수만 말하고 위 목록과 섞지 않는다.
    if cmp.obscured:
        print(f"  ? {len(cmp.obscured)} grant(s) sat in a scope this run could not read — "
              f"unknown now, not revoked.")
    if cmp.revealed:
        print(f"  ? {len(cmp.revealed)} grant(s) are readable again after a scope the "
              f"previous run missed — visible now, not newly granted.")


def cmd_history(args):
    """F8 over time: any two runs, or "the run that stood N days ago" against now."""
    _, _, _, _, snapdir = _load(args.config)
    files = snap.snapshots(snapdir)
    if not files:
        print(f"No snapshots in {snapdir} — run plan or serve once."); return 1
    if not args.since and not getattr(args, "from_", None):
        print(f"{len(files)} snapshot(s) in {snapdir}:\n")
        for p in files:
            sn = snap.load(p)
            print(f"  {sn.ts.isoformat()}  {len(sn.grants):5d} grants  {sn.user:<10} "
                  f"{','.join(sorted(sn.systems))}  {p.name}")
        print("\n  history --since 7d      what moved since the run that stood 7 days ago"
              "\n  history --from A --to B  any two snapshot files (names as listed)")
        return 0
    if args.since:
        when = snap.parse_since(args.since)
        prev_p = snap.at_or_before(snapdir, when)
        if prev_p is None:
            print(f"No snapshot at or before {when.isoformat()} — the memory starts at {files[0].name}."); return 1
        cur_p = files[-1]
    else:
        prev_p, cur_p = Path(snapdir) / args.from_, Path(snapdir) / (args.to or files[-1].name)
    prev, cur = snap.load(prev_p), snap.load(cur_p)
    cmp = snap.compare(prev, cur)
    print(f"Between {prev.ts.isoformat()} and {cur.ts.isoformat()} ({cmp.ago()} apart):\n")
    _print_comparison(cmp)
    print(); return 0


def _print_since(rec, cmp) -> None:
    """F8 위쪽 자리 — 이번 실행이 직전 실행과 무엇이 다른지.

    간격은 불규칙하다(스케줄러가 없다). 그래서 "3일 전 실행과 비교" 라고 경과를
    말하고, 없는 주기를 암시하는 표현("어제 이후")은 쓰지 않는다.
    """
    if rec.error:
        print(f"\nSnapshot — {rec.error}\n"
              f"  The observation below is still good; only the record of it is missing.")
        return
    if cmp is None:
        if rec.snapshot:
            print(f"\nSnapshot — first one recorded ({rec.snapshot.path}).\n"
                  f"  Nothing to compare with yet. Nothing here runs on a schedule, so the\n"
                  f"  next comparison covers however long it is until you run this again.")
        return
    print(f"\nSince your previous run, {cmp.ago()} "
          f"({cmp.prev.ts.isoformat()} -> {cmp.cur.ts.isoformat()}):\n")
    _print_comparison(cmp)


def cmd_plan(args):
    it, adaps, _, _, snapdir = _load(args.config)
    rec = snap.Recorder(snapdir)
    observed, changes, findings, unverified, comparison, _ = _observe_and_plan(it, adaps, rec)
    _print_since(rec, comparison)
    if changes:
        print(f"\nPlan — {len(changes)} change(s) to converge on intent:")
        print(_intent_age(args.config) + "\n")
        for c in changes:
            print(f"  {'+' if c.action == 'grant' else '-'} [{c.grant.system}] {c.cmd}")
    else:
        print("\nConverged — observed state matches intent.")
    if unverified:
        print(f"\nUnverified ({len(unverified)}) — could not check, NOT 'no access':\n")
        for g in unverified:
            print(f"  ? [{g.system}] {g.subject} {g.priv} on {g.resource}")
    if findings:
        # 종류별로 묶어서 낸다. 한 원인이 수백 줄을 만드는 경우가 흔해서(실측:
        # 삭제된 DB 하나가 60줄, 관찰 전용 실행이 2,110줄) 전부 나열하면 진짜
        # 발견이 그 안에 묻힌다. 큰 묶음은 앞 몇 개만 보이고 --verbose 로 전부 본다.
        import collections
        groups: dict[tuple[str, str], list] = collections.defaultdict(list)
        for f in findings:
            groups[(f.system, f.title)].append(f)
        print(f"\nFindings ({len(findings)} in {len(groups)} kind(s)):\n")
        cap = None if getattr(args, "verbose", False) else 3
        for (system, title), fs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            n = len(fs)
            print(f"  · [{system}] {title}" + (f"  ×{n}" if n > 1 else ""))
            for f in (fs if cap is None else fs[:cap]):
                print(f"    {f.detail}")
            if cap is not None and n > cap:
                print(f"    … {n - cap} more (--verbose)")
    print()
    return 0


def cmd_serve(args):
    from . import web
    it, adaps, audit_path, bridges, snapdir = _load(args.config)
    rec = snap.Recorder(snapdir)
    web_cfg = tomllib.loads(Path(args.config).read_text()).get("web", {})
    # The adapters and the audit path go along so the console can grant and revoke
    # (F3). They do not make it write: an adapter writes only when the config names a
    # write credential and that environment variable exists — see Adapter.write_ready.
    web.serve(lambda: _observe_and_plan(it, adaps, rec), args.port, lambda: bridges,
              adapters=adaps, audit_path=audit_path, recorder=rec, approvals=_approvals(args.config),
              graph_fn=_graph_builder(args.config, adaps, bridges),
              trusted_hosts=web_cfg.get("trusted_hosts", []), auth=web_cfg.get("auth"))
    return 0


def _intent_age(config_path: str) -> str:
    """One line: how old the declaration is.

    A plan of 285 changes usually means the world moved, not that someone granted
    285 things — the intent file was generated once and never again. The number is
    read as drift when it is staleness, so the age goes next to it.
    """
    import datetime
    cfg = tomllib.loads(Path(config_path).read_text())
    raw = cfg.get("intent")
    if not raw:
        return "  (no intent file — nothing is declared)"
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path(config_path).parent / path
    if not path.is_file():
        return f"  (intent {path} does not exist)"
    age = datetime.datetime.now() - datetime.datetime.fromtimestamp(path.stat().st_mtime)
    days = age.days
    when = "today" if days == 0 else f"{days} day(s) ago"
    warn = "  ← regenerate it before reading the plan as drift" if days >= 7 else ""
    return f"  declaration: {path.name}, last written {when}{warn}"


def cmd_snapshot(args):
    """Observe once, write one snapshot, say what moved. Nothing else.

    `serve` records once per process, so a console left running all day leaves one
    point of history — the resolution of the record was the number of times someone
    restarted it. This is the command a scheduler runs.
    """
    it, adaps, _, _, snapdir = _load(args.config)
    rec = snap.Recorder(snapdir)
    observed, _, _, _, comparison, _ = _observe_and_plan(it, adaps, rec)
    print(f"Recorded {len(observed)} grant(s) from {len(adaps)} system(s) into {snapdir}.")
    if comparison:
        _print_since(rec, comparison)
    return 0


def cmd_apply(args):
    it, adaps, audit_path, _, snapdir = _load(args.config)
    rec = snap.Recorder(snapdir)
    _, changes, _, _, comparison, _ = _observe_and_plan(it, adaps, rec)
    _print_since(rec, comparison)
    if not changes:
        print("Converged — nothing to apply.")
        return 0
    for c in changes:
        print(f"  {'+' if c.action == 'grant' else '-'} [{c.grant.system}] {c.cmd}")
    if not args.write:
        print(f"\nDry-run: {len(changes)} change(s) NOT applied. Re-run with --write.")
        return 0
    if not args.yes and input(f"\nApply {len(changes)} change(s)? Type 'apply': ") != "apply":
        print("Aborted.")
        return 1

    ok_count = 0
    for c in changes:
        # One writer of audit lines (grantline/audit.py), shared with the console, so the
        # log does not depend on which surface the change came from.
        err = audit.record(audit_path, c.grant.system, c.action, c.cmd,
                           lambda c=c: adaps[c.grant.system].apply(c))
        if err:  # keep going; the audit log records the failure
            print(f"  FAILED: {c.cmd}\n    {err}")
        else:
            ok_count += 1
    print(f"Applied {ok_count}/{len(changes)} change(s). Audit log: {audit_path}")
    return 0 if ok_count == len(changes) else 1


def cmd_probe(args):
    from . import probe as probe_mod
    it, adaps, _, _, snapdir = _load(args.config)
    observed, *_ = _observe_and_plan(it, adaps, snap.Recorder(snapdir))
    subjects = set(args.subject or []) or None
    systems = set(args.system or []) or None
    probes, findings = probe_mod.run(adaps, observed, subjects, systems, write=args.write)
    n = probe_mod.summary(probes)
    print(f"Probed {len(probes)} rows — allow {n['allow']} · deny {n['deny']} · unknown {n['unknown']}"
          " (unknown = could not ask, never 'no access')\n")
    for p in probes:
        if args.verbose or p.verdict != "allow":
            mark = {"allow": "✓", "deny": "✗", "unknown": "?"}[p.verdict]
            print(f"  {mark} [{p.system}] {p.subject} {p.priv} on {p.resource}   {p.how}")
    if findings:
        print(f"\nFindings ({len(findings)}):\n")
        for f in findings:
            print(f"  · [{f.system}] {f.title}\n    {f.detail}")
    print()
    return 0


def cmd_request(args):
    """Propose a change and route it to the people the config names."""
    from .act import ActError, propose
    it, adaps, audit_path, _, snapdir = _load(args.config)
    ap = _approvals(args.config)
    if args.links:
        try:
            req = ap.load(args.links)
        except ActError as exc:
            print(f"refused: {exc}"); return 1
        for who in req.required:
            print(f"{who}: {ap.link(req, who)}")
        return 0
    if args.list:
        for r in ap.all():
            print(f"  {r.id}  {r.status:<9} {r.action} {r.subject} {r.priv} on {r.resource} [{r.system}]"
                  f"  approved: {', '.join(r.approved) or '—'}  missing: {', '.join(r.missing) or '—'}")
        return 0
    observed, *_ = _observe_and_plan(it, adaps, snap.Recorder(snapdir))
    if args.execute:
        try:
            r = ap.run(ap.load(args.execute), adaps, audit_path, observed)
            print(f"executed {r.id}: {r.cmd}")
            return 0
        except ActError as exc:
            print(f"refused: {exc}"); return 1
    try:
        prop = propose(args.action, args.system, args.subject, args.resource, args.priv, observed, adaps)
        req = ap.create(prop)
    except ActError as exc:
        print(f"refused: {exc}"); return 1
    print(f"request {req.id} — {req.action} {req.subject} {req.priv} on {req.resource} [{req.system}]\n  {req.cmd}\n")
    print("approval notification status:")
    for line in ap.notify(req):
        print("  " + line)
    print("\nwhen every approver has approved, the console runs it if a write credential is set;"
          "\notherwise: grantline request --execute " + req.id)
    return 0


def cmd_notify(args):
    """Drift since the previous run → Slack channel (or stdout without a token)."""
    from . import slack
    it, adaps, _, _, snapdir = _load(args.config)
    ap = _approvals(args.config)
    rec = snap.Recorder(snapdir)
    _, _, _, _, cmp, _ = _observe_and_plan(it, adaps, rec)
    if cmp is None:
        print("first run — nothing to compare yet"); return 0
    lines = [f"[grantline] since the run {cmp.ago()} ({cmp.prev.ts.isoformat()} → {cmp.cur.ts.isoformat()}):"]
    lines += [f"  + [{g.system}] {g.subject} {g.priv} on {g.resource}" for g in cmp.added]
    lines += [f"  - [{g.system}] {g.subject} {g.priv} on {g.resource}" for g in cmp.removed]
    if cmp.obscured: lines.append(f"  ? {len(cmp.obscured)} grant(s) unknown now (scope unread), not revoked")
    if cmp.revealed: lines.append(f"  ? {len(cmp.revealed)} grant(s) visible again, not newly granted")
    if not cmp.moved and not cmp.obscured and not cmp.revealed:
        lines.append("  nothing moved")
    text = "\n".join(lines)
    ch = ap.slack_cfg.get("channel")
    r = slack.post(ap.slack_cfg, ch, text) if ch else ""
    print(text + ("" if r == "" else f"\n(slack: {'sent' if not r.startswith('error') else r})"))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="grantline", description=__doc__)
    ap.add_argument("-c", "--config", default="grantline.toml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan", help="show drift and the native commands that would fix it").add_argument(
        "--verbose", "-v", action="store_true",
        help="show every finding instead of the first few per kind")
    s = sub.add_parser("serve", help="web access matrix")
    s.add_argument("--port", type=int, default=8420)
    a = sub.add_parser("apply", help="execute the plan (read-only unless --write)")
    a.add_argument("--write", action="store_true", help="actually execute (default: dry-run)")
    a.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p = sub.add_parser("probe", help="N4: ask each service, as the subject, on the real path")
    p.add_argument("--subject", action="append", help="only these subjects (repeatable)")
    p.add_argument("--system", action="append", help="only these instances (repeatable)")
    p.add_argument("--write", action="store_true", help="S3: also try a Write probe (PUT then DELETE)")
    p.add_argument("--verbose", "-v", action="store_true", help="show allow rows too")
    h = sub.add_parser("history", help="F8 over time: list runs, or compare any two")
    h.add_argument("--since", help="7d / 2w / 12h / 2026-08-01 — compare the run that stood then with the latest")
    h.add_argument("--from", dest="from_", help="snapshot file name to compare from")
    h.add_argument("--to", help="snapshot file name to compare to (default: latest)")
    r = sub.add_parser("request", help="propose one grant/revoke for approval by the people the config names")
    r.add_argument("action", nargs="?", choices=["grant", "revoke"])
    r.add_argument("system", nargs="?"); r.add_argument("subject", nargs="?")
    r.add_argument("resource", nargs="?"); r.add_argument("priv", nargs="?")
    r.add_argument("--list", action="store_true", help="show requests and where they stand")
    r.add_argument("--execute", metavar="ID", help="run an approved request (needs a write credential)")
    r.add_argument("--links", metavar="ID", help="operator only: reveal private approval links for secure delivery")
    sub.add_parser("notify", help="post what moved since the previous run to Slack (or stdout)")
    sub.add_parser("snapshot", help="observe once and record it — for cron, so history has a cadence")
    args = ap.parse_args(argv)
    if args.cmd == "request" and not (args.list or args.execute or args.links) and not all([args.action, args.system, args.subject, args.resource, args.priv]):
        ap.error("request needs: action system subject resource priv  (or --list / --execute ID)")
    return {"plan": cmd_plan, "serve": cmd_serve, "apply": cmd_apply, "probe": cmd_probe,
            "history": cmd_history, "request": cmd_request, "notify": cmd_notify,
            "snapshot": cmd_snapshot}[args.cmd](args)
