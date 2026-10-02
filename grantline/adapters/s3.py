"""S3-compatible object storage adapter (SeaweedFS / MinIO style identities).

Two auth *planes* can coexist — a static config file and a dynamic IAM store —
and only one of them is what the gateway actually consults (`enforced` in
config). Each plane has its own endpoint AND its own credentials: keys are
paired to their plane, and using one plane's key against the other's endpoint
fails as a misleading 403/SignatureDoesNotMatch, not "unknown user". That is
why every plane is a separate config block with its own `*_env` keys — and, within
a plane, why reading and writing name different ones (`url_env` vs `admin_url_env`,
as PostgreSQL and ClickHouse do). Reading a plane must never confer writing it.

Within a plane, an identity may carry both a native action list and an IAM
policy — and when a policy exists, THE NATIVE ACTIONS ARE IGNORED. This
adapter honors that on both sides:
  read:  effective grants come from the policy; shadowed actions are a finding
  write: for a policy-bearing identity, grant/revoke mutates the POLICY
         document (shown as an old->new diff in the plan) — editing the dead
         action list and calling it a change would be a lie.
"""
from __future__ import annotations

import difflib
import fnmatch
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path

from ..model import Finding, Grant, Unobserved
from . import Adapter, _file_ready, env, env_ready

_POLICY_ACTION = {  # IAM action -> normalized priv (observation)
    "s3:GetObject": "Read", "s3:ListBucket": "List", "s3:GetBucketLocation": "List",
    "s3:PutObject": "Write", "s3:DeleteObject": "Write",
    # multipart is how every large upload happens; it is Write, not a fourth verb
    "s3:CreateMultipartUpload": "Write", "s3:UploadPart": "Write",
    "s3:CompleteMultipartUpload": "Write", "s3:AbortMultipartUpload": "Write",
    "s3:ListMultipartUploadParts": "List", "s3:ListBucketMultipartUploads": "List",
    "s3:GetObjectTagging": "Tagging", "s3:PutObjectTagging": "Tagging",
    "s3:*": "Admin", "*": "Admin",
}
_PRIV_ACTIONS = {  # normalized priv -> IAM actions (policy writes)
    "Read": ("s3:GetObject",), "List": ("s3:ListBucket",),
    "Write": ("s3:PutObject", "s3:DeleteObject"), "Admin": ("s3:*",),
}


def _arn(resource: str, objects: bool = True) -> str:
    """Canonical scope -> the ARN this service actually enforces.

    The canonical resource drops the trailing `/*` so two spellings compare equal
    (model.canonical). A policy document must put it back: `arn:aws:s3:::b/curated`
    matches one object literally named `curated`, while `b/curated/*` matches the
    prefix — which is what the grant means. Comparison and enforcement want different
    spellings of the same scope, and only enforcement is negotiable.

    `objects=False` yields the bucket ARN itself, which is what ListBucket is
    evaluated against; object actions are evaluated against the keys inside it.
    """
    scope = resource.removeprefix("bucket:")
    if scope == "*":
        return "arn:aws:s3:::*"
    return "arn:aws:s3:::" + (scope if not objects else scope + "/*")



# SeaweedFS-style native actions are `Verb:bucket/prefix`. But an identity list can also
# carry service-qualified IAM actions (`s3tables:CreateTableBucket`), and those have the
# same shape with a completely different meaning. Splitting on ":" blindly turned
# `s3tables:CreateTableBucket` into a bucket named CreateTableBucket — four phantom
# buckets appeared in a real matrix. Only a known verb makes the right side a bucket.
_NATIVE_VERBS = frozenset({"Read", "Write", "List", "Tagging", "Admin"})


def _listed(v) -> list:
    """IAM's "string or list of strings" → list. None → []."""
    if v is None:
        return []
    return [v] if isinstance(v, str) else list(v)


def _action_grant(name: str, action: str, system: str = "s3") -> Grant:
    verb, sep, rest = action.partition(":")
    if verb in _NATIVE_VERBS:
        return Grant(system, name, f"bucket:{rest or '*'}", verb)
    if sep:
        # service-qualified capability, not a bucket grant
        return Grant(system, name, f"capability:{verb}", rest)
    return Grant(system, name, "bucket:*", action)


def _policy_scopes(policy: dict) -> tuple[str, ...]:
    """Unsupported semantics are still bounded by literal Resource ARNs when known."""
    scopes = set()
    for statement in policy.get("Statement", []):
        resources = _listed(statement.get("Resource"))
        if "NotResource" in statement or not resources:
            return ("bucket:",)
        for resource in resources:
            if not resource.startswith("arn:aws:s3:::"):
                return ("bucket:",)
            scope = resource.removeprefix("arn:aws:s3:::")
            pattern = scope[:-2] if scope.endswith("/*") else scope
            if scope == "*" or any(c in pattern for c in "*?[") or "${" in pattern:
                return ("bucket:",)
            scopes.add(Grant("s3", "", "bucket:" + scope, "").resource)
    return tuple(sorted(scopes)) or ("bucket:",)


def effective_grants(doc: dict, system: str = "s3", *, unobserved=None) -> tuple[set[Grant], list[Finding]]:
    """What one plane actually enforces: policy wins over native actions."""
    grants: set[Grant] = set()
    findings: list[Finding] = []
    for ident in doc.get("identities", []):
        name = ident["name"]
        if ident.get("policy"):
            if ident.get("actions"):
                findings.append(Finding(
                    system, "native actions shadowed by policy",
                    f"identity '{name}' has both an IAM policy and native actions "
                    f"{ident['actions']}; the policy wins and the actions are ignored. "
                    f"The matrix shows the policy (what is enforced).",
                    entities=(name, *ident["actions"]),
                ))
            # ⚠ Deny 를 건너뛰면 **막혀 있는 접근이 허용으로 렌더된다.** 재고 화면에서
            #    그건 그냥 틀린 답이다 — 관리자가 "이 사람은 못 본다" 를 확인하려고
            #    보는 화면인데 본다고 나온다.
            #
            #    Deny 는 공통 모델(있음/없음)에 자리가 없다. 그래서 **버리지 않고**
            #    Allow 에서 빼고, 뺐다는 사실을 finding 으로 낸다 (F4: 모델에 안 들어가는
            #    사실은 침묵하지 않는다).
            allowed: set[tuple[str, str]] = set()
            denied: set[tuple[str, str]] = set()
            unsupported = False
            for st in ident["policy"].get("Statement", []):
                effect = st.get("Effect")
                if any(k in st for k in ("Condition", "NotAction", "NotResource", "Principal", "NotPrincipal")):
                    unsupported = True
                    continue
                if effect not in ("Allow", "Deny"):
                    unsupported = True
                    findings.append(Finding(
                        system, "policy statement with an unknown effect",
                        f"identity '{name}' has a statement whose Effect is "
                        f"{effect!r} — neither Allow nor Deny. Access is unknown.",
                        entities=(name,),
                    ))
                    continue
                # IAM lets a single value stand without brackets: `"Action": "s3:ListBucket"`.
                # Iterating that as a list yields its characters — privileges named `3`
                # and `:` on a bucket named `-` (seen live on the first tree read).
                privs = set(_listed(st.get("Action")))
                if any(a not in _POLICY_ACTION for a in privs):
                    unsupported = True
                bucket = allowed if effect == "Allow" else denied
                for res in _listed(st.get("Resource")):
                    scope = res.removeprefix("arn:aws:s3:::")
                    pattern = scope[:-2] if scope.endswith("/*") else scope
                    if scope != "*" and any(c in pattern for c in "*?["):
                        unsupported = True
                    for p in privs:
                        bucket.add((scope, p))

            # ponytail: only exact Deny subtraction; a full IAM evaluator belongs
            # in the storage service. Overlapping wildcard/partial denies stay unknown.
            for ds, da in denied:
                for scope, action in allowed:
                    if (ds, da) != (scope, action) and (
                            fnmatch.fnmatchcase(ds, scope) or fnmatch.fnmatchcase(scope, ds)) and (
                            fnmatch.fnmatchcase(da, action) or fnmatch.fnmatchcase(action, da)):
                        unsupported = True
                    if (ds, da) != (scope, action) and any(c in ds + scope + da + action for c in "*?["):
                        unsupported = True
                    if ds == scope and da != action and _POLICY_ACTION.get(da, da) == _POLICY_ACTION.get(action, action):
                        unsupported = True
            if unsupported:
                findings.append(Finding(system, "policy evaluation incomplete",
                                        f"identity '{name}': conditional, negative, or overlapping policy "
                                        "is unsupported; access is unknown, not absent. No grants are inferred.",
                                        entities=(name,)))
                if unobserved is not None:
                    unobserved.append(Unobserved(system, _policy_scopes(ident["policy"]),
                                                 "unsupported IAM policy", (name,)))
                continue

            for scope, p in sorted(allowed - denied):
                # Policy ARNs spell prefixes `x/y/*`; native actions spell the same
                # scope `x/y`. One canonical form, or the diff sees a difference
                # that is only spelling.
                grants.add(Grant(system, name, f"bucket:{scope}", _POLICY_ACTION.get(p, p), "policy"))

            overridden = sorted(allowed & denied)
            if overridden:
                shown = ", ".join(f"{p} on {scope}" for scope, p in overridden[:4])
                findings.append(Finding(
                    system, "explicit deny overrides an allow",
                    f"identity '{name}': {len(overridden)} allow(s) are cancelled by an "
                    f"explicit Deny — {shown}"
                    f"{' …' if len(overridden) > 4 else ''}. The matrix shows the "
                    f"enforced result (denied), not the Allow statement.",
                    entities=(name, *(value for pair in overridden[:4] for value in pair)),
                ))
            deny_only = sorted(denied - allowed)
            if deny_only:
                findings.append(Finding(
                    system, "deny without a matching allow",
                    f"identity '{name}' has {len(deny_only)} Deny statement(s) that "
                    f"cancel nothing — no Allow grants them. Harmless today, but the "
                    f"policy reads as if it restricts something it does not.",
                    entities=(name,),
                ))
        else:
            for action in ident.get("actions", []):
                grants.add(_action_grant(name, action, system))
    return grants, findings


def policy_with(policy: dict, g: Grant, add: bool) -> dict:
    """Pure old-policy -> new-policy transform for one grant atom."""
    if any(any(k in st for k in ("NotAction", "NotResource", "Principal", "NotPrincipal"))
           for st in policy.get("Statement", [])):
        raise ValueError("negative or principal-based policy writes are unsupported")
    # ListBucket is evaluated against the bucket itself; object actions against the
    # keys inside it. Writing `b/*` for a List grant produces a statement that never
    # matches — a policy that looks right and permits nothing.
    arn = _arn(g.resource, objects=g.priv != "List")
    actions = set(_PRIV_ACTIONS.get(g.priv, (g.priv,)))
    # ⚠ IAM 은 값 하나를 대괄호 없이 쓰는 것을 허용한다: `"Action": "s3:ListBucket"`.
    #   그걸 list() 하면 **글자 단위로 쪼개진다** — 읽기 쪽에서 잡았던 바로 그 함정을
    #   쓰기 쪽이 그대로 갖고 있었다. 실환경 plan 에서 researcher_a 의 `s3:ListAllMyBuckets` 가
    #   ["s","3",":","L",...] 로 바뀌는 diff 가 나와 발견했다. 적용됐다면 정책이 깨진다.
    #   Resource 도 같은 이유로 정규화한다.
    statements = [dict(st, Action=_listed(st.get("Action")), Resource=_listed(st.get("Resource")))
                  for st in policy.get("Statement", [])]
    if add:
        for st in statements:
            if st.get("Effect") == "Allow" and st.get("Resource") == [arn] and "Condition" not in st:
                st["Action"] = sorted(set(st["Action"]) | actions)
                break
        else:
            statements.append({"Effect": "Allow", "Action": sorted(actions),
                               "Resource": [arn]})
    else:
        split = []
        for st in statements:
            if st.get("Effect") == "Allow" and arn in st.get("Resource", []):
                remaining = [r for r in st["Resource"] if r != arn]
                if remaining:
                    split.append(dict(st, Resource=remaining))
                kept = [a for a in st["Action"] if a not in actions]
                if kept:
                    split.append(dict(st, Resource=[arn], Action=kept))
            else:
                split.append(st)
        statements = split
    return dict(policy, Statement=statements)


def iam_api_tree(endpoint: str, access_key: str, secret_key: str, ctx=None) -> "_MemTree":
    """The same tree through the AWS-IAM-compatible query API (POST form, SigV4 service
    "iam") that SeaweedFS's gateway and AWS both answer — the portable path. Read actions
    only: ListUsers, ListGroupsForUser, ListUserPolicies/GetUserPolicy, ListGroups/GetGroup,
    ListAttachedGroupPolicies, GetPolicy/GetPolicyVersion. This API never returns secret
    keys, so a plane read this way observes fully but cannot probe (the probe says why)."""
    import xml.etree.ElementTree as ET

    from .sigv4 import sign
    url = endpoint.rstrip("/") + "/"
    def call(action: str, **params) -> ET.Element:
        body = urllib.parse.urlencode({"Action": action, "Version": "2010-05-08", **params}).encode()
        h = sign("POST", url, access_key, secret_key, body, service="iam",
                 extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
        req = urllib.request.Request(url, data=body, headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return ET.fromstring(r.read())
    def texts(root: ET.Element, tag: str) -> list[str]:
        return [e.text or "" for e in root.iter() if e.tag.rsplit("}", 1)[-1] == tag]
    def doc_of(text: str) -> dict:
        return json.loads(urllib.parse.unquote(text)) if text else {}
    tree = _MemTree()
    users = texts(call("ListUsers"), "UserName")
    for u in users:
        inline = {}
        for pname in texts(call("ListUserPolicies", UserName=u), "PolicyName"):
            inline[pname] = doc_of("".join(texts(call("GetUserPolicy", UserName=u, PolicyName=pname), "PolicyDocument")))
        tree.top.setdefault("inlinePolicies", {})[u] = inline
        tree.files["identities"][u] = {"name": u, "actions": [], "credentials": []}
    for g in texts(call("ListGroups"), "GroupName"):
        members = texts(call("GetGroup", GroupName=g), "UserName")
        attached = texts(call("ListAttachedGroupPolicies", GroupName=g), "PolicyName")
        tree.files["groups"][g] = {"name": g, "members": members, "policy_names": attached}
        for pname in attached:
            if pname in tree.files["policies"]:
                continue
            arn = f"arn:aws:iam:::policy/{pname}"
            ver = "".join(texts(call("GetPolicy", PolicyArn=arn), "DefaultVersionId")) or "v1"
            tree.files["policies"][pname] = doc_of("".join(texts(call("GetPolicyVersion", PolicyArn=arn, VersionId=ver), "Document")))
    return tree


class _MemTree:
    """merge_iam_tree's input when the tree was fetched over HTTP: {dir: {stem: doc}}
    plus the top-level policies.json. Same layout as the mirrored directory."""
    def __init__(self):
        self.top: dict = {}
        self.files: dict[str, dict] = {"identities": {}, "groups": {}, "policies": {}}


def merge_iam_tree(root) -> dict:
    """SeaweedFS filer `/etc/iam/` mirrored to a directory → one identities document
    in the shape `effective_grants` reads.

        identities/<name>.json   name, credentials, actions (native — a lossy projection)
        groups/<group>.json      members, policy_names
        policies.json            {"policies": {}, "inlinePolicies": {<name>: {<pname>: doc}}}
        policies/<pname>.json    managed policy documents (what groups attach)

    Enforcement (auth_credentials.go): an identity with *any* attached or inline policy
    is evaluated on policies only. So each identity's `policy` here is the union of its
    inline documents and every managed document its groups attach; an identity with none
    keeps only `actions`, which is then the enforced thing. Nothing is dropped silently —
    a group naming a policy file that does not exist becomes a finding downstream, not a
    quiet gap, because the merged statement list simply lacks it and `effective_grants`
    reports what it *did* see; the missing file is recorded in `_gaps`.
    """
    if isinstance(root, _MemTree):
        docs = root.files
        top = root.top
    else:
        root = Path(root)
        def load(p: Path):
            try:
                return json.loads(p.read_text())
            except Exception:
                return None
        docs = {d: {p.stem: load(p) for p in sorted((root / d).glob("*.json"))}
                for d in ("identities", "groups", "policies")}
        top = load(root / "policies.json") or {}
    pol_docs = dict(docs["policies"])
    inline = top.get("inlinePolicies", {}) or {}
    pol_docs.update({k: v for k, v in (top.get("policies") or {}).items() if k not in pol_docs})
    member_of: dict[str, list[str]] = {}
    group_pols: dict[str, list[str]] = {}
    for stem, g in sorted(docs["groups"].items()):
        g = g or {}
        group_pols[g.get("name", stem)] = list(g.get("policy_names", []))
        for m in g.get("members", []):
            member_of.setdefault(m, []).append(g.get("name", stem))
    gaps: list[str] = []
    gap_entities: dict[str, tuple[str, str]] = {}
    identities = []
    gap_subjects: set[str] = set()
    # Map-only structure: the grant set is flat on purpose (what is *enforced*), but
    # the route a person's access takes — identity → group → policy → bucket — is the
    # thing the map exists to show.
    kinds: dict[str, str] = {}
    routes: list[tuple[str, str, str]] = []
    for g, pnames in group_pols.items():
        kinds[f"group:{g}"] = "group"
        for pname in pnames:
            kinds[f"policy:{pname}"] = "policy"
            routes.append((f"group:{g}", f"policy:{pname}", "attaches"))
    for pname, doc in pol_docs.items():
        kinds[f"policy:{pname}"] = "policy"
        evaluated, _ = effective_grants({"identities": [{"name": pname, "policy": doc or {}}]})
        for grant in evaluated:
            routes.append((f"policy:{pname}", grant.resource, "allows"))
    for stem, ident in sorted(docs["identities"].items()):
        if not ident or not ident.get("name"):
            continue
        name = ident["name"]
        statements: list[dict] = []
        for pname, doc in (inline.get(name) or {}).items():
            statements += list((doc or {}).get("Statement", []))
        for g in member_of.get(name, []):
            for pname in group_pols.get(g, []):
                doc = pol_docs.get(pname)
                if doc is None:
                    gap_subjects.add(name)
                    gap = f"group '{g}' attaches policy '{pname}' which has no document"
                    gaps.append(gap)
                    gap_entities[gap] = (g, pname)
                    continue
                statements += list(doc.get("Statement", []))
        out = {"name": name, "actions": ident.get("actions", []),
               "credentials": ident.get("credentials", []), "groups": member_of.get(name, [])}
        if statements:
            out["policy"] = {"Version": "2012-10-17", "Statement": statements}
        identities.append(out)
        kinds[name] = "account"
        for g in member_of.get(name, []):
            routes.append((name, f"group:{g}", "member"))
        for pname in (inline.get(name) or {}):
            kinds[f"policy:{pname}"] = "policy"
            routes.append((name, f"policy:{pname}", "inline"))
            evaluated, _ = effective_grants({"identities": [
                {"name": pname, "policy": inline[name][pname] or {}}]})
            for grant in evaluated:
                routes.append((f"policy:{pname}", grant.resource, "allows"))
    return {"identities": identities, "_gaps": sorted(set(gaps)), "_gap_entities": gap_entities,
            "_gap_subjects": sorted(gap_subjects),
            "_kinds": kinds, "_routes": sorted(set(routes))}


class _Plane:
    """One auth plane: a JSON identities document behind a file or an HTTP
    endpoint (GET/PUT). Endpoint and credentials travel together — that is
    the point of per-plane config blocks.

    **Reading and writing take separate credentials (N1).** They did not: one
    `url_env` served the GET and the PUT, so any deployment that could read this
    plane could also write it, and "hand the console read-only credentials" was
    not a thing the config could express. PostgreSQL has `admin_dsn_env` and
    ClickHouse has `admin_url_env`; this is the same shape.

      url_env / auth_env              the observation credential — GET only
      admin_url_env / admin_auth_env  the write credential — PUT only

    `read()` resolves the first pair and `write()` the second, with **no fallback
    between them**: a missing `admin_url_env` means this plane does not write,
    never "so use the reader's key". A fallback would restore exactly the coupling
    this split exists to break, and it would do it silently.
    """

    def __init__(self, name: str, cfg: dict):
        self.name = name
        self.cfg = cfg
        self.file = Path(cfg["file"]) if cfg.get("file") else None
        # A SeaweedFS "advanced IAM" tree (filer /etc/iam/): identities, groups and
        # policies are *separate* documents. Reading identities alone shows native
        # actions the gateway ignores the moment a policy exists — bucket-wide Read
        # where the path gives a prefix. Caught by the N4 probe on the first run.
        self.dir = Path(cfg["dir"]) if cfg.get("dir") else None
        # The same tree read live from the filer (`filer_url_env`, e.g. http://filer:8888
        # or a port-forward). The adapter walks /etc/iam/ itself — no mirror on disk, and
        # the secrets it needs for probes never land in a file this tool controls (N6).
        self.filer_url_key = "filer_url_env" if cfg.get("filer_url_env") else None
        # The portable path: the AWS-IAM-compatible query API (SeaweedFS gateway, AWS).
        # iam_url_env + iam_key_env/iam_secret_env. Observes fully; cannot probe (no secrets).
        self.iam_url_key = "iam_url_env" if cfg.get("iam_url_env") else None

    def _request(self, url_key: str, auth_key: str, data: bytes | None = None):
        url = env(self.cfg, url_key)
        headers = {"Content-Type": "application/json"}
        # The bearer is optional: some endpoints authenticate through the URL itself.
        # Absent, the request goes without one — it does NOT borrow the other pair's.
        if self.cfg.get(auth_key):
            headers["Authorization"] = f"Bearer {env(self.cfg, auth_key)}"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="PUT" if data is not None else "GET")
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()

    def _filer_get(self, path: str, listing: bool = False) -> bytes:
        base = env(self.cfg, "filer_url_env").rstrip("/")
        headers = {"Accept": "application/json"} if listing else {}
        if self.cfg.get("filer_auth_env"):
            headers["Authorization"] = f"Bearer {env(self.cfg, 'filer_auth_env')}"
        req = urllib.request.Request(base + path, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()

    def _filer_tree(self) -> dict:
        """Walk the filer's /etc/iam/ over HTTP into the same shape merge_iam_tree reads."""
        def ls(d: str) -> list[str]:
            doc = json.loads(self._filer_get(f"/etc/iam/{d}/?limit=10000", listing=True) or b"{}")
            return [e["FullPath"].rsplit("/", 1)[1] for e in (doc.get("Entries") or [])
                    if e["FullPath"].endswith(".json")]
        def get(p: str):
            try:
                return json.loads(self._filer_get(p))
            except Exception:
                return None
        # 파일 하나에 왕복 하나다. 실측 70여 개(identities 24 · groups · policies)를
        # 순서대로 읽으면 3.25초 — 콘솔 콜드 스타트의 거의 전부가 여기였다. 서로
        # 독립이므로 동시에 읽는다. 상한 8은 filer 를 밀어붙이지 않으려는 값이다.
        from concurrent.futures import ThreadPoolExecutor

        tree = _MemTree()
        with ThreadPoolExecutor(max_workers=8) as pool:
            top = pool.submit(get, "/etc/iam/policies.json")
            listings = {d: pool.submit(ls, d) for d in ("identities", "groups", "policies")}
            fetched = {d: [(f, pool.submit(get, f"/etc/iam/{d}/{f}")) for f in listings[d].result()]
                       for d in listings}
            tree.top = top.result() or {}
            for d, items in fetched.items():
                for f, fut in items:
                    tree.files[d][f[:-5]] = fut.result()
        return merge_iam_tree(tree)

    def read(self) -> dict:
        if self.iam_url_key:
            import ssl
            ctx = ssl.create_default_context(cafile=os.environ.get(self.cfg.get("ca_bundle_env", ""), None) or None)
            return merge_iam_tree(iam_api_tree(env(self.cfg, "iam_url_env"), env(self.cfg, "iam_key_env"),
                                               env(self.cfg, "iam_secret_env"), ctx))
        if self.filer_url_key:
            return self._filer_tree()
        if self.dir:
            return merge_iam_tree(self.dir)
        if self.file:
            return json.loads(self.file.read_text())
        return json.loads(self._request("url_env", "auth_env"))

    def write_identity(self, ident: dict) -> None:
        """Write **one identity file** back to the filer tree — never the merged document.

        `read()` hands back a *merge*: an identity's `policy` there is the union of its
        inline documents and every managed document its groups attach. Writing that back
        anywhere would materialise inherited access as the identity's own, and the next
        reader could not tell the difference. So the only thing written is the identity's
        own file, with the only field this tool edits.

        `credentials` is carried over untouched from what is on the filer *now*, not from
        the merged view — the merge does not promise to round-trip secrets, and a write
        that drops an identity's keys locks a real user out.
        """
        base = env(self.cfg, "admin_filer_url_env").rstrip("/")
        if not re.fullmatch(r"[A-Za-z0-9_+=,.@-]+", ident["name"]) or ident["name"] in (".", ".."):
            raise ValueError("invalid identity name")
        path = f"/etc/iam/identities/{urllib.parse.quote(ident['name'], safe='')}.json"
        try:
            current = json.loads(self._filer_get(path))
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            current = {"name": ident["name"]}
        if not isinstance(current, dict) or current.get("name") != ident["name"]:
            raise ValueError("identity document does not match its name")
        current["actions"] = list(ident.get("actions", []))
        body = (json.dumps(current, indent=2) + "\n").encode()
        headers = {"Content-Type": "application/json"}
        token = self._filer_jwt()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(base + path, data=body, headers=headers, method="PUT")
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()

    def _filer_jwt(self) -> str | None:
        """SeaweedFS filer JWT for a write, minted per request.

        The filer leaves GET open and signs only mutations (`jwt.filer_signing` in
        security.toml). So the read path needs no credential and the write path needs
        this one — which is exactly the split `admin_filer_url_env` claims to make, and
        without it that claim was cosmetic: both names pointed at the same open endpoint.

        Hand-rolled because the whole token is three base64 segments and one HMAC, and
        the alternative is a dependency for that. The lifetime is short on purpose
        (`expires_after_seconds = 10` on the server side): a token that outlives the
        request it was minted for is a credential lying around.
        """
        if not self.cfg.get("admin_filer_jwt_env"):
            return None
        import base64
        import hashlib
        import hmac
        import time

        def seg(b: bytes) -> bytes:
            return base64.urlsafe_b64encode(b).rstrip(b"=")

        key = env(self.cfg, "admin_filer_jwt_env").encode()
        head = seg(b'{"alg":"HS256","typ":"JWT"}')
        claims = seg(json.dumps({"exp": int(time.time()) + 10}, separators=(",", ":")).encode())
        sig = seg(hmac.new(key, head + b"." + claims, hashlib.sha256).digest())
        return (head + b"." + claims + b"." + sig).decode()

    def write(self, doc: dict) -> None:
        if self.dir or self.filer_url_key or self.iam_url_key:
            raise SystemExit(f"plane '{self.name}' is an IAM tree — the merged document "
                             "is not writable; see write_identity()")
        body = json.dumps(doc, indent=2) + "\n"
        if self.file:
            self.file.write_text(body)
        else:
            self._request("admin_url_env", "admin_auth_env", body.encode())

    def write_ready(self) -> tuple[bool, str]:
        """Can this plane be written — decided without resolving anything (N1).

        A file-backed plane is judged by the filesystem, and deliberately so: there
        is no second credential to withhold, because the filesystem permission *is*
        the credential. An `admin_file` key would be the same path written twice, and
        a `writable = true` flag would be a claim the OS can contradict — a config
        saying "read-only" over a file this process can happily overwrite is worse
        than no claim at all. So a read-only deployment of a file plane is made the
        way the OS makes one: the file is not writable by this process, and the note
        below says exactly that.
        """
        if self.filer_url_key:
            # An IAM tree writes one identity file at a time (write_identity), and only
            # when the config names a *second* endpoint for it. Reading this tree needs
            # no credential in our deployment (a port-forward is the credential), so
            # without this split "can read" would silently mean "can write".
            return env_ready(self.cfg, "admin_filer_url_env")
        if self.dir or self.iam_url_key:
            return False, f"read-only here: plane '{self.name}' is an IAM tree (dir/iam api)."
        if self.file:
            return _file_ready(self.file, f"plane '{self.name}' file {self.file} "
                                          f"(the filesystem permission is the credential here)")
        return env_ready(self.cfg, "admin_url_env")


class S3ConfigAdapter(Adapter):
    system = "s3"
    privs = tuple(sorted(_NATIVE_VERBS))

    def __init__(self, cfg: dict, system: str = "s3"):
        self.system = system
        self.cfg = cfg
        self.planes = {name: _Plane(name, pcfg)
                       for name, pcfg in cfg.get("planes", {}).items()}
        self.enforced = cfg.get("enforced", "static")
        if self.enforced not in self.planes:
            raise SystemExit(f"s3: enforced plane '{self.enforced}' has no config block")

    # ── N4 probe ───────────────────────────────────────────────────────────
    # The one adapter where the probe is the real thing: the subject's own access key,
    # signed the way their client signs, against the endpoint their client uses. This is
    # the check that caught every S3 mistake so far (a policy not applied, a plane the
    # gateway ignores, a key from the other plane).
    #
    #   endpoint_env   the data endpoint (e.g. https://s3.example) — not the IAM URL
    #   ca_bundle_env  optional PEM for a private CA
    #
    # List → GET /bucket?max-keys=1&prefix=…   Read → HEAD the first listed key
    # Write (only with write=True) → PUT then DELETE a probe key under the scope;
    # a PUT that succeeds but cannot be deleted is reported, never hidden.
    def probe(self, grants, write: bool = False):
        import datetime
        import ssl
        import urllib.error

        from ..probe import Probe
        from .sigv4 import sign
        rows = sorted(grants, key=lambda g: (g.subject, g.resource, g.priv))
        endpoint = self.cfg.get("endpoint_env") and os.environ.get(self.cfg["endpoint_env"])
        if not endpoint:
            return [Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                          "no endpoint_env in config — nothing to probe against") for g in rows]
        try:
            doc = self._enforced_doc()
        except Exception as exc:
            return [Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                          f"enforced plane unreadable: {exc}") for g in rows]
        keys = {i["name"]: (c["access_key"], c["secret_key"])
                for i in doc.get("identities", []) for c in i.get("credentials", [])[:1]}
        ctx = ssl.create_default_context(cafile=os.environ.get(self.cfg.get("ca_bundle_env", ""), None) or None)

        def call(method, url, ak, sk, body=b""):
            req = urllib.request.Request(url, data=body or None, method=method,
                                         headers=sign(method, url, ak, sk, body))
            try:
                with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                return e.code, e.read()

        out: list[Probe] = []
        listed: dict[tuple[str, str], str | None] = {}  # (subject, scope) -> first key
        for g in rows:
            if not g.resource.startswith("bucket:") or g.priv not in ("List", "Read", "Write"):
                out.append(Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                                 f"no probe for {g.priv} on {g.resource.split(':')[0]}: resources")); continue
            if g.subject not in keys:
                out.append(Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                                 "identity has no access key in the enforced plane")); continue
            ak, sk = keys[g.subject]
            scope = g.resource.removeprefix("bucket:")
            if scope == "*":
                out.append(Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                                 "store-wide scope — pick a bucket to probe")); continue
            bucket, _, prefix = scope.partition("/")
            base = endpoint.rstrip("/")
            if g.priv == "List":
                q = urllib.parse.urlencode({"list-type": "2", "max-keys": "1", "prefix": prefix + ("/" if prefix else "")})
                st, body = call("GET", f"{base}/{bucket}?{q}", ak, sk)
                m = re.search(rb"<Key>([^<]+)</Key>", body) if st == 200 else None
                listed[(g.subject, scope)] = m.group(1).decode() if m else None
                out.append(Probe(g.system, g.subject, g.resource, g.priv,
                                 "allow" if st == 200 else "deny" if st == 403 else "unknown",
                                 f"GET /{bucket}?prefix={prefix}/ → HTTP {st}"))
            elif g.priv == "Read":
                key = listed.get((g.subject, scope))
                if key is None:  # list it ourselves (the List row may not exist for this subject)
                    q = urllib.parse.urlencode({"list-type": "2", "max-keys": "1", "prefix": prefix + ("/" if prefix else "")})
                    st, body = call("GET", f"{base}/{bucket}?{q}", ak, sk)
                    m = re.search(rb"<Key>([^<]+)</Key>", body) if st == 200 else None
                    key = m.group(1).decode() if m else None
                if not key:
                    out.append(Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                                     "no object under the scope to read (or cannot list it)")); continue
                st, _ = call("HEAD", f"{base}/{bucket}/{urllib.parse.quote(key)}", ak, sk)
                out.append(Probe(g.system, g.subject, g.resource, g.priv,
                                 "allow" if st == 200 else "deny" if st == 403 else "unknown",
                                 f"HEAD /{bucket}/{key} → HTTP {st}"))
            else:  # Write
                if not write:
                    out.append(Probe(g.system, g.subject, g.resource, g.priv, "unknown",
                                     "write probe leaves a mark — run with --write to try it")); continue
                key = f"{prefix + '/' if prefix else ''}_grantline-probe/{datetime.datetime.now(datetime.UTC):%Y%m%dT%H%M%SZ}-{g.subject}"
                st, _ = call("PUT", f"{base}/{bucket}/{urllib.parse.quote(key)}", ak, sk, b"grantline probe\n")
                how = f"PUT /{bucket}/{key} → HTTP {st}"
                if st == 200:
                    st2, _ = call("DELETE", f"{base}/{bucket}/{urllib.parse.quote(key)}", ak, sk)
                    how += f"; DELETE → HTTP {st2}" + ("" if st2 in (200, 204) else " — probe object LEFT BEHIND (no delete right)")
                out.append(Probe(g.system, g.subject, g.resource, g.priv,
                                 "allow" if st == 200 else "deny" if st == 403 else "unknown", how))
        return out

    def _enforced_doc(self) -> dict:
        # plan() asks once per change, and a tree source answers each ask with a full
        # walk over the network (dozens of GETs — minutes on a real filer). Reuse the
        # doc observe() just read: observe always runs first in the same request, so
        # it is exactly as fresh as the page being rendered.
        doc = getattr(self, "_observed_enforced", None)
        return doc if doc is not None else self.planes[self.enforced].read()

    def observe(self):
        docs: dict[str, dict | None] = {}
        findings: list[Finding] = []
        unobserved: list[Unobserved] = []
        self._observed_enforced = None
        for name, plane in self.planes.items():
            try:
                docs[name] = plane.read()
                if name == self.enforced:
                    self._observed_enforced = docs[name]
            except Exception as exc:
                docs[name] = None
                if name == self.enforced:
                    unobserved.append(Unobserved(
                        self.system, ("bucket:",),
                        f"enforced plane '{name}' unreachable: {exc}"))
                else:
                    findings.append(Finding(
                        self.system, "auth plane unreachable",
                        f"plane '{name}' could not be read ({exc}); cross-plane "
                        f"identity check skipped this run.",
                        entities=(name,),
                    ))

        grants: set[Grant] = set()
        self.kinds, self.routes = {}, []
        if docs.get(self.enforced) is not None:
            doc = docs[self.enforced]
            self.kinds = dict(doc.get("_kinds", {})) or {i["name"]: "account" for i in doc.get("identities", [])}
            self.routes = [(self.system, s, d, l) for s, d, l in doc.get("_routes", [])]
            grants, shadow = effective_grants(doc, self.system, unobserved=unobserved)
            findings += shadow
            gaps = doc.get("_gaps", [])
            for gap in gaps:
                findings.append(Finding(self.system, "policy document missing", gap,
                                        entities=tuple(doc.get("_gap_entities", {}).get(gap, ()))))
            if gaps:
                # Old/mirrored documents without affected identities remain system-wide unknown.
                unobserved.append(Unobserved(self.system, ("bucket:",), "policy documents missing",
                                             tuple(doc.get("_gap_subjects", ()))))
            grants = {g for g in grants if not any(u.covers(g) for u in unobserved)}
            blind = {name for u in unobserved for name in u.subjects}
            whole = any(not u.subjects for u in unobserved)
            # Keep healthy identities' routes; an unevaluated identity must not light up
            # policy paths. Flat grants alone are the evaluated result for those identities.
            self.routes = [] if whole else [r for r in self.routes if r[1] not in blind]

        # identities living in only one plane authenticate against only that
        # plane's endpoint — or nowhere, depending on which plane the gateway
        # consults. Either way it is drift worth naming.
        readable = {n: {i["name"] for i in d.get("identities", [])}
                    for n, d in docs.items() if d is not None}
        # ⚠ Only the *non-enforced* side is a problem. An identity that lives in the
        # enforced plane alone is the healthy, normal case — that plane is what the
        # gateway consults, so the identity authenticates. Flagging it produced one
        # finding per identity on a real cluster (20 of them) and buried everything
        # else. What actually breaks is an identity that exists ONLY where nobody
        # looks: its keys are configured somewhere, yet it authenticates nowhere,
        # and the failure surfaces as a misleading 403 rather than "unknown user".
        if len(readable) > 1 and self.enforced in readable:
            enforced_names = readable[self.enforced]
            for plane, names in readable.items():
                if plane == self.enforced:
                    continue
                orphans = sorted(names - enforced_names)
                if orphans:
                    findings.append(Finding(
                        self.system, "identity missing from the enforced plane",
                        f"{len(orphans)} identity(ies) exist in plane '{plane}' but not in "
                        f"the enforced plane '{self.enforced}': {', '.join(orphans[:8])}"
                        f"{' …' if len(orphans) > 8 else ''}. Their keys authenticate "
                        f"nowhere — the failure surfaces as a misleading "
                        f"403/SignatureDoesNotMatch, not 'unknown user'.",
                        entities=(plane, self.enforced, *orphans[:8]),
                    ))
        return grants, findings, unobserved

    def _cmd(self, g: Grant, add: bool) -> str:
        verb = "+=" if add else "-="
        action = f"{g.priv}:{g.resource.removeprefix('bucket:')}"
        try:
            ident = next((i for i in self._enforced_doc().get("identities", [])
                          if i["name"] == g.subject), None)
        except Exception:
            ident = None
        if ident and ident.get("policy"):
            old, new = ident["policy"], policy_with(ident["policy"], g, add)
            diff = "\n".join(difflib.unified_diff(
                json.dumps(old, indent=2).splitlines(),
                json.dumps(new, indent=2).splitlines(),
                fromfile=f"{g.subject}.policy (current)",
                tofile=f"{g.subject}.policy (planned)", lineterm=""))
            return (f"s3-iam[{self.enforced}]: PUT policy for identity '{g.subject}' "
                    f"(policy shadows native actions — the policy is what changes)\n{diff}")
        created = "" if ident else "  -- identity will be created; credentials out of band"
        return f"s3-iam[{self.enforced}]: identity '{g.subject}' actions {verb} '{action}'{created}"

    def coalesce(self, changes: list) -> list:
        """One PUT per identity, not one per grant.

        An identity's access is one document. Sixteen grants on `researcher_b` were sixteen
        plan lines, each with its own full diff, and `apply` wrote the same document
        sixteen times — each write re-reading what the previous one had just put.
        The result was correct and unreadable. Now the diff shows the document as it
        will be after all of them, and the write happens once.

        Identities with no policy keep their native actions edited one at a time:
        that path is a list append, not a document rewrite, and folding it would
        hide which action came from which grant.
        """
        from ..diff import Change
        doc_scoped: dict[tuple[str, str], list] = {}
        out: list = []
        for c in changes:
            ident = self._identity(c.grant.subject)
            if ident and ident.get("policy"):
                doc_scoped.setdefault((c.grant.subject, c.action), []).append(c)
            else:
                out.append(c)
        for (subject, action), cs in doc_scoped.items():
            grants = tuple(c.grant for c in cs)
            out.append(Change(action, cs[0].grant,
                              self._cmd_many(subject, grants, add=action == "grant"),
                              grants))
        return out

    def _identity(self, name: str):
        try:
            return next((i for i in self._enforced_doc().get("identities", [])
                         if i["name"] == name), None)
        except Exception:
            return None

    def _cmd_many(self, subject: str, grants: tuple, add: bool) -> str:
        """The command for several grants on one identity: the document, once."""
        ident = self._identity(subject)
        if not (ident and ident.get("policy")):
            return self._cmd(grants[0], add)
        old = ident["policy"]
        new = old
        for g in grants:
            new = policy_with(new, g, add)
        diff = "\n".join(difflib.unified_diff(
            json.dumps(old, indent=2).splitlines(),
            json.dumps(new, indent=2).splitlines(),
            fromfile=f"{subject}.policy (current)",
            tofile=f"{subject}.policy (planned)", lineterm=""))
        what = ", ".join(f"{g.priv} on {g.resource.removeprefix('bucket:')}" for g in grants[:4])
        more = f" +{len(grants) - 4}" if len(grants) > 4 else ""
        return (f"s3-iam[{self.enforced}]: PUT policy for identity '{subject}' — "
                f"{len(grants)} grant(s): {what}{more}\n{diff}")

    def grant_cmd(self, g: Grant) -> str:
        return self._cmd(g, add=True)

    def revoke_cmd(self, g: Grant) -> str:
        return self._cmd(g, add=False)

    def write_ready(self):
        # Only the enforced plane is ever written: the other plane is read to compare
        # identities, and writing it would change nothing the gateway consults.
        #
        # Note which plane's *write* credential this asks about. Observation reads
        # every plane with its own `url_env`; that a plane was read says nothing about
        # whether this tool may change it, and until `admin_url_env` existed it said
        # exactly that — reading implied writing.
        return self.planes[self.enforced].write_ready()

    def apply(self, change):
        add = change.action == "grant"
        # coalesce() 가 묶었으면 여러 개, 아니면 하나. 테스트 더블처럼 Change 가 아닌
        # 것이 와도 grant 하나로 동작한다.
        grants = getattr(change, "all_grants", None) or (change.grant,)
        subject = grants[0].subject
        plane = self.planes[self.enforced]
        doc = plane.read()  # re-read: apply against current state, not the plan's snapshot
        ident = next((i for i in doc.setdefault("identities", [])
                      if i["name"] == subject), None)
        if ident is None:
            ident = {"name": subject, "actions": []}
            doc["identities"].append(ident)
        for g in grants:
            if ident.get("policy"):
                ident["policy"] = policy_with(ident["policy"], g, add)
            else:
                action = f"{g.priv}:{g.resource.removeprefix('bucket:')}"
                actions = [a for a in ident.get("actions", []) if a != action]
                if add:
                    actions.append(action)
                ident["actions"] = actions
        if plane.filer_url_key:
            # ⚠ 정책을 든 신원은 여기서 쓰지 않는다. SeaweedFS 는 정책이 하나라도
            # 있으면 native actions 를 무시하므로 actions 를 고쳐야 아무 일도 안
            # 일어나고, 정작 바꿔야 할 정책 문서는 **그룹이 공유한다** — 한 사람의
            # grant 로 쓰면 같은 그룹 전원의 접근이 함께 바뀐다. 조용히 하면 안 되는
            # 일이라 거부한다.
            if ident.get("policy"):
                raise SystemExit(
                    f"identity '{subject}' is evaluated on policies, not native actions "
                    f"(SeaweedFS ignores `actions` once any policy attaches). The document "
                    f"to change is a group's managed policy, which every member shares — "
                    f"this tool will not rewrite it from one subject's grant. Change "
                    f"that document with whatever owns it.")
            plane.write_identity(ident)
        else:
            plane.write(doc)
