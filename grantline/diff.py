"""Convergence engine: intent set vs observed set -> explicit grant/revoke plan.

Permissions are additive. Removing a line from the intent file does NOT remove
the permission on the server — so the plan must *enumerate revokes by name*.
That is the whole point of this module: extra = observed - intent, and every
extra held by a managed subject becomes a named REVOKE.
"""
from __future__ import annotations

from dataclasses import dataclass

from .intent import Intent
from .model import Finding, Grant, Unobserved, kind_of, level
from .subsume import covers as _subsumes


@dataclass
class Change:
    action: str  # "grant" | "revoke"
    grant: Grant
    cmd: str
    # 한 명령이 여러 grant 를 한꺼번에 처리할 때 그 grant 들. 비어 있으면 [grant] 하나다.
    # S3 처럼 문서 하나를 통째로 PUT 하는 시스템에서, 같은 신원의 grant 16개가 16번의
    # PUT 으로 보이던 것을 한 번으로 묶는다 (실측: 285개 항목 → 실제 명령 39개).
    grants: tuple = ()

    @property
    def all_grants(self) -> tuple:
        return self.grants or (self.grant,)


def plan(intent: Intent, observed: set[Grant], adapters: dict,
         unobserved: list[Unobserved] = (),
         ) -> tuple[list[Change], list[Finding], list[Grant]]:
    """-> (changes, findings, unverified intent grants).

    Grants inside an unobserved scope are excluded from the diff in BOTH
    directions: we cannot know they are missing (spurious GRANTs) nor that
    anything extra exists there (revokes cannot be enumerated). They come
    back as `unverified` so the UI shows '?' instead of pretending."""
    changes: list[Change] = []
    findings: list[Finding] = []

    def blind(g: Grant) -> bool:
        return any(u.covers(g) for u in unobserved)

    unverified = sorted((g for g in intent.grants if blind(g)), key=_key)
    visible_intent = intent.grants - set(unverified)
    visible_observed = {g for g in observed if not blind(g)}
    for u in unobserved:
        n = sum(1 for g in unverified if u.covers(g))
        findings.append(Finding(
            u.system, "unobserved scope",
            f"{', '.join(u.subjects) + ': ' if u.subjects else ''}{', '.join(u.prefixes)} could not be read ({u.note}). "
            f"{n} intent grant(s) there are unverified — shown as '?', not planned. "
            f"'no access' and 'could not check' are different facts.",
            entities=(*u.subjects, *u.prefixes),
        ))

    missing = visible_intent - visible_observed
    extra = visible_observed - visible_intent

    # N5. A grant the subject already holds more broadly is not missing — planning it
    # would emit a command that changes nothing. Index by (system, subject) first: the
    # check is per-subject by definition, and scanning all observed grants for every
    # declared one is quadratic on a real deployment.
    by_subject: dict[tuple[str, str], list[Grant]] = {}
    for g in visible_observed:
        by_subject.setdefault((g.system, g.subject), []).append(g)

    for g in sorted(missing, key=_key):
        wider = next((h for h in by_subject.get((g.system, g.subject), ())
                      if _subsumes(h, g)), None)
        if wider is not None:
            # Suppressed, not silent (F4): the steward asked for one thing and holds
            # something larger, and that difference is worth seeing even though no
            # command is needed.
            findings.append(Finding(
                g.system, "already covered by a broader grant",
                f"{g.subject}: {g.priv} on {g.resource} is declared, and "
                f"{wider.priv} on {wider.resource} already covers it. No grant planned; "
                f"the held privilege is wider than the declared one.",
                entities=(g.subject, g.priv, g.resource, wider.priv, wider.resource),
            ))
            continue
        changes.append(Change("grant", g, adapters[g.system].grant_cmd(g)))

    # A revoke needs a mandate for the *system*, not just the subject. Declaring a
    # subject's S3 grants does not license revoking its PostgreSQL grants — "this file
    # says nothing about postgres" and "postgres should be empty" are different
    # statements, and only the second is a mandate.
    #
    # Observed on a real deployment: an intent declaring S3 for 11 people planned 61
    # PostgreSQL revokes for those same people, whose PG roles are managed elsewhere.
    #
    # A system counts as described once the intent declares anything in it — writing the
    # postgres section is the normal way to say "I am describing postgres". For the
    # deliberately-empty case ("PUBLIC must hold nothing"), name the system in
    # `managed_systems`; silence alone must not delete.
    described = {g.system for g in intent.grants} | intent.managed_systems

    # 관리 대상이 아닌 주체가 가진 것 — grant 하나마다 한 줄을 내면 실환경에서
    # 6,600줄이 되고, 그 안에 진짜 발견(삭제된 DB 에 남은 권한 4건)이 묻힌다.
    # 이건 "발견" 이 아니라 "이 도구가 소유를 주장하지 않는 범위" 라는 상태다.
    # 주체별로 한 줄로 접고, 무엇을 가졌는지는 그 주체의 페이지가 이미 보여준다.
    unmanaged: dict[tuple[str, str], list[Grant]] = {}
    undeclared: dict[tuple[str, str], list[Grant]] = {}   # 같은 이유로 접는다

    for g in sorted(extra, key=_key):
        if g.subject not in intent.managed:
            unmanaged.setdefault((g.system, g.subject), []).append(g)
        elif g.system in described:
            changes.append(Change("revoke", g, adapters[g.system].revoke_cmd(g)))
        else:
            undeclared.setdefault((g.system, g.subject), []).append(g)

    findings += _lint_default_privs(intent, observed)
    findings += _lint_naming(intent, observed)
    def _where(gs: list[Grant]) -> str:
        res = sorted({g.resource for g in gs})
        return ", ".join(res[:3]) + (f" (+{len(res) - 3} more)" if len(res) > 3 else "")

    for (system, subject), gs in sorted(undeclared.items()):
        findings.append(Finding(
            system, "undeclared system for a managed subject",
            f"{subject} holds {len(gs)} grant(s) up to {level({g.priv for g in gs})} on "
            f"{_where(gs)} in '{system}', but the intent declares nothing for them there. "
            f"Silence is not a mandate to revoke — declare it, or list '{system}' in "
            f"managed_systems to say the system is fully described.",
            entities=(subject, system, level({g.priv for g in gs}), *sorted({g.resource for g in gs})[:3]),
        ))

    for (system, subject), gs in sorted(unmanaged.items()):
        findings.append(Finding(
            system, "unmanaged drift",
            f"{subject} holds {len(gs)} grant(s) up to {level({g.priv for g in gs})} on "
            f"{_where(gs)}; the "
            f"subject is not in managed_subjects so nothing is planned. Add it to manage "
            f"it, or accept that this tool does not speak for it.",
            entities=(subject, level({g.priv for g in gs}), *sorted({g.resource for g in gs})[:3]),
        ))

    # 어댑터가 여러 grant 를 한 명령으로 처리할 수 있으면 여기서 묶는다. 묶지 않으면
    # 계획이 실제 작업량을 과장하고(같은 문서를 N번 쓰는 것처럼 보인다), apply 도
    # 같은 문서를 N번 왕복한다.
    merged: list[Change] = []
    by_system: dict[str, list[Change]] = {}
    for c in changes:
        by_system.setdefault(c.grant.system, []).append(c)
    for system, cs in by_system.items():
        fn = getattr(adapters.get(system), "coalesce", None)
        merged += list(fn(cs)) if fn else cs
    return merged, findings, unverified


def _key(g: Grant):
    return (g.system, g.subject, g.resource, g.priv)


def _lint_default_privs(intent: Intent, observed: set[Grant]) -> list[Finding]:
    """ALTER DEFAULT PRIVILEGES binds to the role that *creates* objects.
    Declaring it for a group role does nothing: members own what they create.
    Symptom appears late ("only new tables are invisible"), so lint it now."""
    out = []
    group_roles = {g.resource.removeprefix("role:")
                   for g in intent.grants | observed
                   if g.resource.startswith("role:") and g.priv == "MEMBER"}
    for g in intent.grants:
        if kind_of(g.system) == "postgres" and g.resource.startswith("default:") and "@" in g.resource:
            creator = g.resource.rsplit("@", 1)[1]
            if creator in group_roles:
                out.append(Finding(
                    "postgres", "default privileges on a group role",
                    f"{g.resource}: creator role '{creator}' has members, so its members' "
                    f"objects are NOT covered (owner is the member, not the group). "
                    f"Declare default privileges per creating role instead.",
                    entities=(g.resource, creator),
                ))
    return out


def _lint_naming(intent: Intent, observed: set[Grant]) -> list[Finding]:
    """Same concept, different suffix across systems ('x_reader' vs 'x_researcher')
    makes auditing impossible. Flag stems that use >1 suffix from one synonym group."""
    roles: dict[str, set[str]] = {}  # stem -> suffixes seen
    for g in intent.grants | observed:
        if g.resource.startswith("role:") and "_" in g.resource:
            stem, _, suffix = g.resource.removeprefix("role:").rpartition("_")
            roles.setdefault(stem, set()).add(suffix)
    out = []
    for stem, suffixes in sorted(roles.items()):
        for group in intent.naming_synonyms:
            hit = suffixes & set(group)
            if len(hit) > 1:
                out.append(Finding(
                    "*", "naming drift",
                    f"role stem '{stem}' uses synonymous suffixes {sorted(hit)} — "
                    f"same concept, two names. Pick one and rename the other.",
                    entities=(stem, *sorted(hit)),
                ))
    return out
