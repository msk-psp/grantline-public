"""F3 — one grant or revoke, named by the operator, previewed before it runs.

Two rules shape this module, and both of them are about what it refuses to do.

**N2: the preview is the command.** `propose()` builds the native command once,
from the adapter, and `execute()` runs *that string* — it does not rebuild a
"similar" one. The console posts the previewed command back and it must still
match what the adapter would emit now; if the server moved underneath the
preview, the write is refused rather than quietly applied to a different world.

**N1: reading never resolves a write credential.** Whether the run button is
alive is answered by `Adapter.write_ready()`, which only asks whether the config
names a credential and whether that environment variable exists. The value is
resolved inside `apply()`, at the moment of the write, and nowhere else.

Nothing here iterates: one subject, one resource, one privilege per call. F3's
"bounded by construction" is not a policy that has to be enforced downstream if
the only shape available is a single atom.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import audit
from .diff import Change
from .model import Grant
from .subsume import satisfied_by


class ActError(Exception):
    """Something the operator should read: what failed, and why. Never a trace."""


@dataclass
class Proposal:
    action: str            # grant | revoke
    grant: Grant
    cmd: str               # the native command — previewed and, if run, executed
    ready: bool            # a write credential is configured for this system
    ready_note: str        # why it is (or is not) — names the env var, never its value
    blocked: str = ""      # non-empty: this must not run, and here is why
    note: str = ""         # worth reading, but not a reason to stop


def _adapter(adapters: dict, system: str):
    if system not in adapters:
        known = ", ".join(sorted(adapters)) or "none"
        raise ActError(f"no adapter is configured for system '{system}' "
                       f"(configured: {known}) — nothing here can speak to it.")
    return adapters[system]


def propose(action: str, system: str, subject: str, resource: str, priv: str,
            observed: set[Grant], adapters: dict) -> Proposal:
    """The command that *would* run, plus everything that argues against running it."""
    if action not in ("grant", "revoke"):
        raise ActError(f"unknown action '{action}' — this tool grants or revokes.")
    missing = [n for n, v in (("subject", subject), ("resource", resource), ("privilege", priv))
               if not (v or "").strip()]
    if missing:
        raise ActError("fill in " + ", ".join(missing) + " — a write names all three.")

    adapter = _adapter(adapters, system)
    g = Grant(system, subject.strip(), resource.strip(), priv.strip())
    try:
        cmd = adapter.grant_cmd(g) if action == "grant" else adapter.revoke_cmd(g)
    except Exception as exc:
        # A resource kind the service has no statement for (`global:*` on PostgreSQL,
        # `capability:` on S3). Saying so beats emitting prose that cannot be run (N3).
        raise ActError(f"{system} has no {action} statement for resource "
                       f"'{g.resource}': {exc}") from None

    ready, ready_note = adapter.write_ready()
    blocked = adapter.refuse_write(g, action)
    note = ""
    if blocked:
        pass          # 이미 막혔다. 아래 판정들은 "왜 무의미한가" 를 덧쓸 뿐이다.
    elif action == "grant":
        if g in observed:
            blocked = (f"{subject} already holds {g.priv} on {g.resource} in {system}. "
                       f"Running this changes nothing.")
        else:
            wider = satisfied_by(g, observed)
            if wider is not None:
                # N5. The command would succeed and mean nothing — the held grant is
                # already broader. Emitting it would add a line to the audit log that
                # tells a later reader a lie about what changed.
                blocked = (f"already covered: {subject} holds {wider.priv} on "
                           f"{wider.resource}, which reaches {g.resource} in {system}. "
                           f"Granting the narrower privilege changes no access — "
                           f"revoke the broader grant if that is what you meant.")
    elif action == "revoke" and g not in observed:
        note = (f"{subject} was not observed holding {g.priv} on {g.resource}. "
                f"It may sit in a scope this observer cannot read, so the revoke is "
                f"still offered — but it may well be a no-op.")

    return Proposal(action, g, cmd, ready, ready_note, blocked, note)


def execute(prop: Proposal, adapters: dict, audit_path: str | None,
            expect_cmd: str | None = None) -> None:
    """Run the previewed command. Raises ActError with a readable reason on refusal."""
    if expect_cmd is not None and expect_cmd != prop.cmd:
        # The console posts back the command it displayed. If the adapter would now
        # emit a different one — an S3 policy edited elsewhere between preview and
        # click, say — then what was approved is not what would run.
        raise ActError(
            "the command changed between the preview and this click, so nothing ran.\n"
            f"you approved:  {expect_cmd}\n"
            f"it would now be:  {prop.cmd}\n"
            "Something else changed the system in between. Review it again.")
    if prop.blocked:
        raise ActError(prop.blocked)
    if not prop.ready:
        raise ActError(prop.ready_note)
    if not audit_path:
        raise ActError("no audit_log is configured, so this write could not be "
                       "recorded. An unrecorded change is the one nobody can answer "
                       "for later; set `audit_log` in the config first.")
    adapter = _adapter(adapters, prop.grant.system)
    err = audit.record(audit_path, prop.grant.system, prop.action, prop.cmd,
                       lambda: adapter.apply(Change(prop.action, prop.grant, prop.cmd)))
    if err:
        raise ActError(f"{prop.grant.system} refused the command: {err}")
