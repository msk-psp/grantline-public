"""One line per attempted write, whoever issued it.

The CLI and the console must leave the *same* record — a steward reading
`audit.jsonl` should not have to know which surface a change came from, and a
second format would be a second thing to keep in sync. So the entry is built in
exactly one place, and both callers hand it the command they are about to run.

Failures are recorded too. A write that raised is the most interesting line in
the file, and dropping it would leave the log claiming a quiet afternoon.
"""
from __future__ import annotations

import datetime
import getpass
import json
import os


def record(path: str, system: str, action: str, cmd: str, run) -> str | None:
    """Execute `run()`, append the audit line, and return an error message or None.

    The message is for a human — the caller renders it, never a traceback (F6).
    """
    entry = {"ts": datetime.datetime.now(datetime.UTC).isoformat(),
             "user": getpass.getuser(), "system": system,
             "action": action, "cmd": cmd}
    err = None
    try:
        with open(path, "a", opener=lambda p, flags: os.open(p, flags, 0o600)) as log:
            # Persist the attempt before touching the service, including disk errors.
            log.write(json.dumps(dict(entry, phase="attempt")) + "\n")
            log.flush()
            try:
                run()
                entry["ok"] = True
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
                entry.update(ok=False, error=str(exc))
            log.write(json.dumps(entry) + "\n")
            log.flush()
    except OSError as exc:
        return f"audit failed: {exc}"
    return err
