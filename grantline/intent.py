"""Load declared intent (TOML) into the normalized Grant set."""
from __future__ import annotations

import tomllib
from pathlib import Path

from .model import Grant


class Intent:
    def __init__(self, grants: set[Grant], managed: set[str], naming_synonyms: list[list[str]],
                 managed_systems: set[str] | None = None):
        self.grants = grants
        self.managed = managed          # subjects the tool may revoke from
        # systems the intent claims to describe *completely*. Without this, a system
        # a subject was never declared in is reported, not revoked (see diff.py).
        self.managed_systems = managed_systems or set()
        self.naming_synonyms = naming_synonyms

    def for_system(self, system: str) -> set[Grant]:
        return {g for g in self.grants if g.system == system}


# suffix groups that mean the same thing; two of them on one stem = naming drift
DEFAULT_SYNONYMS = [
    ["read", "reader", "readonly", "ro", "researcher", "viewer"],
    ["write", "writer", "rw", "maintainer", "editor"],
]


def load(path: str | Path) -> Intent:
    data = tomllib.loads(Path(path).read_text())
    # Canonicalise on the way in: a declaration written `bucket:x/y/*` and an observed
    # grant read back as `bucket:x/y` are the same scope, and the diff must not treat
    # spelling as difference.
    grants = {
        Grant(system=g["system"], subject=g["subject"],
              resource=g["resource"], priv=p)
        for g in data.get("grants", [])
        for p in g["privs"]
    }
    return Intent(
        grants=grants,
        managed=set(data.get("managed_subjects", [])),
        naming_synonyms=data.get("naming", {}).get("synonyms", DEFAULT_SYNONYMS),
        managed_systems=set(data.get("managed_systems", [])),
    )
