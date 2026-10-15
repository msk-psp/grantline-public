#!/usr/bin/env python3
"""Public-source privacy checks; diagnostics never include matched values.

Scan index blobs, not working-tree files. A range scans each commit's changed
blobs and author/committer metadata, so adding then deleting a leak still fails.
This is a focused guardrail, not a complete secret or personal-data classifier.
"""
import argparse
import re
import subprocess
from pathlib import Path

RULES = {
    "slack-user-id": re.compile(r"\b[UW](?=[A-Z0-9]{8,12}\b)(?=[A-Z0-9]*\d)[A-Z0-9]{8,12}\b"),
    "email": re.compile(r"[\w.%+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}"),
    "private-key": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "credential-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[A-Z0-9]{16})\b"),
    "internal-host": re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|local|lan)\b(?![.\w*-])"),
    "private-ip": re.compile(r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![\d.])"),
    "personal-home-path": re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+(?:/|\b)"),
}

# Exact published SigV4 test vector, allowed only in its existing regression.
AWS_VECTOR_PATH = "tests/test_n4_probe.py"
AWS_VECTOR = "AKIA" + "IOSFODNN7EXAMPLE"
DEMO_HOME_NAMES = {"user", "alice", "bob", "jovyan"}


def safe_email(value):
    domain = value.rsplit("@", 1)[-1].lower()
    return value.lower() in {"noreply@openai.com", "noreply@anthropic.com", "noreply@github.com"} or domain in {"example.com", "example.org", "example.net", "noreply.github.com"} or domain.endswith((".example", ".users.noreply.github.com")) or domain == "users.noreply.github.com"


def safe_commit_email(email):
    email = email.lower()
    # GitHub web-flow uses this exact address for web-created merge commits.
    return email == "noreply@github.com" or email.endswith(("@users.noreply.github.com", "@noreply.github.com"))


def scan_text(path, text):
    """Return category/line only; no match or source text leaves this function."""
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        for category, pattern in RULES.items():
            for match in pattern.finditer(line):
                value = match.group()
                if category == "email" and safe_email(value):
                    continue
                if category == "credential-token" and path == AWS_VECTOR_PATH and value == AWS_VECTOR:
                    continue
                if category == "personal-home-path" and value.strip("/").split("/")[1] in DEMO_HOME_NAMES:
                    continue
                findings.append((category, number))
                break
    return findings


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True).stdout


def scan_blob(root, revision, path):
    blob = git(root, "show", f"{revision}:{path}")
    # Binary assets need separate visual review, not lossy text decoding.
    if b"\x00" in blob:
        return []
    return scan_text(path, blob.decode("utf-8", errors="replace"))


def inspect(root, mode, base=None, head=None):
    """Diagnostics contain only rule, path, line and (when applicable) commit."""
    findings = []
    if mode in {"staged", "tracked"}:
        if mode == "staged":
            paths = git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split(b"\x00")
        else:
            paths = git(root, "ls-files", "-z").split(b"\x00")
        for raw in paths:
            if raw:
                path = raw.decode("utf-8", errors="surrogateescape")
                findings.extend(f"{category}: {path!r}:{line}" for category, line in scan_blob(root, "", path))
        if mode == "staged":
            for role in ("AUTHOR", "COMMITTER"):
                identity = git(root, "var", f"GIT_{role}_IDENT").decode()
                email = identity.rsplit("<", 1)[-1].split(">", 1)[0]
                if not safe_commit_email(email):
                    findings.append(f"commit-email: staged ({role.lower()})")
        return findings
    # Resolve to immutable hashes before using input in rev-list; no option injection.
    base_sha = git(root, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}").decode().strip() if base else None
    head_sha = git(root, "rev-parse", "--verify", "--end-of-options", f"{head}^{{commit}}").decode().strip()
    revisions = f"{base_sha}..{head_sha}" if base_sha else head_sha
    commits = git(root, "rev-list", head_sha, "--not", "--remotes=origin") if mode == "unpushed" else git(root, "rev-list", revisions)
    for commit in commits.decode().splitlines():
        emails = git(root, "show", "-s", "--format=%ae%n%ce", commit).decode().splitlines()
        for role, email in zip(("author", "committer"), emails):
            if not safe_commit_email(email):
                findings.append(f"commit-email: {commit} ({role})")
        message = git(root, "show", "-s", "--format=%B", commit).decode("utf-8", errors="replace")
        findings.extend(f"commit-message-{category}: {commit}:{line}" for category, line in scan_text("commit-message", message))
        paths = set(git(root, "diff-tree", "--root", "-r", "-m", "--no-commit-id", "--name-only", "--diff-filter=ACMR", "-z", commit).split(b"\x00"))
        for raw in sorted(paths):
            if raw:
                path = raw.decode("utf-8", errors="surrogateescape")
                findings.extend(f"{category}: {path!r}:{line} commit={commit}" for category, line in scan_blob(root, commit, path))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--staged", action="store_true")
    modes.add_argument("--tracked", action="store_true")
    modes.add_argument("--range", nargs=2, metavar=("BASE", "HEAD"))
    modes.add_argument("--initial", metavar="HEAD", help="scan all history for a first push without a base")
    modes.add_argument("--unpushed", metavar="HEAD", help="new-branch commits not already reachable from origin refs")
    args = parser.parse_args()
    try:
        mode = "staged" if args.staged else "tracked" if args.tracked else "unpushed" if args.unpushed else "range"
        base, head = args.range if args.range else (None, args.initial or args.unpushed)
        findings = inspect(args.root, mode, base, head)
    except (subprocess.CalledProcessError, OSError):
        parser.exit(2, "privacy gate could not read Git inputs; no sensitive output was printed\n")
    for finding in findings:
        print(finding)
    if findings:
        print("privacy gate blocked publication; replace real identifiers with fictional fixtures")
        return 1
    print("privacy gate passed (text patterns only; review binary assets separately)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
