"""Public fixtures must not leak real identities, including intermediate commits."""
import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

gate_path = Path(__file__).resolve().parents[1] / "scripts" / "privacy_gate.py"
spec = importlib.util.spec_from_file_location("privacy_gate", gate_path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

signals = {
    "slack-user-id": "U" + "12345678AB",
    "email": "person" + "@mail.invalid",
    "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "credential-token": "ghp_" + "a" * 30,
    "internal-host": "service" + ".internal",
    "private-ip": "192" + ".168.2.4",
    "personal-home-path": "/Users/" + "someone/repo",
}
for category, signal in signals.items():
    assert (category, 1) in gate.scan_text("fixture.txt", signal), category

safe = "alice@example.com bob@example.org U_REVIEWER @demo-reviewer localhost 127.0.0.1"
assert not gate.scan_text("fixture.txt", safe)
assert not gate.scan_text("fixture.txt", "123+demo@users.noreply.github.com")
assert not gate.scan_text("fixture.txt", "Co-Authored-By: Codex <noreply@openai.com>")
vector = "AKIA" + "IOSFODNN7EXAMPLE"
assert not gate.scan_text("tests/test_n4_probe.py", vector)
assert gate.scan_text("tests/arbitrary.py", vector), "only the published vector fixture is exempt"


def run(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True).stdout.decode().strip()


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    run(root, "init", "-q")
    run(root, "config", "user.name", "Demo Contributor")
    run(root, "config", "user.email", "demo@users.noreply.github.com")
    (root / "scripts").mkdir()
    shutil.copyfile(gate_path, root / "scripts" / "privacy_gate.py")
    path = root / "fixture.txt"
    path.write_text(safe)
    run(root, "add", "fixture.txt")
    run(root, "commit", "-qm", "safe baseline")
    base = run(root, "rev-parse", "HEAD")
    # A clean worktree cannot conceal a staged leak, nor vice versa.
    path.write_text(signals["slack-user-id"])
    run(root, "add", "fixture.txt")
    path.write_text(safe)
    diagnostics = gate.inspect(root, "staged")
    assert any("slack-user-id" in item for item in diagnostics)
    assert all(signals["slack-user-id"] not in item for item in diagnostics)
    hook = gate_path.parents[1] / ".githooks" / "pre-commit"
    assert subprocess.run([str(hook)], cwd=root, capture_output=True).returncode == 1
    run(root, "add", "fixture.txt")
    path.write_text(signals["email"])
    assert not gate.inspect(root, "staged"), "unstaged values are not being published yet"
    path.write_text(safe)
    leaked = root / "removed.txt"
    leaked.write_text(signals["credential-token"])
    run(root, "add", "removed.txt")
    run(root, "commit", "-qm", "intermediate fixture")
    run(root, "rm", "-q", "removed.txt")
    run(root, "commit", "-qm", "remove fixture")
    head = run(root, "rev-parse", "HEAD")
    diagnostics = gate.inspect(root, "range", base, head)
    assert any("credential-token" in item for item in diagnostics), "add/delete must not hide a leak"
    assert all(signals["credential-token"] not in item for item in diagnostics)
    # Raw commit metadata is inspected without printing the personal email.
    run(root, "config", "user.email", signals["email"])
    run(root, "commit", "--allow-empty", "-qm", "metadata fixture")
    metadata_head = run(root, "rev-parse", "HEAD")
    diagnostics = gate.inspect(root, "range", head, metadata_head)
    assert len(diagnostics) == 2 and all("commit-email" in item for item in diagnostics)
    assert all(signals["email"] not in item for item in diagnostics)
    assert gate.inspect(root, "staged") == ["commit-email: staged (author)", "commit-email: staged (committer)"]
    # The baseline's old metadata is not rechecked in a later safe range.
    run(root, "config", "user.email", "demo@users.noreply.github.com")
    run(root, "commit", "--allow-empty", "-qm", "safe metadata")
    clean_head = run(root, "rev-parse", "HEAD")
    assert not gate.inspect(root, "range", metadata_head, clean_head)
    run(root, "update-ref", "refs/remotes/origin/latest-feature", metadata_head)
    assert not gate.inspect(root, "unpushed", head=clean_head)
    push_hook = gate_path.parents[1] / ".githooks" / "pre-push"
    update = f"refs/heads/demo {clean_head} refs/heads/demo {'0' * 40}\n"
    assert subprocess.run([str(push_hook)], cwd=root, input=update, text=True, capture_output=True).returncode == 0
    run(root, "commit", "--allow-empty", "-qm", signals["slack-user-id"])
    message_head = run(root, "rev-parse", "HEAD")
    diagnostics = gate.inspect(root, "range", clean_head, message_head)
    assert len(diagnostics) == 1 and "commit-message-slack-user-id" in diagnostics[0]
    assert signals["slack-user-id"] not in diagnostics[0]
    result = subprocess.run(["python3", str(gate_path), "--root", str(root), "--range", base, metadata_head], capture_output=True, text=True)
    assert result.returncode == 1
    assert "credential-token" in result.stdout and "commit-email" in result.stdout
    assert all(value not in result.stdout + result.stderr for value in signals.values())
    invalid = subprocess.run(["python3", str(gate_path), "--root", str(root), "--range", "missing-input", message_head], capture_output=True, text=True)
    assert invalid.returncode == 2 and "missing-input" not in invalid.stdout + invalid.stderr

print("privacy gate: patterns, redaction, index snapshots and commit ranges passed")
