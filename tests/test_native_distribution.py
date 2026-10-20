"""The native distribution must not regain a Python service or ship its oracle."""
import subprocess
import sys
import tomllib
from pathlib import Path

root = Path(__file__).resolve().parents[1]
assert not list((root / "grantline").rglob("*.py")), "retired application returned"
metadata = tomllib.loads((root / "pyproject.toml").read_text())
assert "project" not in metadata and "build-system" not in metadata
assert (root / "Dockerfile.rust").resolve() == (root / "Dockerfile").resolve()
assert 'COPY tests' not in (root / "Dockerfile").read_text()
assert '!tests/' not in (root / ".dockerignore").read_text()
assert not (root / "tests/reference/grantline/cli.py").exists()
assert not (root / "tests/reference/grantline/web.py").exists()
# An explicit test import is required; even a present environment credential is refused.
script = """import os, sys
sys.path.insert(0, 'tests/reference')
from grantline.adapters import env
os.environ['FICTIONAL_READER'] = 'synthetic'
try:
    env({'dsn_env': 'FICTIONAL_READER'}, 'dsn')
except RuntimeError:
    pass
else:
    raise AssertionError('reference resolved service credentials')
"""
subprocess.run([sys.executable, "-I", "-c", script], cwd=root, check=True)
print("Native distribution: no Python entry point; test reference isolated and network credentials refused")
