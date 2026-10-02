"""Run every tests/test_*.py as the script it is.

The tests are plain modules that assert at import time — each one pins a mistake that
was real once (its docstring says which). A framework would add fixtures and discovery
for no gain here; what matters is that every file runs and any failure stops the build.

    python tests/run.py           # all
    python tests/run.py graph s3  # only files whose name contains one of these
"""
import runpy
import sys
import traceback
from pathlib import Path

here = Path(__file__).parent
only = sys.argv[1:]
files = sorted(p for p in here.glob("test_*.py") if not only or any(o in p.name for o in only))
failed = []
for f in files:
    try:
        runpy.run_path(str(f), run_name="__main__")
        print(f"ok   {f.name}")
    except SystemExit as exc:
        if exc.code not in (None, 0):
            failed.append(f.name); print(f"FAIL {f.name} (exit {exc.code})")
    except Exception:
        failed.append(f.name); print(f"FAIL {f.name}"); traceback.print_exc()
print(f"\n{len(files) - len(failed)}/{len(files)} passed")
sys.exit(1 if failed else 0)
