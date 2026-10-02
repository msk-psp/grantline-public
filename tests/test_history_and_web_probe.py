"""history (F8 over time) and the console's probe page (N4 in the web)."""
import datetime
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grantline import snapshot as snap
from grantline.model import Grant
from grantline.pages import parse_path, render_probe
from grantline.probe import Probe

# parse_since: relative forms count back from now, dates are absolute
now = datetime.datetime(2026, 9, 3, 12, 0, tzinfo=datetime.UTC)
assert snap.parse_since("7d", now) == now - datetime.timedelta(days=7)
assert snap.parse_since("2w", now) == now - datetime.timedelta(weeks=2)
assert snap.parse_since("2026-08-01", now) == datetime.datetime(2026, 8, 1, tzinfo=datetime.UTC)

# at_or_before picks the run that stood at that moment; compare over the two
with tempfile.TemporaryDirectory() as d:
    g1 = {Grant("postgres", "a", "db:x", "CONNECT")}
    g2 = g1 | {Grant("postgres", "b", "db:x", "CONNECT")}
    t1 = datetime.datetime(2026, 8, 20, 9, 0, tzinfo=datetime.UTC)
    t2 = datetime.datetime(2026, 9, 1, 9, 0, tzinfo=datetime.UTC)
    snap.write(d, g1, [], ["postgres"], now=t1)
    snap.write(d, g2, [], ["postgres"], now=t2)
    p = snap.at_or_before(d, datetime.datetime(2026, 8, 25, tzinfo=datetime.UTC))
    assert p and "2026-08-20" in p.name, p
    assert snap.at_or_before(d, datetime.datetime(2026, 8, 1, tzinfo=datetime.UTC)) is None
    cmp = snap.compare(snap.load(p), snap.load(snap.latest(d)))
    assert [g.subject for g in cmp.added] == ["b"] and not cmp.removed

# web route + page
assert parse_path("/s/researcher_b/probe") == ("probe", ("researcher_b",))
html = render_probe("researcher_b", [Probe("s3", "researcher_b", "bucket:x", "Read", "deny", "HEAD → 403"),
                            Probe("clickhouse", "researcher_b", "db:research", "SELECT", "unknown", "cannot ask")], [])
assert "verify" not in html and "HEAD → 403" in html and "cannot ask" in html and "1 denied" in html
print("ok")
