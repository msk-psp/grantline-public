"""Diagnostic severity must stay separate from grant direction and preserve details."""
import datetime
import html
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from grantline import pages, web
from grantline.cli import _load, _observe_and_plan
from grantline.i18n import LANGUAGES, language, t
from grantline.model import Finding, Grant, Unobserved
from grantline.probe import Probe
from grantline.probe import compare as compare_probes
from grantline.snapshot import Snapshot, compare

assert Finding('s3', 'system could not be read', 'down').level == 'error'
assert Finding('s3', 'unmanaged drift', 'review').level == 'warning'
assert Finding('s3', 'already covered by a broader grant', 'covered').level == 'info'
assert Finding('s3', 'custom', 'notice', level='info').level == 'info'
try:
    Finding('s3', 'custom', 'notice', level='" onclick="bad')
except ValueError:
    pass
else:
    raise AssertionError('invalid levels must not become HTML class names')

findings = [Finding('s3', '<same title>', f'<detail{i}>', level='warning') for i in range(4)]
findings += [Finding('s3', '<same title>', 'failure', level='error'), Finding('s3', 'notice', 'info', level='info')]
notes = pages.render_findings(findings)
assert notes.index('note log-entry log-error') < notes.index('note log-entry log-warning') < notes.index('note log-entry log-info')
assert notes.count('<div class="note log-entry') == 3, 'different levels must not collapse together'
assert '<details><summary>2 more findings</summary>' in notes
assert all(f'&lt;detail{i}&gt;' in notes for i in range(4)) and '<detail0>' not in notes
assert '&lt;same title&gt;' in notes
assert notes in web.render(set(), [], findings)
assert notes in pages.render_probe('alice', [], findings)

before = Snapshot(Path('before'), datetime.datetime(2026, 10, 1, tzinfo=datetime.UTC), 'demo',
                  frozenset({'s3'}), frozenset({Grant('s3', 'alice', 'bucket:removed', 'Read')}), ())
after = Snapshot(Path('after'), datetime.datetime(2026, 10, 2, tzinfo=datetime.UTC), 'demo',
                 frozenset({'s3'}), frozenset({Grant('s3', 'alice', 'bucket:added', 'Write')}), ())
for locale in LANGUAGES:
    token = language.set(locale)
    try:
        log = pages._since_run(SimpleNamespace(comparison=compare(before, after)))
        assert '<th>' + t('Log level') + '</th>' in log
        assert log.count('log-level log-info') == 2 and 'log-error' not in log
        assert 'bucket:added' in log and 'bucket:removed' in log
        assert 'INFO' in pages._since_run(SimpleNamespace(comparison=None))
        assert 'ERROR' in pages._since_run(SimpleNamespace(error='<disk failure>'))
        assert '&lt;disk failure&gt;' in pages._since_run(SimpleNamespace(error='<disk failure>'))
        assert t('Warning') in pages.log_badge('warning')
        assert 'ERROR' in pages.render_inventory(set(), unobserved=[Unobserved('s3', ('bucket:',), '<down>')])
    finally:
        language.reset(token)
print('ok log classification, severity grouping/order, escaping, snapshot direction and four language badges')

# Identifiers are explicit, escaped, matched longest-first and never split inside words.
identifiers = ('alice', 'bucket:demo', 'bucket:demo/path.*', 'SELECT', '한 글', '<img src=x onerror=bad>')
detail = 'alice SELECT bucket:demo/path.*; bucket:demo, malice, alice_extra. 한 글 <img src=x onerror=bad> <unsafe>'
rich = pages.log_detail(Finding('s3', 'drift', detail, entities=identifiers + ('', 'alice')))
assert html.unescape(re.sub(r'<[^>]*>', '', rich)) == detail
assert all(pages.log_entity(value) in rich for value in identifiers)
assert 'malice, alice_extra' in rich and '<img' not in rich
assert '<code class="log-entity">bucket:demo</code>/path' not in rich
assert pages.log_detail(Finding('s3', 'drift', detail)) == html.escape(detail)
folded = pages.render_findings([Finding('s3', 'drift', 'alice', entities=('alice',)) for _ in range(4)])
assert folded.count(pages.log_entity('alice')) == 4 and '<details>' in folded

# Exercise actual diagnostic producers through the credential-free bundled demo.
it, adapters, *_ = _load(str(Path(__file__).resolve().parent.parent / 'examples/demo/grantline.toml'))
_, _, diagnostics, *_ = _observe_and_plan(it, adapters)
assert diagnostics and all(f.entities for f in diagnostics)
assert all('log-entity' in pages.log_detail(f) for f in diagnostics)
probe = compare_probes([Probe('s3', 'alice', 'bucket:demo', 'Read', 'deny', 'HEAD')],
                       {Grant('s3', 'alice', 'bucket:demo', 'Read')})[0]
assert all(pages.log_entity(value) in pages.log_detail(probe) for value in ('alice', 'bucket:demo', 'Read'))
assert pages.log_entity('bucket:added') in log and pages.log_entity('Write') in log
print('ok explicit entity blocks, literal matching, escaping, folded details, demo producers and probe logs')
