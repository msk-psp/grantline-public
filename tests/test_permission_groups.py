"""Permission candidates are folded by account, then separated by service."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from grantline.diff import Change
from grantline.i18n import language
from grantline.model import Grant
from grantline.web import render

one = Grant('s3', '<demo>', 'bucket:example', 'Read')
two = Grant('s3', '<demo>', 'bucket:example', 'Write')
changes = [Change('grant', one, 'MOCK <ADD>', (one, two)),
           Change('revoke', Grant('postgres', '<demo>', 'db:example', 'CONNECT'), 'MOCK REMOVE'),
           Change('revoke', Grant('s3', 'service-demo', 'bucket:example', 'Read'), 'MOCK OTHER')]
token = language.set('ko')
try:
    page = render(set(), changes, [])
    plan = page.split('<h2>권한 차이</h2>')[1].split('<h2>진단</h2>')[0]
    assert plan.count('<details>') == 2 and '<details open' not in plan
    assert '&lt;demo&gt; · 추가 후보 2건 · 회수 후보 1건' in plan
    assert 'service-demo · 추가 후보 0건 · 회수 후보 1건' in plan
    assert '<h3>s3 · 추가 후보 2건 · 회수 후보 0건</h3>' in plan
    assert '<h3>postgres · 추가 후보 0건 · 회수 후보 1건</h3>' in plan
    assert 'MOCK &lt;ADD&gt;' in plan and 'MOCK <ADD>' not in page
    assert all(cmd in plan for cmd in ('MOCK REMOVE', 'MOCK OTHER'))
    assert '자동으로 적용되지 않습니다' in plan
finally:
    language.reset(token)

# Folding replaces the old flat 200-command cutoff; candidates remain reachable.
many = [Change('grant', one, f'MOCK {i}') for i in range(205)]
assert 'MOCK 204</code>' in render(set(), many, [])
