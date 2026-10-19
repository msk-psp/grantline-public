#!/usr/bin/env python3
"""Native detail/history/filter/prefill/refresh contracts, no external services."""
import datetime
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='grantline-console-details-') as tmp:
        root = Path(tmp)
        cfg = root / 'grantline.toml'
        cfg.write_text('intent="intent.toml"\nsnapshots="history"\n[adapters.pg]\ntype="fixture"\nkind="postgres"\nfixture="fixture.json"\n[adapters.pg-staging]\ntype="fixture"\nkind="postgres"\nfixture="fixture.json"\n[graph.environments]\nprod=["pg"]\nstaging=["pg-staging"]\n')
        (root / 'intent.toml').write_text('')
        grants = [dict(subject='alice', resource='role:reader', priv='MEMBER'), dict(subject='reader', resource='table:demo.app.events', priv='SELECT', source='explicit', grantor='owner')]
        (root / 'fixture.json').write_text(json.dumps(dict(grants=grants,kinds={'alice':'account','reader':'role'})))
        history = root / 'history'
        history.mkdir(mode=0o700)
        for day, subject in [(1, 'before-user'), (2, 'after-user')]:
            records = [dict(run=dict(ts=f'2026-10-{day:02}T00:00:00+00:00', user='demo', systems=['pg'])),dict(grant=dict(system='pg',subject=subject,resource='table:demo.app.events',priv='SELECT'))]
            (history / f'snapshot-2026100{day}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records))
        with socket.socket() as free:
            free.bind(('127.0.0.1', 0))
            port = free.getsockname()[1]
        child = subprocess.Popen([str(ROOT / 'rust/target/debug/grantline-rs'),'-c',str(cfg),'serve','--host','127.0.0.1','--port',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            origin = f'http://127.0.0.1:{port}'

            def page(path):
                with urllib.request.urlopen(origin+path,timeout=5) as response:
                    html = response.read().decode()
                boot = json.loads(re.search(r'<script id=grantline-data type=application/json>(.*?)</script>',html,re.S)[1])
                return boot, html.split('<script id=grantline-data')[0]

            for _ in range(100):
                assert child.poll() is None
                try:
                    page('/accounts')
                    break
                except OSError:
                    time.sleep(.03)
            b, h = page('/account?subject=alice&environment=prod&lang=en')
            assert b['error'] is None and 'Inherited grants' in h and 'reader' in h and 'Grantor' in h
            assert '<td>pg-staging' not in h
            b, h = page('/resource?resource=db%3Ademo&system=pg&lang=en')
            assert 'Child resources' in h and 'schema:demo.app' in h and 'events' in h
            b, h = page('/act?system=pg&subject=alice&resource=table%3Ademo.app.events&priv=SELECT&action=revoke&lang=en')
            assert (b['subject'],b['resource'],b['privilege'],b['action']) == ('alice','table:demo.app.events','SELECT','revoke')
            refresh = urllib.parse.parse_qs(urllib.parse.urlsplit(b['refresh_url']).query)
            assert refresh['subject'] == ['alice'] and refresh['action'] == ['revoke'] and refresh['refresh'] == ['1']
            assert 'fieldset disabled' in h
            query = '/history?from=snapshot-20261001.jsonl&to=snapshot-20261002.jsonl&lang=en'
            b, h = page(query)
            c = b['history_comparison']
            assert b['error'] is None and c['added'][0]['subject'] == 'after-user' and c['removed'][0]['subject'] == 'before-user', (b['error'], c)
            assert 'from=snapshot-20261001.jsonl' in b['refresh_url'] and 'to=snapshot-20261002.jsonl' in b['refresh_url']
            b, _ = page('/history?since=2026-10-01T12%3A00%3A00Z&to=snapshot-20261002.jsonl')
            assert b['error'] is None and b['history_comparison']['added'][0]['subject'] == 'after-user'
            assert page('/history?from=..%2Foutside&to=snapshot-20261002.jsonl')[0]['error']
            (history/'snapshot-20261003.jsonl').write_text('malformed snapshot')
            assert page('/history?since=2026-10-01T12%3A00%3A00Z')[0]['error'], 'invalid history silently disappeared'
            for item in history.iterdir():
                item.unlink()
            # A known baseline and one new grant: only its current context should be drawn.
            now = datetime.datetime.now(datetime.UTC)
            base = [dict(system='pg',subject='alice',resource='role:reader',priv='MEMBER'),dict(system='pg',subject='reader',resource='table:demo.app.old',priv='SELECT')]
            records = [dict(run=dict(ts=(now-datetime.timedelta(days=10)).isoformat(),user='demo',systems=['pg']))] + [dict(grant=g) for g in base]
            (history/'snapshot-baseline.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records))
            with urllib.request.urlopen(origin+'/api/catalog?days=7',timeout=5) as response:
                recent = json.load(response)
            assert recent['recent']['complete'] and recent['recent']['added'] == 1 and recent['recent']['removed'] == 1, recent['recent']
            assert recent['graph']['terminals'] == ['table:demo.app.events'], recent['graph']
            b, h = page('/resources?days=7&system=pg&lang=en')
            assert b['error'] is None and 'Observed change routes' in h and 'table:demo.app.events' in h and 'table:demo.app.old' not in h
            try:
                urllib.request.urlopen(origin+'/api/catalog?days=-1',timeout=5)
                raise AssertionError('invalid recent window accepted')
            except urllib.error.HTTPError as exc:
                assert exc.code == 400 and 'error' in json.load(exc)
            print('Console details: inherited paths/source/grantor/environment filter, DB/schema navigation, request prefill/read-only guard, refresh context, exact/since history diffs and unsafe/malformed snapshot refusal, recent route context/removal accounting and invalid window refusal passed')
        finally:
            child.terminate()
            child.wait(timeout=5)


if __name__ == '__main__':
    main()
