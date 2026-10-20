#!/usr/bin/env python3
"""Isolated native ClickHouse reader tests; --docker also verifies a disposable real server."""
import argparse
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'clickhouse/clickhouse-server@sha256:a63a90ffdcb574683ebfe96e4c53e2dbe401864add7bb06dc244eb935d828e7f'
MARKER = 'NEVER-OUTPUT-CREDENTIAL'


def grant(subject='demo', role=None, **extra):
    return dict(dict(user_name=subject, role_name=role, access_type='SELECT', access_object='',
                     database='analytics', table=None, column=None, is_partial_revoke=0, grant_option=0), **extra)


def role(user='demo', name='reader', parent=None):
    return dict(user_name=user, role_name=parent, granted_role_name=name, with_admin_option=0)


def encoded(rows):
    return json.dumps(dict(data=rows, rows=len(rows)), ensure_ascii=False).encode()


def run(binary, config, endpoint, *command, live=True, check=True, extra_env=None):
    env = dict(os.environ, GRANTLINE_R3B_READER=endpoint,
               GRANTLINE_R3B_ADMIN='http://127.0.0.1:1/' + MARKER,
               HTTP_PROXY='http://127.0.0.1:1', HTTPS_PROXY='http://127.0.0.1:1', ALL_PROXY='http://127.0.0.1:1')
    env.update(extra_env or {})
    if endpoint is None:
        env.pop('GRANTLINE_R3B_READER', None)
    result = subprocess.run([binary, '-c', str(config), *command, *(['--live'] if live else [])],
                            env=env, cwd='/', capture_output=True, text=True, timeout=35)
    assert MARKER not in result.stdout + result.stderr, 'credential escaped through output'
    if not check:
        return result
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def probe_baseline(root, rows):
    path = root / 'probe-baseline.jsonl'
    records = [dict(run=dict(ts='2026-10-01T00:00:00+00:00', user='demo', systems=['ch-test']))]
    records += [dict(grant=dict(system='ch-test', subject=s, resource=r, priv=p)) for s, r, p in rows]
    path.write_text(''.join(json.dumps(row) + '\n' for row in records))
    return path


def probe_rows(report):
    return {(p['subject'], p['resource'], p['priv']): p for p in report['probes']}


def config_at(root):
    config = root / 'config.toml'
    config.write_text('intent="intent.toml"\nsnapshots="history"\n[adapters.ch-test]\ntype="clickhouse"\nurl_env="GRANTLINE_R3B_READER"\nadmin_url_env="GRANTLINE_R3B_ADMIN"\nread_timeout_seconds=1\n')
    (root / 'intent.toml').write_text('managed_subjects=["demo"]\nmanaged_systems=["ch-test"]\n[[grants]]\nsystem="ch-test"\nsubject="demo"\nresource="db:analytics"\nprivs=["SELECT"]\n')
    return config


def protocol(binary):
    state = dict(mode='healthy', calls=[], user='reader')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path)
            params = urllib.parse.parse_qs(path.query)
            state['calls'].append((path.path, params, dict(self.headers)))
            mode = state['mode']
            status, body, headers = 200, None, {}
            query = params.get('query', [''])[0]
            assert path.path == '/catalog/'
            assert self.headers.get('X-ClickHouse-User') == state['user']
            assert self.headers.get('X-ClickHouse-Key') == MARKER + '+:pw'
            assert 'user' not in params and 'password' not in params and MARKER not in self.path
            assert params['readonly'] == ['2'] and params['result_overflow_mode'] == ['throw']
            assert params['max_rows_to_read'] == ['100000'] and params['max_execution_time'] == ['30']
            assert params['default_format'] == ['JSON'] and params['wait_end_of_query'] == ['1']
            if query.startswith('SELECT currentUser()'):
                rows = [dict(user='another' if mode == 'identity-wrong' else state['user'])]
            elif query.startswith('SHOW GRANTS') and (mode.startswith('probe-') or mode == 'identity-wrong'):
                match = re.match(r'SHOW GRANTS FOR `([^`]+)`', query)
                subject = match[1] if match else state['user']
                if 'WITH IMPLICIT FINAL' in query:
                    lines = [f'GRANT SELECT ON analytics.* TO `{subject}`']
                    if mode == 'probe-column':
                        lines = [f'GRANT SELECT(a) ON analytics.events TO `{subject}`']
                    if mode == 'probe-partial':
                        lines += [f'REVOKE SELECT ON analytics.events FROM `{subject}`']
                    if mode == 'probe-prefix':
                        lines = [f'GRANT SELECT ON prefix*.* TO `{subject}`']
                    if mode == 'probe-wrong-recipient':
                        lines = ['GRANT SELECT ON analytics.* TO another']
                    if mode == 'probe-unrecognized':
                        lines = ['garbage ' + MARKER]
                else:
                    lines = [f'GRANT reader TO `{subject}`']
                rows = [dict(grants=line) for line in lines]
            elif query.startswith('CHECK GRANT'):
                rows = [dict(result=0 if mode == 'restricted' else 1)]
            elif 'FROM system.users' in query and 'FROM system.roles' in query:
                assert 'LIMIT 10001' in query
                rows = [dict(name=name, kind=kind) for name, kind in [
                    ('demo', 'account'), ('reader', 'role'), ('base', 'role'),
                    ('empty-user', 'account'), ('empty-role', 'role'),
                ]]
                if mode == 'principal-kind':
                    rows[-1]['kind'] = 'unknown-kind'
            elif 'system.role_grants' in query:
                assert 'LIMIT 10001' in query
                rows = [role(), role(None, 'base', 'reader')]
            elif 'system.grants' in query:
                assert 'LIMIT 10001' in query
                rows = [grant('demo'), grant('table-user', table='events'), grant('global-user', database=None),
                        grant('stale', database='dropped'), grant(None, 'base')]
                if mode == 'column':
                    rows[-1].update(table='events', column='a')
                if mode == 'partial':
                    rows[-1]['is_partial_revoke'] = 1
                if mode == 'parameterized':
                    rows[-1]['access_object'] = 'unsupported-source'
                if mode == 'named-collection':
                    rows[-1].update(access_type='NAMED COLLECTION', access_object='fixture_store', database=None)
                if mode == 'missing-field':
                    del rows[0]['column']
                if mode == 'invalid-flag':
                    rows[0]['is_partial_revoke'] = 2
                if mode == 'failed-after-roles':
                    status, body = 500, MARKER.encode()
            elif 'system.databases' in query:
                rows = [dict(name='analytics')]
                if mode == 'row-limit':
                    rows *= 10001
            elif query.startswith('SHOW GRANTS FOR '):
                rows = [dict(grants='GRANT SELECT ON analytics*.* TO demo' if mode == 'prefix' else 'GRANT SELECT ON analytics.* TO demo')]
            else:
                raise AssertionError('unexpected query')
            if mode == 'redirect':
                status, headers = 302, dict(Location=f'http://127.0.0.1:{self.server.server_port}/leak')
            if mode == 'http403':
                status, body = 403, MARKER.encode()
            if mode == 'bad-json':
                body = b'<html>' + MARKER.encode()
            if mode == 'bad-count':
                body = b'{"data":[],"rows":1}'
            if mode == 'embedded-exception':
                body = json.dumps(dict(data=rows, rows=len(rows), exception=MARKER)).encode()
            if mode == 'hidden-limit':
                body = json.dumps(dict(data=rows, rows=len(rows), rows_before_limit_at_least=20000)).encode()
            if mode == 'exception-header':
                headers['X-ClickHouse-Exception-Code'] = '497'
            if mode == 'byte-limit':
                body = b'x' * (16 * 1024 * 1024 + 1)
            if mode == 'probe-late-timeout':
                time.sleep(0.65)
            if mode == 'timeout':
                time.sleep(1.2)
            if body is None:
                body = encoded(rows)
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f'http://reader:{MARKER}%2B%3Apw@127.0.0.1:{server.server_port}/catalog/'
    try:
        with tempfile.TemporaryDirectory(prefix='grantline-ch-http-') as folder:
            root = Path(folder)
            config = config_at(root)
            offline = run(binary, config, endpoint, 'plan', '--json', live=False)
            assert not state['calls'] and offline['unobserved'] and not offline['changes']
            plan = run(binary, config, endpoint, 'plan', '--json')
            assert len(plan['observed']) == 7 and plan['observation_complete']
            assert any(f['title'] == 'stale grants on dropped database' and f['system'] == 'ch-test' for f in plan['findings'])
            graph = run(binary, config, endpoint, 'graph', '--subject', 'demo', '--json')
            assert graph['graph']['kind']['base'] == 'role'
            assert any('base' in path for path in graph['routes_from']['demo']['paths'])
            assert graph['graph']['kind']['empty-user'] == 'human'
            assert graph['graph']['kind']['empty-role'] == 'role'
            assert graph['graph']['homes']['empty-user'] == ['ch-test']
            assert not any(e['src'] == 'empty-user' or e['dst'] == 'empty-user' for e in graph['graph']['edges'])
            recorded = run(binary, config, endpoint, 'snapshot', '--json')
            assert recorded['grants'] == 7
            calls = len(state['calls'])
            assert run(binary, config, endpoint, 'plan', '--observed', recorded['path'], '--json', live=False)['observed'] == plan['observed']
            assert len(state['calls']) == calls
            assert run(binary, config, endpoint, 'plan', '--observed', recorded['path'], '--json', check=False).returncode != 0
            assert len(state['calls']) == calls
            state['mode'] = 'column'
            plan = run(binary, config, endpoint, 'plan', '--json')
            assert not plan['unobserved']
            assert any(g['subject'] == 'base' and g['resource'] == 'column:analytics.events.a' for g in plan['observed'])
            state['mode'] = 'named-collection'
            plan = run(binary, config, endpoint, 'plan', '--json')
            assert not plan['unobserved']
            assert any(g['subject'] == 'base' and g['resource'] == 'named_collection:fixture_store' for g in plan['observed'])
            for mode in ['partial', 'parameterized']:
                state['mode'] = mode
                plan = run(binary, config, endpoint, 'plan', '--json')
                assert {s for u in plan['unobserved'] for s in u['subjects']} == {'base', 'reader', 'demo'}, mode
                assert all(u['category'] == 'unsupported' and u['privileges'] == ['SELECT'] for u in plan['unobserved'])
                assert not any(g['subject'] in {'base', 'reader', 'demo'} and g['priv'] == 'SELECT' for g in plan['observed'])
                assert any(g['subject'] == 'demo' and g['priv'] == 'MEMBER' for g in plan['observed'])
                assert plan['unverified'] and not any(c['grant']['subject'] == 'demo' for c in plan['changes'])
                recorded = run(binary, config, endpoint, 'snapshot', '--json')
                imported = run(binary, config, endpoint, 'plan', '--observed', recorded['path'], '--json', live=False)
                assert imported['unobserved'] == plan['unobserved'] and imported['observed'] == plan['observed']
            cases = ['restricted', 'principal-kind', 'failed-after-roles', 'missing-field', 'invalid-flag', 'prefix', 'row-limit',
                     'redirect', 'http403', 'bad-json', 'bad-count', 'exception-header', 'embedded-exception', 'hidden-limit', 'byte-limit', 'timeout']
            for mode in cases:
                state.update(mode=mode, calls=[])
                plan = run(binary, config, endpoint, 'plan', '--json')
                assert not plan['observation_complete'] and not plan['observed'] and not plan['changes'] and plan['unverified'], mode
                assert any(f['title'] == 'system could not be read' for f in plan['findings']), mode
                if mode == 'redirect':
                    assert len(state['calls']) == 1
            state.update(mode='healthy', calls=[])
            for endpoint_bad in [None, 'not-a-url-' + MARKER, 'http://reader:' + MARKER + '@127.0.0.1:1/?password=bad', 'file:///tmp/' + MARKER, endpoint.replace('http:', 'https:')]:
                plan = run(binary, config, endpoint_bad, 'plan', '--json')
                assert plan['unobserved'] and not plan['changes']
            assert not state['calls']
            original = config.read_text()
            config.write_text(original.replace('type="clickhouse"', 'type="clickhouse"\nkind="postgres"'))
            assert run(binary, config, endpoint, 'plan', '--json', check=False).returncode != 0
            assert not state['calls']
            config.write_text(original)
            cases_probe = [('demo', 'table:analytics.events', 'SELECT'),
                           ('demo', 'db:missing', 'SELECT'), ('demo', 'role:reader', 'MEMBER')]
            baseline = probe_baseline(root, cases_probe)
            command = ('probe', '--observed', str(baseline), '--json')
            state.update(mode='probe-healthy', calls=[], user='reader')
            offline = run(binary, config, endpoint, *command, live=False)
            assert offline['summary'] == dict(allow=0, deny=0, unknown=3) and not state['calls']
            report = run(binary, config, endpoint, *command)
            assert [probe_rows(report)[c]['verdict'] for c in cases_probe] == ['allow', 'deny', 'allow'], report
            assert len(report['findings']) == 1
            assert all('not a login' in p['how'] for p in report['probes'])
            # Explicit observer override works without a reader, and never falls back if missing.
            original = config.read_text()
            config.write_text(original + 'probe_url_env="GRANTLINE_R3E_OBSERVER"\n')
            dedicated = run(binary, config, None, *command, extra_env={'GRANTLINE_R3E_OBSERVER': endpoint})
            assert dedicated['summary'] == report['summary']
            count = len(state['calls'])
            unavailable = run(binary, config, endpoint, *command, extra_env={'GRANTLINE_R3E_OBSERVER': ''})
            assert unavailable['summary'] == dict(allow=0, deny=0, unknown=3) and len(state['calls']) == count
            config.write_text(original + '[adapters.ch-test.probe_url_envs]\ndemo="GRANTLINE_R3E_SUBJECT"\n')
            state.update(user='demo', calls=[])
            subject_url = endpoint.replace('reader:', 'demo:')
            logged = run(binary, config, None, *command, extra_env={'GRANTLINE_R3E_SUBJECT': subject_url})
            assert logged['summary'] == report['summary']
            assert all('subject HTTP login' in p['how'] for p in logged['probes'])
            state.update(mode='identity-wrong', calls=[])
            mismatch = run(binary, config, endpoint, *command, extra_env={'GRANTLINE_R3E_SUBJECT': subject_url})
            assert mismatch['summary'] == dict(allow=0, deny=0, unknown=3) and len(state['calls']) == 1
            assert not mismatch['findings']
            state.update(mode='probe-healthy', calls=[])
            absent = run(binary, config, endpoint, *command, extra_env={'GRANTLINE_R3E_SUBJECT': ''})
            assert absent['summary']['unknown'] == 3 and not state['calls']
            config.write_text(original)
            state.update(user='reader', calls=[])
            for mode in ['probe-column', 'probe-partial', 'probe-prefix', 'probe-wrong-recipient', 'probe-unrecognized',
                         'redirect', 'http403', 'bad-json', 'bad-count', 'exception-header', 'embedded-exception', 'hidden-limit', 'byte-limit', 'timeout']:
                state.update(mode=mode, calls=[])
                failed = run(binary, config, endpoint, *command)
                assert failed['summary'] == dict(allow=0, deny=0, unknown=3) and not failed['findings'], (mode, failed)
                if mode == 'redirect':
                    assert len(state['calls']) == 1
            # A later subject timing out invalidates even an earlier successful subject.
            delayed = probe_baseline(root, [('demo', 'db:analytics', 'SELECT'), ('zlate', 'db:analytics', 'SELECT')])
            state.update(mode='probe-late-timeout', calls=[])
            failed = run(binary, config, endpoint, 'probe', '--observed', str(delayed), '--json')
            assert failed['summary'] == dict(allow=0, deny=0, unknown=2)
            assert all('partial results discarded' in p['how'] for p in failed['probes'])
            state.update(mode='probe-healthy', calls=[])
            too_many = probe_baseline(root, [(f'u{i}', 'db:analytics', 'SELECT') for i in range(129)])
            capped = run(binary, config, endpoint, 'probe', '--observed', str(too_many), '--json')
            assert capped['summary']['unknown'] == 129 and not state['calls']
            print('ClickHouse probe HTTP: offline isolation, ACL/role verdicts, explicit observer and subject credential isolation, identity mismatch, 14 unknown/error cases, total-deadline partial discard, subject cap and redaction passed')
            print(f'ClickHouse HTTP: offline/import isolation, live plan/graph/snapshot, 2 inherited unknown cases and {len(cases)} failure cases passed')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def docker_test(binary, context):
    # Explicit context prevents DOCKER_HOST from redirecting test writes elsewhere.
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    ctx = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert ctx['Endpoints']['docker']['Host'].startswith('unix://'), 'integration test requires a local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-r3b-' + uuid.uuid4().hex[:12]
    def sql(query):
        return subprocess.check_output([*docker, 'exec', '-i', name, 'clickhouse-client', '--multiquery'], input=query, text=True, stderr=subprocess.PIPE)
    try:
        subprocess.run([*docker, 'run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::8123', '--memory', '2g', '--cpus', '2',
                        '--ulimit', 'nofile=262144:262144', IMAGE], check=True, stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 60
        while True:
            try:
                assert sql('SELECT 1') == '1\n'
                break
            except (subprocess.CalledProcessError, AssertionError):
                if time.monotonic() >= deadline:
                    raise RuntimeError('Disposable ClickHouse failed to start') from None
                time.sleep(0.2)
        # Fictional identities and empty data, entirely inside the disposable server.
        sql('''
CREATE DATABASE gl_data;
CREATE DATABASE gl_dropped;
CREATE TABLE gl_data.events (a UInt8, b UInt8) ENGINE=Memory;
CREATE USER gl_observer IDENTIFIED WITH no_password SETTINGS readonly=2;
GRANT SHOW ACCESS, SHOW DATABASES ON *.* TO gl_observer;
GRANT SELECT ON system.grants TO gl_observer;
GRANT SELECT ON system.role_grants TO gl_observer;
GRANT SELECT ON system.databases TO gl_observer;
CREATE USER gl_restricted IDENTIFIED WITH no_password SETTINGS readonly=2;
CREATE ROLE gl_base, gl_nested, gl_column_role;
CREATE USER gl_subject, gl_table, gl_global, gl_stale, gl_column, gl_partial;
CREATE NAMED COLLECTION gl_store AS url='http://127.0.0.1:1/fixture';
GRANT SELECT ON gl_data.* TO gl_base;
GRANT NAMED COLLECTION ON gl_store TO gl_base;
GRANT gl_base TO gl_nested;
GRANT gl_nested TO gl_subject;
GRANT SELECT ON gl_data.events TO gl_table;
GRANT SELECT ON *.* TO gl_global;
GRANT SELECT ON gl_dropped.* TO gl_stale;
DROP DATABASE gl_dropped;
GRANT SELECT(a) ON gl_data.events TO gl_column_role;
GRANT gl_column_role TO gl_column;
GRANT SELECT ON *.* TO gl_partial;
REVOKE SELECT ON gl_data.events FROM gl_partial;
GRANT INSERT ON gl_data.events TO gl_partial;
''')
        hostport = subprocess.check_output([*docker, 'port', name, '8123'], text=True).strip()
        assert hostport.startswith('127.0.0.1:')
        endpoint = f'http://gl_observer@{hostport}/'
        with tempfile.TemporaryDirectory(prefix='grantline-ch-live-') as folder:
            config = config_at(Path(folder))
            config.write_text(config.read_text().replace('read_timeout_seconds=1', 'read_timeout_seconds=30'))
            (Path(folder) / 'intent.toml').write_text('managed_subjects=["gl_subject","gl_column","gl_partial"]\nmanaged_systems=["ch-test"]\n')
            plan = run(binary, config, endpoint, 'plan', '--json')
            assert plan['observed'], [f['detail'] for f in plan['findings']]
            observed = {(g['subject'], g['resource'], g['priv']) for g in plan['observed']}
            assert ('gl_base', 'db:gl_data', 'SELECT') in observed
            assert ('gl_nested', 'role:gl_base', 'MEMBER') in observed
            assert ('gl_subject', 'role:gl_nested', 'MEMBER') in observed
            assert ('gl_table', 'table:gl_data.events', 'SELECT') in observed
            assert ('gl_global', 'global:*', 'SELECT') in observed
            assert ('gl_stale', 'db:gl_dropped', 'SELECT') in observed
            unknown = {s for u in plan['unobserved'] for s in u['subjects']}
            assert unknown == {'gl_partial'}, unknown
            assert ('gl_column_role', 'column:gl_data.events.a', 'SELECT') in observed
            assert ('gl_column', 'role:gl_column_role', 'MEMBER') in observed
            assert ('gl_base', 'named_collection:gl_store', 'NAMED COLLECTION') in observed
            assert ('gl_partial', 'table:gl_data.events', 'INSERT') in observed
            assert not any(g[0] in unknown and g[2] == 'SELECT' for g in observed)
            assert not any(c['grant']['subject'] in unknown and c['grant']['priv'] in {'SELECT', 'MEMBER', 'ALL'} for c in plan['changes'])
            assert any(f['title'] == 'stale grants on dropped database' and 'gl_stale' in f['entities'] for f in plan['findings'])
            restricted = run(binary, config, endpoint.replace('gl_observer', 'gl_restricted'), 'plan', '--json')
            assert not restricted['observed'] and not restricted['changes'] and restricted['unobserved']
            # Independent server-side proof: the observer cannot execute a write.
            url = f'http://{hostport}/'
            try:
                urllib.request.urlopen(urllib.request.Request(url, data=b'CREATE DATABASE gl_forbidden', headers={'X-ClickHouse-User': 'gl_observer'}, method='POST'), timeout=5)
            except urllib.error.HTTPError as exc:
                assert re.search(rb'Code: (164|497)\.', exc.read()), 'write did not fail with READONLY/ACCESS_DENIED'
            else:
                raise AssertionError('read-only observer accepted a write')
            assert sql('EXISTS DATABASE gl_forbidden') == '0\n'
            # Server-resolved ACLs flatten all granted roles. Direct membership is queried separately.
            root = Path(folder)
            cases_probe = [('gl_subject', 'table:gl_data.events', 'SELECT'),
                           ('gl_subject', 'table:gl_data.events', 'INSERT'),
                           ('gl_subject', 'role:gl_nested', 'MEMBER'),
                           ('gl_subject', 'role:gl_base', 'MEMBER'),
                           ('gl_table', 'db:gl_data', 'SELECT'),
                           ('gl_global', 'table:anywhere.events', 'SELECT'),
                           ('gl_stale', 'db:gl_dropped', 'SELECT'),
                           ('gl_column', 'table:gl_data.events', 'SELECT'),
                           ('gl_partial', 'table:gl_data.events', 'SELECT'),
                           ('gl_base', 'db:gl_data', 'SELECT'),
                           ('missing-user', 'db:gl_data', 'SELECT'),
                           ('gl_subject', 'db:gl_data', 'ALL')]
            baseline = probe_baseline(root, cases_probe)
            command = ('probe', '--observed', str(baseline), '--json')
            report = run(binary, config, endpoint, *command)
            expected = ['allow', 'deny', 'allow', 'deny', 'deny', 'allow', 'allow', 'unknown', 'unknown', 'allow', 'unknown', 'unknown']
            assert [probe_rows(report)[c]['verdict'] for c in cases_probe] == expected, report
            assert len(report['findings']) == 3
            assert all('not a login' in p['how'] for p in report['probes'] if p['verdict'] != 'unknown')
            restricted = run(binary, config, endpoint.replace('gl_observer', 'gl_restricted'), *command)
            assert restricted['summary']['allow'] == restricted['summary']['deny'] == 0
            # Quoted user, database and table identifiers must survive SHOW GRANTS and SQL quoting.
            sql('CREATE DATABASE `gl space`; CREATE TABLE `gl space`.`odd``table` (a UInt8) ENGINE=Memory; CREATE USER `gl``quoted`; GRANT SELECT ON `gl space`.`odd``table` TO `gl``quoted`;')
            quoted_baseline = probe_baseline(root, [('gl`quoted', 'table:gl space.odd`table', 'SELECT')])
            quoted_report = run(binary, config, endpoint, 'probe', '--observed', str(quoted_baseline), '--json')
            assert quoted_report['summary'] == dict(allow=1, deny=0, unknown=0), quoted_report
            # A real password login. readonly=2 must not turn a held INSERT ACL into a false denial.
            sql("CREATE USER gl_login IDENTIFIED WITH sha256_password BY 'NEVER-OUTPUT-CREDENTIAL' SETTINGS readonly=2; GRANT SELECT, INSERT ON gl_data.* TO gl_login;")
            login_baseline = probe_baseline(root, [('gl_login', 'table:gl_data.events', p) for p in ['SELECT', 'INSERT']])
            original = config.read_text()
            config.write_text(original + '[adapters.ch-test.probe_url_envs]\ngl_login="GRANTLINE_R3E_SUBJECT"\n')
            login_url = f'http://gl_login:{MARKER}@{hostport}/'
            logged = run(binary, config, None, 'probe', '--observed', str(login_baseline), '--json', extra_env={'GRANTLINE_R3E_SUBJECT': login_url})
            assert logged['summary'] == dict(allow=2, deny=0, unknown=0), logged
            assert all('subject HTTP login' in p['how'] for p in logged['probes'])
            for credentials in ['', login_url.replace(MARKER, 'WRONG-SYNTHETIC-PASSWORD'), endpoint]:
                failed = run(binary, config, endpoint, 'probe', '--observed', str(login_baseline), '--json', extra_env={'GRANTLINE_R3E_SUBJECT': credentials})
                assert failed['summary'] == dict(allow=0, deny=0, unknown=2) and not failed['findings'], failed
            config.write_text(original)
            req = urllib.request.Request(url, data=b'CHECK GRANT INSERT ON gl_data.events',
                                         headers={'X-ClickHouse-User': 'gl_login', 'X-ClickHouse-Key': MARKER}, method='POST')
            # Server profile is readonly=2, so CHECK GRANT reflects that context rather than the stored ACL.
            assert urllib.request.urlopen(req, timeout=5).read().strip() == b'0'
            # Disabled default roles are still included in FINAL; this is not an activation/data proof.
            sql('CREATE USER gl_disabled; GRANT gl_nested TO gl_disabled; SET DEFAULT ROLE NONE TO gl_disabled;')
            disabled_baseline = probe_baseline(root, [('gl_disabled', 'table:gl_data.events', 'SELECT')])
            config.write_text(original + '[adapters.ch-test.probe_url_envs]\ngl_disabled="GRANTLINE_R3E_SUBJECT"\n')
            disabled = run(binary, config, None, 'probe', '--observed', str(disabled_baseline), '--json', extra_env={'GRANTLINE_R3E_SUBJECT': f'http://gl_disabled@{hostport}/'})
            assert disabled['summary'] == dict(allow=1, deny=0, unknown=0), disabled
            assert 'all granted roles' in disabled['probes'][0]['how']
            req = urllib.request.Request(url, data=b'CHECK GRANT SELECT ON gl_data.events',
                                         headers={'X-ClickHouse-User': 'gl_disabled'}, method='POST')
            assert urllib.request.urlopen(req, timeout=5).read().strip() == b'0'
            config.write_text(original)
            prefix_baseline = probe_baseline(root, [('gl_prefix', 'db:prefixdemo', 'SELECT')])
            print('ClickHouse probe Docker: real nested/global/table ACLs, direct role membership, partial/column unknowns, quoted names, missing/restricted observers, password login/mismatch/failure, read-only INSERT semantics and non-default roles passed')
            sql('CREATE USER gl_prefix; GRANT SELECT ON prefixdemo*.* TO gl_prefix;')
            prefix_probe = run(binary, config, endpoint, 'probe', '--observed', str(prefix_baseline), '--json')
            assert prefix_probe['summary'] == dict(allow=0, deny=0, unknown=1), prefix_probe
            prefix = run(binary, config, endpoint, 'plan', '--json')
            assert not prefix['observed'] and not prefix['changes'] and prefix['unobserved']
            assert any('Wildcard-prefix' in u['note'] for u in prefix['unobserved'])
            print('ClickHouse server version:', sql('SELECT version()').strip())
            print('ClickHouse Docker: 26.6.2.160 catalog scopes, nested roles, stale DB, column/partial unknowns, restricted visibility, write refusal and legacy wildcard guard passed')
    finally:
        subprocess.run([*docker, 'stop', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'rust/target/debug/grantline-rs')
    parser.add_argument('--docker', action='store_true')
    parser.add_argument('--docker-context')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    protocol(binary)
    if args.docker:
        docker_test(binary, args.docker_context)


if __name__ == '__main__':
    main()
