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


def run(binary, config, endpoint, *command, live=True, check=True):
    env = dict(os.environ, GRANTLINE_R3B_READER=endpoint,
               GRANTLINE_R3B_ADMIN='http://127.0.0.1:1/' + MARKER,
               HTTP_PROXY='http://127.0.0.1:1', HTTPS_PROXY='http://127.0.0.1:1', ALL_PROXY='http://127.0.0.1:1')
    if endpoint is None:
        env.pop('GRANTLINE_R3B_READER', None)
    result = subprocess.run([binary, '-c', str(config), *command, *(['--live'] if live else [])],
                            env=env, cwd='/', capture_output=True, text=True, timeout=35)
    assert MARKER not in result.stdout + result.stderr, 'credential escaped through output'
    if not check:
        return result
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def config_at(root):
    config = root / 'config.toml'
    config.write_text('intent="intent.toml"\nsnapshots="history"\n[adapters.ch-test]\ntype="clickhouse"\nurl_env="GRANTLINE_R3B_READER"\nadmin_url_env="GRANTLINE_R3B_ADMIN"\nread_timeout_seconds=1\n')
    (root / 'intent.toml').write_text('managed_subjects=["demo"]\nmanaged_systems=["ch-test"]\n[[grants]]\nsystem="ch-test"\nsubject="demo"\nresource="db:analytics"\nprivs=["SELECT"]\n')
    return config


def protocol(binary):
    state = dict(mode='healthy', calls=[])

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
            assert self.headers.get('X-ClickHouse-User') == 'reader'
            assert self.headers.get('X-ClickHouse-Key') == MARKER + '+:pw'
            assert 'user' not in params and 'password' not in params and MARKER not in self.path
            assert params['readonly'] == ['2'] and params['result_overflow_mode'] == ['throw']
            assert params['max_rows_to_read'] == ['100000'] and params['max_execution_time'] == ['30']
            assert params['default_format'] == ['JSON'] and params['wait_end_of_query'] == ['1']
            if query.startswith('CHECK GRANT'):
                rows = [dict(result=0 if mode == 'restricted' else 1)]
            elif 'system.role_grants' in query:
                assert 'LIMIT 10001' in query
                rows = [role(), role(None, 'base', 'reader')]
            elif 'system.grants' in query:
                assert 'LIMIT 10001' in query
                rows = [grant('demo'), grant('table-user', table='events'), grant('global-user', database=None),
                        grant('stale', database='dropped'), grant(None, 'base')]
                if mode == 'column':
                    rows[-1]['column'] = 'a'
                if mode == 'partial':
                    rows[-1]['is_partial_revoke'] = 1
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
            recorded = run(binary, config, endpoint, 'snapshot', '--json')
            assert recorded['grants'] == 7
            calls = len(state['calls'])
            assert run(binary, config, endpoint, 'plan', '--observed', recorded['path'], '--json', live=False)['observed'] == plan['observed']
            assert len(state['calls']) == calls
            assert run(binary, config, endpoint, 'plan', '--observed', recorded['path'], '--json', check=False).returncode != 0
            assert len(state['calls']) == calls
            for mode in ['column', 'partial']:
                state['mode'] = mode
                plan = run(binary, config, endpoint, 'plan', '--json')
                assert {s for u in plan['unobserved'] for s in u['subjects']} == {'base', 'reader', 'demo'}, mode
                assert not any(g['subject'] in {'base', 'reader', 'demo'} for g in plan['observed'])
                assert plan['unverified'] and not any(c['grant']['subject'] == 'demo' for c in plan['changes'])
            cases = ['restricted', 'failed-after-roles', 'missing-field', 'invalid-flag', 'prefix', 'row-limit',
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
GRANT SELECT ON gl_data.* TO gl_base;
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
            assert unknown == {'gl_column_role', 'gl_column', 'gl_partial'}, unknown
            assert not any(g[0] in unknown for g in observed)
            assert not any(c['grant']['subject'] in unknown for c in plan['changes'])
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
            sql('CREATE USER gl_prefix; GRANT SELECT ON prefixdemo*.* TO gl_prefix;')
            prefix = run(binary, config, endpoint, 'plan', '--json')
            assert not prefix['observed'] and not prefix['changes'] and prefix['unobserved']
            assert any('Wildcard-prefix' in u['note'] for u in prefix['unobserved'])
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
