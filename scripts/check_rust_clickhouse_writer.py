#!/usr/bin/env python3
"""Single-statement ClickHouse writer: isolated HTTP failures and official server."""
import argparse
import copy
import json
import os
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

from check_rust_clickhouse import IMAGE, MARKER, ROOT, encoded, grant


def intent(root, rows, managed=('gl_user',)):
    text = 'managed_subjects=' + json.dumps(managed) + '\nmanaged_systems=["ch-test"]\n'
    for subject, resource, privileges in rows:
        text += ('[[grants]]\nsystem="ch-test"\nsubject=' + json.dumps(subject) + '\nresource='
                 + json.dumps(resource) + '\nprivs=' + json.dumps(privileges) + '\n')
    (root / 'intent.toml').write_text(text)


def config_at(root, resources=('table:analytics.events',)):
    p = root / 'config.toml'
    p.write_text('intent="intent.toml"\n[adapters.ch-test]\ntype="clickhouse"\n'
                 'url_env="GL_CH_UNUSED_READER"\nadmin_url_env="GL_CH_WRITER"\n'
                 'probe_url_envs={gl_user="GL_CH_UNUSED_PROBE"}\nread_timeout_seconds=3\n'
                 'clickhouse_write_tables=' + json.dumps(resources) + '\n')
    intent(root, [('gl_user', resources[0], ['SELECT'])])
    return p


def run(binary, config, endpoint, *, write=None, live=True, ok=True):
    env = dict(os.environ, GL_CH_UNUSED_READER=MARKER, GL_CH_UNUSED_PROBE=MARKER,
               HTTP_PROXY='http://127.0.0.1:1', HTTPS_PROXY='http://127.0.0.1:1', ALL_PROXY='http://127.0.0.1:1')
    env.pop('GL_CH_WRITER', None)
    if endpoint is not None:
        env['GL_CH_WRITER'] = endpoint
    args = [binary, '-c', str(config), 'apply', '--system', 'ch-test', '--json']
    if live:
        args += ['--live']
    if write is not None:
        args += ['--write']
        if write:
            args += ['--expect', write]
    r = subprocess.run(args, cwd='/', env=env, text=True, capture_output=True, timeout=12)
    assert MARKER not in r.stdout + r.stderr, 'credential escaped output'
    assert (r.returncode == 0) == ok, r.stderr
    return json.loads(r.stdout) if ok else r


def protocol(binary):
    base = [grant(subject='writer', database='analytics', table='events', grant_option=1)]
    s = dict(mode='normal', grants=copy.deepcopy(base), posts=[], gets=[])
    principals = [dict(name=n, id=str(uuid.uuid4()), storage='local_directory', kind='account') for n in ['writer', 'gl_user']]
    table = dict(database='analytics', name='events', id=str(uuid.uuid4()), engine='Memory', create_table_query='CREATE TABLE analytics.events(a UInt8) ENGINE=Memory')
    database = dict(name='analytics', id=str(uuid.uuid4()), engine='Atomic')
    server_id = str(uuid.uuid4())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path)
            params = urllib.parse.parse_qs(path.query)
            q = params.get('query', [''])[0]
            s['gets'].append(path.path)
            assert path.path == '/catalog/' and MARKER not in self.path
            assert self.headers.get('X-ClickHouse-User') == 'writer'
            assert self.headers.get('X-ClickHouse-Key') == MARKER
            assert params['readonly'] == ['2'] and params['max_rows_to_read'] == ['100000']
            assert params['result_overflow_mode'] == ['throw'] and params['max_execution_time'] == ['30']
            if s['posts'] and s['mode'] == 'post-failure':
                self.send_response(500)
                self.end_headers()
                self.wfile.write(MARKER.encode())
                return
            if q.startswith('CHECK GRANT'):
                rows = [dict(result=1)]
            elif q.startswith('SELECT currentUser()'):
                rows = [dict(login='writer', server_uuid=server_id, version='26.6.2.160')]
            elif 'FROM system.users' in q:
                rows = principals
            elif 'FROM system.role_grants' in q:
                rows = []
            elif 'FROM system.grants' in q:
                rows = s['grants']
            elif 'FROM system.tables' in q:
                rows = [table]
            elif 'FROM system.databases' in q:
                rows = [database]
            elif q.startswith('SHOW GRANTS'):
                rows = [dict(statement='GRANT SELECT ON analytics.events TO writer WITH GRANT OPTION')]
                if len(s['grants']) > 1:
                    rows.append(dict(statement='GRANT SELECT ON analytics.events TO gl_user'))
            else:
                raise AssertionError(q)
            body = encoded(rows)
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path)
            params = urllib.parse.parse_qs(path.query)
            q = self.rfile.read(int(self.headers['Content-Length'])).decode()
            s['posts'].append(q)
            assert path.path == '/catalog/' and 'query' not in params and MARKER not in self.path
            assert self.headers.get('X-ClickHouse-User') == 'writer' and self.headers.get('X-ClickHouse-Key') == MARKER
            assert params['readonly'] == ['0'] and params['wait_end_of_query'] == ['1']
            assert q == 'GRANT SELECT ON `analytics`.`events` TO `gl_user`;'
            if s['mode'] == 'timeout':
                time.sleep(4)
                return
            if s['mode'] in ['normal', 'post-failure', 'post-extra']:
                s['grants'].append(grant(subject='gl_user', database='analytics', table='events'))
            if s['mode'] == 'post-extra':
                s['grants'].append(grant(subject='writer', database='analytics', table='events', access_type='INSERT'))
            self.send_response(500 if s['mode'] == 'error' else 302 if s['mode'] == 'redirect' else 200)
            if s['mode'] == 'redirect':
                self.send_header('Location', '/leak')
            if s['mode'] == 'exception':
                self.send_header('X-ClickHouse-Exception-Code', '497')
            self.end_headers()
            if s['mode'] in ['error', 'exception', 'body-error']:
                self.wfile.write(MARKER.encode())

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    endpoint = f'http://writer:{MARKER}@127.0.0.1:{server.server_port}/catalog/'
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = config_at(root)
            for url in [None, 'invalid-' + MARKER, endpoint + '?bad=1', endpoint + '#bad', endpoint.replace('writer:', ':')]:
                run(binary, config, url, ok=False)
            run(binary, config, endpoint, live=False, ok=False)
            run(binary, config, endpoint, write='', ok=False)
            assert not s['gets'] and not s['posts'], 'missing live/write consent contacted server'
            for mode in ['normal', 'error', 'exception', 'body-error', 'redirect', 'timeout', 'ineffective', 'post-failure', 'post-extra']:
                s.update(mode=mode, grants=copy.deepcopy(base), posts=[], gets=[])
                p = run(binary, config, endpoint)
                assert p['changed'] and not p['applied'] and not p['effective_access_verified'] and p['single_statement_only']
                assert not s['posts']
                if mode == 'normal':
                    assert run(binary, config, endpoint, write=p['plan_id'])['applied']
                else:
                    before = time.monotonic()
                    failure = run(binary, config, endpoint, write=p['plan_id'], ok=False)
                    assert 'outcome unknown' in failure.stderr and time.monotonic() - before < 8
                assert len(s['posts']) == 1 and '/leak' not in s['gets'], 'write was retried, redirected or compensated'
            s.update(mode='normal', grants=copy.deepcopy(base), posts=[], gets=[])
            p = run(binary, config, endpoint)
            principals[1]['id'] = str(uuid.uuid4())
            run(binary, config, endpoint, write=p['plan_id'], ok=False)
            assert not s['posts']
            p = run(binary, config, endpoint)
            table['id'] = str(uuid.uuid4())
            run(binary, config, endpoint, write=p['plan_id'], ok=False)
            assert not s['posts']
            assert sorted(p.name for p in root.iterdir()) == ['config.toml', 'intent.toml']
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    print('ClickHouse writer HTTP: explicit credentials/live/expect, preview/one POST, row/byte/time bounds, stale IDs, errors/timeout/redirect/ineffective/post-check uncertainty, no retry/compensation and redaction passed')


def docker_test(binary, context):
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    info = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert info['Endpoints']['docker']['Host'].startswith('unix://'), 'requires local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-ch-writer-' + uuid.uuid4().hex[:12]

    def sql(query, user='default', ok=True):
        r = subprocess.run([*docker, 'exec', '-i', name, 'clickhouse-client', '--user', user, '--multiquery'], input=query, text=True, capture_output=True, timeout=20)
        assert (r.returncode == 0) == ok, r.stderr
        return r.stdout.strip()

    def acls():
        return sql('SELECT user_name,role_name,access_type,access_object,database,table,column,is_partial_revoke,grant_option FROM system.grants ORDER BY ALL FORMAT JSONEachRow')

    try:
        subprocess.run([*docker, 'run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::8123', '--memory', '2g', '--cpus', '2', '--ulimit', 'nofile=262144:262144', IMAGE], check=True, stdout=subprocess.DEVNULL)
        for _ in range(150):
            r = subprocess.run([*docker, 'exec', name, 'clickhouse-client', '--query', 'SELECT 1'], capture_output=True)
            if r.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError('Disposable ClickHouse failed to start')
        sql('''CREATE DATABASE analytics ENGINE=Atomic;
CREATE TABLE analytics.events(a UInt8) ENGINE=Memory;
INSERT INTO analytics.events VALUES(42);
CREATE TABLE analytics.sibling(a UInt8) ENGINE=MergeTree ORDER BY a;
CREATE TABLE analytics.denied(a UInt8) ENGINE=Memory;
CREATE VIEW analytics.v AS SELECT a FROM analytics.events;
CREATE USER gl_writer,gl_user,gl_other,gl_no_authority;
CREATE ROLE gl_group;
GRANT gl_group TO gl_user;
GRANT SHOW ACCESS,SHOW DATABASES ON *.* TO gl_writer,gl_no_authority;
GRANT SELECT ON system.users TO gl_writer,gl_no_authority;
GRANT SELECT ON system.roles TO gl_writer,gl_no_authority;
GRANT SELECT ON system.role_grants TO gl_writer,gl_no_authority;
GRANT SELECT ON system.grants TO gl_writer,gl_no_authority;
GRANT SELECT ON system.databases TO gl_writer,gl_no_authority;
GRANT SELECT ON system.tables TO gl_writer,gl_no_authority;
GRANT SELECT,INSERT ON analytics.events TO gl_writer WITH GRANT OPTION;
GRANT SELECT,INSERT ON analytics.sibling TO gl_writer WITH GRANT OPTION;
CREATE DATABASE `odd db` ENGINE=Atomic;
CREATE TABLE `odd db`.`odd\\`table`(a UInt8) ENGINE=Memory;
CREATE USER `odd\\`user`;
GRANT SELECT ON `odd db`.`odd\\`table` TO gl_writer WITH GRANT OPTION;
''')
        port = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']['8123/tcp'][0]['HostPort']
        endpoint = f'http://gl_writer:{MARKER}@127.0.0.1:{port}/'
        # no_password authentication accepts this harmless marker without publishing real credentials.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            resources = ('table:analytics.events', 'table:analytics.sibling', 'table:analytics.denied', 'table:odd db.odd`table')
            config = config_at(root, resources)
            def declare(rows, managed=('gl_user',)):
                kept = [('gl_user', 'role:gl_group', ['MEMBER'])] if 'gl_user' in managed else []
                intent(root, [*rows, *kept], managed=managed)

            baseline = acls()
            # One direct role ACL affects existing members; actual data access is checked separately.
            declare([('gl_group', resources[0], ['SELECT'])], managed=('gl_group',))
            p = run(binary, config, endpoint)
            assert len(p['changes']) == 1 and not p['applied'] and acls() == baseline
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            assert run(binary, config, endpoint, write=p['plan_id'])['applied']
            assert sql('SELECT a FROM analytics.events', user='gl_user') == '42'
            sql('SELECT a FROM analytics.sibling', user='gl_user', ok=False)
            no = run(binary, config, endpoint)
            assert not no['changed'] and not run(binary, config, endpoint, write=no['plan_id'])['applied']
            run(binary, config, endpoint, write=p['plan_id'], ok=False)
            declare([], managed=('gl_group',))
            inverse = run(binary, config, endpoint)
            assert run(binary, config, endpoint, write=inverse['plan_id'])['applied'] and acls() == baseline
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            # INSERT is independent from SELECT; no expansion to sibling tables.
            declare([('gl_user', resources[0], ['INSERT'])])
            p = run(binary, config, endpoint)
            run(binary, config, endpoint, write=p['plan_id'])
            sql('INSERT INTO analytics.events VALUES(43)', user='gl_user')
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            sql('INSERT INTO analytics.sibling VALUES(43)', user='gl_user', ok=False)
            declare([])
            p = run(binary, config, endpoint)
            run(binary, config, endpoint, write=p['plan_id'])
            sql('INSERT INTO analytics.events VALUES(44)', user='gl_user', ok=False)
            assert acls() == baseline
            # UUID/ACL/source/session and same-name object recreation invalidate review.
            for kind in ['table', 'subject', 'ddl', 'role', 'acl', 'authority', 'config', 'intent', 'session']:
                declare([('gl_user', resources[0], ['SELECT'])])
                original_config = config.read_bytes()
                original_intent = (root / 'intent.toml').read_bytes()
                p = run(binary, config, endpoint)
                if kind == 'table':
                    sql('DROP TABLE analytics.events SYNC; CREATE TABLE analytics.events(a UInt8) ENGINE=Memory')
                elif kind == 'subject':
                    sql('REVOKE gl_group FROM gl_user; DROP USER gl_user; CREATE USER gl_user; GRANT gl_group TO gl_user')
                elif kind == 'ddl':
                    sql('ALTER TABLE analytics.events ADD COLUMN b UInt8')
                elif kind == 'role':
                    sql('CREATE ROLE temporary_role')
                elif kind == 'acl':
                    sql('GRANT SELECT ON analytics.sibling TO gl_other')
                elif kind == 'authority':
                    sql('REVOKE GRANT OPTION FOR SELECT ON analytics.events FROM gl_writer')
                elif kind == 'config':
                    config.write_text(config.read_text() + '\n# changed\n')
                elif kind == 'intent':
                    (root / 'intent.toml').write_text((root / 'intent.toml').read_text() + '\n# changed\n')
                snapshot = acls()
                active = endpoint.replace('gl_writer:', 'gl_no_authority:') if kind == 'session' else endpoint
                run(binary, config, active, write=p['plan_id'], ok=False)
                assert acls() == snapshot, kind
                config.write_bytes(original_config)
                (root / 'intent.toml').write_bytes(original_intent)
                if kind == 'ddl':
                    sql('ALTER TABLE analytics.events DROP COLUMN b')
                elif kind == 'role':
                    sql('DROP ROLE temporary_role')
                elif kind == 'acl':
                    sql('REVOKE SELECT ON analytics.sibling FROM gl_other')
                elif kind == 'authority':
                    sql('GRANT SELECT ON analytics.events TO gl_writer WITH GRANT OPTION')
            # Unsupported plans never write; direct broad/delegated/column/partial ACLs refuse.
            for subject, resource, privileges in [('gl_user', 'db:analytics', ['SELECT']), ('gl_user', resources[0], ['ALL']), ('gl_user', resources[0], ['ALTER']), ('gl_user', 'table:analytics.*', ['SELECT']), ('missing', resources[0], ['SELECT']), ('default', resources[0], ['SELECT']), ('gl_writer', resources[0], ['SELECT']), ('gl_user', 'table:system.users', ['SELECT']), ('gl_user', 'table:analytics.missing', ['SELECT'])]:
                declare([(subject, resource, privileges)], managed=(subject,))
                snapshot = acls()
                run(binary, config, endpoint, ok=False)
                assert acls() == snapshot
            declare([('gl_user', resources[0], ['SELECT', 'INSERT'])])
            failure = run(binary, config, endpoint, ok=False)
            assert 'at most one change' in failure.stderr
            declare([('gl_user', resources[0], ['SELECT'])])
            configured = config.read_text()
            config.write_text(configured.replace('clickhouse_write_tables=' + json.dumps(resources), 'clickhouse_write_tables=[]'))
            run(binary, config, endpoint, ok=False)
            config.write_text(configured)
            for setup, cleanup in [('GRANT SELECT ON analytics.* TO gl_user', 'REVOKE SELECT ON analytics.* FROM gl_user'), ('GRANT SELECT(a) ON analytics.events TO gl_user', 'REVOKE SELECT(a) ON analytics.events FROM gl_user'), ('GRANT SELECT ON analytics.events TO gl_user WITH GRANT OPTION', 'REVOKE SELECT ON analytics.events FROM gl_user'), ('GRANT SELECT ON analytics.* TO gl_user; REVOKE SELECT ON analytics.events FROM gl_user', 'REVOKE SELECT ON analytics.* FROM gl_user')]:
                sql(setup)
                snapshot = acls()
                run(binary, config, endpoint, ok=False)
                assert acls() == snapshot
                sql(cleanup)
            declare([('gl_user', 'table:analytics.denied', ['SELECT'])])
            failure = run(binary, config, endpoint, ok=False)
            assert 'GRANT OPTION' in failure.stderr
            # A recipient role in the writer's ancestry cannot mutate writer authority.
            sql('CREATE ROLE writer_parent; GRANT writer_parent TO gl_writer')
            declare([('writer_parent', resources[0], ['SELECT'])], managed=('writer_parent',))
            run(binary, config, endpoint, ok=False)
            sql('REVOKE writer_parent FROM gl_writer; DROP ROLE writer_parent')
            # Retain existing memberships, but a plan to revoke one cannot reach SQL.
            intent(root, [], managed=('gl_user',))
            run(binary, config, endpoint, ok=False)
            declare([('gl_user', resources[0], ['SELECT'])])
            saved_config = config.read_text()
            config.write_text(saved_config.replace('clickhouse_write_tables=' + json.dumps(resources), 'clickhouse_write_tables=["table:analytics.v"]'))
            intent(root, [('gl_user', 'table:analytics.v', ['SELECT'])])
            run(binary, config, endpoint, ok=False)
            config.write_text(saved_config)
            sql('CREATE ROLE gl_user')
            run(binary, config, endpoint, ok=False)
            sql('DROP ROLE gl_user')
            declare([('gl_user', resources[0], ['SELECT'])])
            sql('CREATE ROLE authority_role; GRANT SELECT ON analytics.events TO authority_role WITH GRANT OPTION; GRANT authority_role TO gl_no_authority')
            run(binary, config, endpoint.replace('gl_writer:', 'gl_no_authority:'), ok=False)
            sql('REVOKE authority_role FROM gl_no_authority; DROP ROLE authority_role')
            # A server-side read-only profile rejects POST after a valid read-only preview.
            sql('ALTER USER gl_writer SETTINGS readonly=2')
            p = run(binary, config, endpoint)
            snapshot = acls()
            failure = run(binary, config, endpoint, write=p['plan_id'], ok=False)
            assert 'outcome unknown' in failure.stderr and acls() == snapshot
            sql('ALTER USER gl_writer SETTINGS readonly=0')
            declare([('odd`user', resources[3], ['SELECT'])], managed=('odd`user',))
            p = run(binary, config, endpoint)
            assert p['changes'][0]['cmd'] == 'GRANT SELECT ON `odd db`.`odd\\`table` TO `odd\\`user`;'
            run(binary, config, endpoint, write=p['plan_id'])
            declare([], managed=('odd`user',))
            p = run(binary, config, endpoint)
            run(binary, config, endpoint, write=p['plan_id'])
            assert acls() == baseline
            assert sorted(p.name for p in root.iterdir()) == ['config.toml', 'intent.toml']
            print('ClickHouse writer server version:', sql('SELECT version()'))
            print('ClickHouse writer Docker: one SELECT/INSERT grant/revoke/inverse, role member SELECT, scoped actual INSERT/denials, quoted SQL, no-op, stale UUID/DDL/ACL/source/session, authority/unsafe shapes/ancestry/default-off/multi-change refusal passed')
    finally:
        subprocess.run([*docker, 'stop', name], capture_output=True, timeout=30, check=False)


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
