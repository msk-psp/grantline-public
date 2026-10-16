#!/usr/bin/env python3
"""Canonical ClickHouse memberships: exact inverse, propagation and refusal."""
import argparse
import json
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from check_rust_clickhouse import IMAGE, MARKER, ROOT
from check_rust_clickhouse_writer import config_at, intent, protocol, run


def docker_test(binary, context):
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    info = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert info['Endpoints']['docker']['Host'].startswith('unix://'), 'requires local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-ch-member-' + uuid.uuid4().hex[:12]

    def sql(query, user='default', ok=True):
        r = subprocess.run([*docker, 'exec', '-i', name, 'clickhouse-client', '--user', user, '--multiquery'], input=query, text=True, capture_output=True, timeout=20)
        assert (r.returncode == 0) == ok, r.stderr
        return r.stdout.strip()

    def snapshot():
        return tuple(sql(q + ' ORDER BY ALL LIMIT 10001 FORMAT JSONEachRow SETTINGS max_execution_time=10,max_rows_to_read=100000') for q in [
            'SELECT user_name,role_name,access_type,access_object,database,table,column,is_partial_revoke,grant_option FROM system.grants',
            'SELECT user_name,role_name,granted_role_name,granted_role_id,granted_role_is_default,with_admin_option FROM system.role_grants',
            'SELECT name,default_roles_all,default_roles_list,default_roles_except,grantees_any,grantees_list,grantees_except FROM system.users',
        ])

    try:
        subprocess.run([*docker, 'run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::8123', '--memory', '2g', '--cpus', '2', '--ulimit', 'nofile=262144:262144', IMAGE], check=True, stdout=subprocess.DEVNULL)
        for _ in range(150):
            if subprocess.run([*docker, 'exec', name, 'clickhouse-client', '--query', 'SELECT 1'], capture_output=True).returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError('Disposable ClickHouse failed to start')
        sql(r'''CREATE DATABASE analytics ENGINE=Atomic; CREATE DATABASE outside ENGINE=Atomic;
CREATE TABLE analytics.events(a UInt8) ENGINE=Memory; INSERT INTO analytics.events VALUES(42);
CREATE TABLE outside.keep(a UInt8) ENGINE=Memory; INSERT INTO outside.keep VALUES(99);
CREATE USER gl_writer,gl_other_writer,gl_user,gl_other,gl_disabled,`odd\`user`;
ALTER USER gl_disabled DEFAULT ROLE NONE;
CREATE ROLE gl_reader,gl_leaf,gl_db_reader,gl_insert,gl_holder,gl_plain,gl_bad,`odd\`role`;
GRANT SELECT ON analytics.events TO gl_leaf;
GRANT SELECT ON analytics.* TO gl_db_reader;
GRANT gl_leaf TO gl_reader;
GRANT INSERT ON analytics.events TO gl_insert;
GRANT SELECT ON analytics.events TO `odd\`role`;
GRANT ROLE ADMIN ON *.* TO gl_bad;
GRANT gl_holder TO gl_user;
GRANT SELECT ON outside.keep TO gl_other;
GRANT SHOW ACCESS,SHOW DATABASES ON *.* TO gl_writer,gl_other_writer;
GRANT SELECT ON system.users TO gl_writer,gl_other_writer;
GRANT SELECT ON system.roles TO gl_writer,gl_other_writer;
GRANT SELECT ON system.role_grants TO gl_writer,gl_other_writer;
GRANT SELECT ON system.grants TO gl_writer,gl_other_writer;
GRANT SELECT ON system.databases TO gl_writer,gl_other_writer;
GRANT SELECT ON system.tables TO gl_writer,gl_other_writer;
GRANT gl_reader,gl_db_reader,gl_insert,gl_plain,gl_bad,`odd\`role` TO gl_writer WITH ADMIN OPTION;
''')
        port = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']['8123/tcp'][0]['HostPort']
        endpoint = f'http://gl_writer:{MARKER}@127.0.0.1:{port}/'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            roles = ('gl_reader', 'gl_db_reader', 'gl_insert', 'gl_plain', 'gl_bad', 'odd`role')
            config = config_at(root, (), roles=roles)

            def declare(rows, managed=('gl_user',)):
                kept = [('gl_user', 'role:gl_holder', ['MEMBER'])] if 'gl_user' in managed else []
                intent(root, [*kept, *rows], managed=managed)

            def change(rows, managed=('gl_user',)):
                declare(rows, managed)
                p = run(binary, config, endpoint)
                assert p['changed'] and not p['applied'] and p['single_statement_only']
                assert p['membership_changes_affect_dependants'] and not p['effective_access_verified']
                assert not p['database_changes_include_future_tables']
                a = run(binary, config, endpoint, write=p['plan_id'])
                assert a['applied'] and a['changes'] == p['changes']
                return p

            def refuse(rows, managed=('gl_user',), active=None):
                declare(rows, managed)
                before = snapshot()
                try:
                    run(binary, config, active or endpoint, ok=False)
                except AssertionError as error:
                    raise AssertionError(f'Expected refusal for {rows}: {error}') from error
                assert snapshot() == before

            baseline = snapshot()
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            p = change([('gl_user', 'role:gl_reader', ['MEMBER'])])
            assert p['changes'][0]['cmd'] == 'GRANT `gl_reader` TO `gl_user`;'
            assert sql('SELECT a FROM analytics.events', user='gl_user') == '42'
            sql('SELECT a FROM outside.keep', user='gl_user', ok=False)
            assert sql('SELECT a FROM outside.keep', user='gl_other') == '99'
            sql('INSERT INTO analytics.events VALUES(43)', user='gl_user', ok=False)
            noop = run(binary, config, endpoint)
            assert not noop['changed'] and not run(binary, config, endpoint, write=noop['plan_id'])['applied']
            run(binary, config, endpoint, write=p['plan_id'], ok=False)
            revoke = change([])
            assert revoke['changes'][0]['cmd'] == 'REVOKE `gl_reader` FROM `gl_user`;'
            assert snapshot() == baseline
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            # Inverse of a revoke is separately reviewed and restores its exact row/policies.
            change([('gl_user', 'role:gl_reader', ['MEMBER'])])
            granted = snapshot()
            change([])
            change([('gl_user', 'role:gl_reader', ['MEMBER'])])
            assert snapshot() == granted
            change([])
            assert snapshot() == baseline
            # A role recipient propagates through a retained role-to-account edge.
            change([('gl_holder', 'role:gl_reader', ['MEMBER'])], managed=('gl_holder',))
            assert sql('SELECT a FROM analytics.events', user='gl_user') == '42'
            change([], managed=('gl_holder',))
            assert snapshot() == baseline
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            # Removing one direct membership does not erase a retained alternative path.
            sql('GRANT gl_reader TO gl_holder')
            alternate = snapshot()
            change([('gl_user', 'role:gl_reader', ['MEMBER'])])
            change([])
            assert snapshot() == alternate
            assert sql('SELECT a FROM analytics.events', user='gl_user') == '42'
            sql('REVOKE gl_reader FROM gl_holder')
            # Membership covers future privileges on the allowlisted role, not frozen objects.
            change([('gl_user', 'role:gl_reader', ['MEMBER'])])
            sql('CREATE TABLE analytics.future(a UInt8) ENGINE=Memory; INSERT INTO analytics.future VALUES(43); GRANT SELECT ON analytics.future TO gl_reader')
            assert sql('SELECT a FROM analytics.future', user='gl_user') == '43'
            change([])
            sql('SELECT a FROM analytics.future', user='gl_user', ok=False)
            sql('REVOKE SELECT ON analytics.future FROM gl_reader; DROP TABLE analytics.future SYNC')
            assert snapshot() == baseline
            # A DB-wide role covers future relations without object-writer allowlists.
            change([('gl_user', 'role:gl_db_reader', ['MEMBER'])])
            sql('CREATE TABLE analytics.db_future(a UInt8) ENGINE=Memory; INSERT INTO analytics.db_future VALUES(47)')
            assert sql('SELECT a FROM analytics.db_future', user='gl_user') == '47'
            change([])
            sql('SELECT a FROM analytics.db_future', user='gl_user', ok=False)
            sql('DROP TABLE analytics.db_future SYNC')
            assert snapshot() == baseline
            change([('gl_user', 'role:gl_insert', ['MEMBER'])])
            sql('INSERT INTO analytics.events VALUES(44)', user='gl_user')
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            change([])
            sql('INSERT INTO analytics.events VALUES(45)', user='gl_user', ok=False)
            assert sql('SELECT sum(a) FROM analytics.events') == '86', 'inverse never restores data'
            assert snapshot() == baseline
            change([('odd`user', 'role:odd`role', ['MEMBER'])], managed=('odd`user',))
            assert sql('SELECT sum(a) FROM analytics.events', user='odd`user') == '86'
            change([], managed=('odd`user',))
            assert snapshot() == baseline
            # Every review binds identity UUIDs, role privileges, options and policy bytes.
            for kind in ['role-uuid', 'user-uuid', 'role-acl', 'unrelated-acl', 'edge', 'default', 'grantees', 'admin', 'config', 'intent', 'session']:
                declare([('gl_user', 'role:gl_reader', ['MEMBER'])])
                config_bytes = config.read_bytes()
                intent_bytes = (root / 'intent.toml').read_bytes()
                p = run(binary, config, endpoint)
                if kind == 'role-uuid':
                    sql('DROP ROLE gl_reader; CREATE ROLE gl_reader; GRANT gl_leaf TO gl_reader; GRANT gl_reader TO gl_writer WITH ADMIN OPTION')
                elif kind == 'user-uuid':
                    sql('DROP USER gl_user; CREATE USER gl_user; GRANT gl_holder TO gl_user')
                elif kind == 'role-acl':
                    sql('GRANT INSERT ON analytics.events TO gl_reader')
                elif kind == 'unrelated-acl':
                    sql('GRANT INSERT ON outside.keep TO gl_other')
                elif kind == 'edge':
                    sql('GRANT gl_plain TO gl_other')
                elif kind == 'default':
                    sql('ALTER USER gl_user DEFAULT ROLE NONE')
                elif kind == 'grantees':
                    sql('ALTER USER gl_writer GRANTEES NONE')
                elif kind == 'admin':
                    sql('REVOKE ADMIN OPTION FOR gl_reader FROM gl_writer')
                elif kind == 'config':
                    config.write_text(config.read_text() + '\n# changed\n')
                elif kind == 'intent':
                    (root / 'intent.toml').write_text((root / 'intent.toml').read_text() + '\n# changed\n')
                before = snapshot()
                active = endpoint.replace('gl_writer:', 'gl_other_writer:') if kind == 'session' else endpoint
                run(binary, config, active, write=p['plan_id'], ok=False)
                assert snapshot() == before, kind
                config.write_bytes(config_bytes)
                (root / 'intent.toml').write_bytes(intent_bytes)
                undo = {'role-acl': 'REVOKE INSERT ON analytics.events FROM gl_reader', 'unrelated-acl': 'REVOKE INSERT ON outside.keep FROM gl_other', 'edge': 'REVOKE gl_plain FROM gl_other', 'default': 'ALTER USER gl_user DEFAULT ROLE ALL', 'grantees': 'ALTER USER gl_writer GRANTEES ANY', 'admin': 'GRANT gl_reader TO gl_writer WITH ADMIN OPTION'}
                if kind in undo:
                    sql(undo[kind])
            baseline = snapshot()
            # Direct ADMIN only: neither inherited ADMIN nor global ROLE ADMIN substitutes.
            sql('GRANT gl_reader TO gl_plain WITH ADMIN OPTION; GRANT gl_plain TO gl_other_writer')
            refuse([('gl_user', 'role:gl_reader', ['MEMBER'])], active=endpoint.replace('gl_writer:', 'gl_other_writer:'))
            sql('REVOKE gl_plain FROM gl_other_writer; REVOKE gl_reader FROM gl_plain; GRANT ROLE ADMIN ON *.* TO gl_other_writer')
            refuse([('gl_user', 'role:gl_reader', ['MEMBER'])], active=endpoint.replace('gl_writer:', 'gl_other_writer:'))
            sql('REVOKE ROLE ADMIN ON *.* FROM gl_other_writer')
            # Existing ADMIN/default options cannot silently be normalized by MEMBER.
            sql('GRANT gl_reader TO gl_user WITH ADMIN OPTION')
            refuse([], managed=('gl_user',))
            refuse([('gl_user', 'role:gl_reader', ['MEMBER'])])
            sql('REVOKE gl_reader FROM gl_user; ALTER USER gl_user DEFAULT ROLE gl_holder')
            refuse([('gl_user', 'role:gl_reader', ['MEMBER'])])
            sql('ALTER USER gl_user DEFAULT ROLE ALL EXCEPT gl_reader')
            refuse([('gl_user', 'role:gl_reader', ['MEMBER'])])
            sql('ALTER USER gl_user DEFAULT ROLE ALL')
            refuse([('gl_disabled', 'role:gl_reader', ['MEMBER'])], managed=('gl_disabled',))
            # Unsafe ancestor privileges/options are rejected as well as direct role ACLs.
            for extra, undo in [('GRANT SELECT ON *.* TO gl_leaf', 'REVOKE SELECT ON *.* FROM gl_leaf; GRANT SELECT ON analytics.events TO gl_leaf'), ('GRANT SELECT ON analytics.events TO gl_leaf WITH GRANT OPTION', 'REVOKE GRANT OPTION FOR SELECT ON analytics.events FROM gl_leaf'), ('GRANT gl_leaf TO gl_reader WITH ADMIN OPTION', 'REVOKE ADMIN OPTION FOR gl_leaf FROM gl_reader')]:
                sql(extra)
                refuse([('gl_user', 'role:gl_reader', ['MEMBER'])])
                sql(undo)
            for subject, role in [('gl_user', 'gl_bad'), ('gl_writer', 'gl_reader'), ('gl_reader', 'gl_reader'), ('gl_leaf', 'gl_reader'), ('default', 'gl_reader'), ('missing', 'gl_reader'), ('gl_user', 'gl_leaf'), ('gl_user', 'missing'), ('gl_user', '*')]:
                refuse([(subject, 'role:' + role, ['MEMBER'])], managed=(subject,))
            for bad in [(), ('*',), ('role:gl_reader',), ('gl_user',)]:
                config_at(root, (), roles=bad or ('placeholder',))
                if not bad:
                    config.write_text(config.read_text().replace('["placeholder"]', '[]'))
                refuse([('gl_user', 'role:' + (bad[0] if bad else 'gl_reader'), ['MEMBER'])])
            config_at(root, (), roles=roles)
            refuse([('gl_user', 'role:gl_reader', ['ADMIN'])])
            refuse([('gl_user', 'role:gl_reader', ['MEMBER']), ('gl_user', 'role:gl_insert', ['MEMBER'])])
            config_at(root, ('table:analytics.events',), roles=roles)
            sql('GRANT SELECT ON analytics.events TO gl_writer WITH GRANT OPTION')
            refuse([('gl_user', 'role:gl_reader', ['MEMBER']), ('gl_user', 'table:analytics.events', ['SELECT'])])
            sql('REVOKE SELECT ON analytics.events FROM gl_writer')
            assert snapshot() == baseline
            print('ClickHouse membership server version:', sql('SELECT version()'))
            print('ClickHouse memberships: account/role/nested/quoted grant, revoke and both reviewed inverses, SELECT/INSERT/denial, retained and future privileges, residual paths and data preservation, full raw catalog equality; stale identities/ACLs/edges/policies/inputs/session and unsafe/default-off/admin/cycle/multi-change refusal passed')
    finally:
        subprocess.run([*docker, 'stop', name], capture_output=True, timeout=30, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'rust/target/debug/grantline-rs')
    parser.add_argument('--docker', action='store_true')
    parser.add_argument('--docker-context')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    protocol(binary, membership_scope=True)
    if args.docker:
        docker_test(binary, args.docker_context)


if __name__ == '__main__':
    main()
