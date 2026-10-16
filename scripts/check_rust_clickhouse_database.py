#!/usr/bin/env python3
"""Explicit single ClickHouse DB ACLs: future objects, exact state and refusal."""
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
    name = 'grantline-ch-db-' + uuid.uuid4().hex[:12]

    def sql(query, user='default', ok=True):
        r = subprocess.run([*docker, 'exec', '-i', name, 'clickhouse-client', '--user', user, '--multiquery'], input=query, text=True, capture_output=True, timeout=20)
        assert (r.returncode == 0) == ok, r.stderr
        return r.stdout.strip()

    def acls():
        return sql('SELECT user_name,role_name,access_type,access_object,database,table,column,is_partial_revoke,grant_option FROM system.grants ORDER BY ALL FORMAT JSONEachRow')

    try:
        subprocess.run([*docker, 'run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::8123', '--memory', '2g', '--cpus', '2', '--ulimit', 'nofile=262144:262144', IMAGE], check=True, stdout=subprocess.DEVNULL)
        for _ in range(150):
            if subprocess.run([*docker, 'exec', name, 'clickhouse-client', '--query', 'SELECT 1'], capture_output=True).returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError('Disposable ClickHouse failed to start')
        sql(r'''CREATE DATABASE analytics ENGINE=Atomic; CREATE DATABASE outside ENGINE=Atomic;
CREATE DATABASE empty_db ENGINE=Atomic; CREATE DATABASE no_authority ENGINE=Atomic;
CREATE DATABASE `odd\`db` ENGINE=Atomic;
CREATE TABLE analytics.events(a UInt8) ENGINE=Memory;
INSERT INTO analytics.events VALUES(42);
CREATE TABLE analytics.more(a UInt8) ENGINE=MergeTree ORDER BY a;
CREATE VIEW analytics.current_view AS SELECT a FROM analytics.events;
CREATE TABLE outside.keep(a UInt8) ENGINE=Memory;
CREATE TABLE outside.denied(a UInt8) ENGINE=Memory;
INSERT INTO outside.keep VALUES(99);
CREATE TABLE `odd\`db`.`odd\`table`(a UInt8) ENGINE=Memory;
INSERT INTO `odd\`db`.`odd\`table` VALUES(42);
CREATE USER gl_writer,gl_table_writer,gl_user,gl_other,`odd\`user`;
CREATE ROLE gl_group; GRANT gl_group TO gl_user;
GRANT SELECT ON outside.keep TO gl_user;
GRANT SHOW ACCESS,SHOW DATABASES ON *.* TO gl_writer,gl_table_writer;
GRANT SELECT ON system.users TO gl_writer,gl_table_writer;
GRANT SELECT ON system.roles TO gl_writer,gl_table_writer;
GRANT SELECT ON system.role_grants TO gl_writer,gl_table_writer;
GRANT SELECT ON system.grants TO gl_writer,gl_table_writer;
GRANT SELECT ON system.databases TO gl_writer,gl_table_writer;
GRANT SELECT ON system.tables TO gl_writer,gl_table_writer;
GRANT SELECT,INSERT ON analytics.* TO gl_writer WITH GRANT OPTION;
GRANT SELECT,INSERT ON empty_db.* TO gl_writer WITH GRANT OPTION;
GRANT SELECT ON `odd\`db`.* TO gl_writer WITH GRANT OPTION;
GRANT SELECT ON analytics.events TO gl_table_writer WITH GRANT OPTION;
''')
        port = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']['8123/tcp'][0]['HostPort']
        endpoint = f'http://gl_writer:{MARKER}@127.0.0.1:{port}/'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tables = ('table:outside.keep',)
            dbs = ('db:analytics', 'db:empty_db', 'db:odd`db', 'db:no_authority')
            config = config_at(root, tables, databases=dbs)
            configured = config.read_text()
            kept = [('gl_user', 'table:outside.keep', ['SELECT']), ('gl_user', 'role:gl_group', ['MEMBER'])]

            def declare(rows, managed=('gl_user',)):
                intent(root, [*rows, *(kept if 'gl_user' in managed else [])], managed=managed)

            def apply(rows, managed=('gl_user',)):
                declare(rows, managed)
                p = run(binary, config, endpoint)
                assert len(p['changes']) == 1 and p['database_changes_include_future_tables']
                assert not p['applied'] and not p['effective_access_verified'] and p['single_statement_only']
                assert run(binary, config, endpoint, write=p['plan_id'])['applied']
                return p

            baseline = acls()
            declare([('gl_user', 'db:analytics', ['SELECT'])])
            p = run(binary, config, endpoint)
            assert p['changes'][0]['cmd'] == 'GRANT SELECT ON `analytics`.* TO `gl_user`;'
            assert p['database_changes_include_future_tables'] and acls() == baseline
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            run(binary, config, endpoint, write=p['plan_id'])
            assert sql('SELECT a FROM analytics.events', user='gl_user') == '42'
            assert sql('SELECT a FROM analytics.current_view', user='gl_user') == '42'
            assert sql('SELECT a FROM outside.keep', user='gl_user') == '99'
            sql('SELECT a FROM outside.denied', user='gl_user', ok=False)
            sql('SELECT * FROM system.users', user='gl_user', ok=False)
            sql('CREATE TABLE analytics.future(a UInt8) ENGINE=Memory; INSERT INTO analytics.future VALUES(43)')
            assert sql('SELECT a FROM analytics.future', user='gl_user') == '43'
            no = run(binary, config, endpoint)
            assert not no['changed'] and not no['database_changes_include_future_tables']
            assert not run(binary, config, endpoint, write=no['plan_id'])['applied']
            run(binary, config, endpoint, write=p['plan_id'], ok=False)
            apply([])
            assert acls() == baseline
            sql('SELECT a FROM analytics.future', user='gl_user', ok=False)
            sql('CREATE TABLE analytics.after_inverse(a UInt8) ENGINE=Memory')
            sql('SELECT a FROM analytics.after_inverse', user='gl_user', ok=False)
            # An ordinary empty DB authorizes future tables too, rather than an empty read scope.
            apply([('gl_user', 'db:empty_db', ['SELECT'])])
            sql('CREATE TABLE empty_db.future(a UInt8) ENGINE=Memory; INSERT INTO empty_db.future VALUES(42)')
            assert sql('SELECT a FROM empty_db.future', user='gl_user') == '42'
            apply([])
            sql('SELECT a FROM empty_db.future', user='gl_user', ok=False)
            # INSERT neither adds SELECT nor writes outside the named DB; revoke keeps data.
            apply([('gl_user', 'db:analytics', ['INSERT'])])
            sql('INSERT INTO analytics.events VALUES(44); INSERT INTO analytics.more VALUES(45)', user='gl_user')
            sql('CREATE TABLE analytics.insert_future(a UInt8) ENGINE=Memory')
            sql('INSERT INTO analytics.insert_future VALUES(46)', user='gl_user')
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            sql('INSERT INTO outside.keep VALUES(47)', user='gl_user', ok=False)
            apply([])
            sql('INSERT INTO analytics.events VALUES(48)', user='gl_user', ok=False)
            assert sql('SELECT a FROM analytics.insert_future') == '46' and acls() == baseline
            # Role ACL propagation is real, while removing a direct edge leaves alternate paths.
            apply([('gl_group', 'db:analytics', ['SELECT'])], managed=('gl_group',))
            assert sql('SELECT count() FROM analytics.events', user='gl_user') == '2'
            apply([], managed=('gl_group',))
            sql('SELECT a FROM analytics.events', user='gl_user', ok=False)
            apply([('gl_user', 'db:analytics', ['SELECT'])])
            sql('GRANT SELECT ON analytics.* TO gl_group')
            apply([])
            assert sql('SELECT count() FROM analytics.events', user='gl_user') == '2'
            sql('REVOKE SELECT ON analytics.* FROM gl_group')
            assert acls() == baseline
            apply([('odd`user', 'db:odd`db', ['SELECT'])], managed=('odd`user',))
            assert sql(r'SELECT a FROM `odd\`db`.`odd\`table`', user='odd`user') == '42'
            apply([], managed=('odd`user',))
            assert acls() == baseline

            for kind in ['db-uuid', 'table-create', 'table-recreate', 'table-ddl', 'view-create', 'acl', 'config', 'intent', 'session']:
                declare([('gl_user', 'db:empty_db' if kind == 'db-uuid' else 'db:analytics', ['SELECT'])])
                p = run(binary, config, endpoint)
                config_bytes, intent_bytes = config.read_bytes(), (root / 'intent.toml').read_bytes()
                if kind == 'db-uuid':
                    sql('DROP DATABASE empty_db SYNC; CREATE DATABASE empty_db ENGINE=Atomic')
                elif kind == 'table-create':
                    sql('CREATE TABLE analytics.new_during(a UInt8) ENGINE=Memory')
                elif kind == 'table-recreate':
                    sql('DROP TABLE analytics.after_inverse SYNC; CREATE TABLE analytics.after_inverse(a UInt8) ENGINE=Memory')
                elif kind == 'table-ddl':
                    sql('ALTER TABLE analytics.events ADD COLUMN b UInt8')
                elif kind == 'view-create':
                    sql('CREATE VIEW analytics.view_during AS SELECT a FROM analytics.events')
                elif kind == 'acl':
                    sql('GRANT SELECT ON analytics.events TO gl_other')
                elif kind == 'config':
                    config.write_text(config.read_text() + '\n# changed\n')
                elif kind == 'intent':
                    (root / 'intent.toml').write_text((root / 'intent.toml').read_text() + '\n# changed\n')
                snapshot = acls()
                active = endpoint.replace('gl_writer:', 'gl_table_writer:') if kind == 'session' else endpoint
                run(binary, config, active, write=p['plan_id'], ok=False)
                assert acls() == snapshot, kind
                config.write_bytes(config_bytes)
                (root / 'intent.toml').write_bytes(intent_bytes)
                if kind == 'table-create':
                    sql('DROP TABLE analytics.new_during SYNC')
                elif kind == 'view-create':
                    sql('DROP VIEW analytics.view_during SYNC')
                elif kind == 'table-ddl':
                    sql('ALTER TABLE analytics.events DROP COLUMN b')
                elif kind == 'acl':
                    sql('REVOKE SELECT ON analytics.events FROM gl_other')
            # Scope opt-ins are independent; broadening/narrowing must not coalesce held ACLs.
            config.write_text(configured.replace('clickhouse_write_databases=' + json.dumps(dbs), 'clickhouse_write_databases=[]'))
            declare([('gl_user', 'db:analytics', ['SELECT'])])
            run(binary, config, endpoint, ok=False)
            config.write_text(configured)
            declare([('gl_user', 'table:analytics.events', ['SELECT'])])
            run(binary, config, endpoint, ok=False)
            declare([('gl_user', 'db:analytics', ['SELECT'])])
            run(binary, config, endpoint.replace('gl_writer:', 'gl_table_writer:'), ok=False)
            for setup, cleanup in [
                    ('GRANT SELECT ON analytics.events TO gl_user', 'REVOKE SELECT ON analytics.events FROM gl_user'),
                    ('GRANT SELECT ON analytics.* TO gl_user; REVOKE SELECT ON analytics.events FROM gl_user', 'REVOKE SELECT ON analytics.* FROM gl_user'),
                    ('GRANT SELECT ON analytics.* TO gl_user WITH GRANT OPTION', 'REVOKE SELECT ON analytics.* FROM gl_user'),
                    ('GRANT SELECT ON *.* TO gl_user', 'REVOKE SELECT ON *.* FROM gl_user')]:
                sql(setup)
                snapshot = acls()
                run(binary, config, endpoint, ok=False)
                assert acls() == snapshot
                sql(cleanup)
                # A global revoke removes the retained grant too; restore it explicitly.
                sql('GRANT SELECT ON outside.keep TO gl_user')
            sql('GRANT SELECT ON analytics.* TO gl_user')
            config.write_text(configured.replace('clickhouse_write_tables=' + json.dumps(tables), 'clickhouse_write_tables=["table:outside.keep","table:analytics.events"]'))
            declare([('gl_user', 'table:analytics.events', ['SELECT'])])
            snapshot = acls()
            failure = run(binary, config, endpoint, ok=False)
            assert 'Overlapping' in failure.stderr and acls() == snapshot
            sql('REVOKE SELECT ON analytics.* FROM gl_user')
            config.write_text(configured)
            for subject, resource, privileges in [('gl_user', 'db:analytics*', ['SELECT']), ('gl_user', 'global:*', ['SELECT']), ('gl_user', 'db:system', ['SELECT']), ('gl_user', 'db:analytics', ['ALL']), ('gl_user', 'db:missing', ['SELECT']), ('gl_writer', 'db:analytics', ['SELECT']), ('gl_user', 'db:no_authority', ['SELECT'])]:
                declare([(subject, resource, privileges)], managed=(subject,))
                snapshot = acls()
                run(binary, config, endpoint, ok=False)
                assert acls() == snapshot
            declare([('gl_user', 'db:analytics', ['SELECT', 'INSERT'])])
            failure = run(binary, config, endpoint, ok=False)
            assert 'at most one' in failure.stderr
            assert acls() == baseline
            assert sorted(p.name for p in root.iterdir()) == ['config.toml', 'intent.toml']
            print('ClickHouse DB server version:', sql('SELECT version()'))
            print('ClickHouse DB: current/view/future/empty DB SELECT and INSERT, other DB denial, role propagation/residual access, exact inverse and data preservation, quoted DB, stale DB UUID/table set/DDL/ACL/input/session, independent allowlists/direct authority/overlap/partial/delegated/global/multi-change refusal passed')
    finally:
        subprocess.run([*docker, 'stop', name], capture_output=True, timeout=30, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'rust/target/debug/grantline-rs')
    parser.add_argument('--docker', action='store_true')
    parser.add_argument('--docker-context')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    protocol(binary, database_scope=True)
    if args.docker:
        docker_test(binary, args.docker_context)


if __name__ == '__main__':
    main()
