#!/usr/bin/env python3
"""Canonical role membership writes on a disposable official PostgreSQL cluster."""
import argparse
import json
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from check_rust_postgres import IMAGE, MARKER, ROOT, assert_postgres_major
from check_rust_postgres_writer import config_at, intent, run


def docker_test(binary, context):
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    info = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert info['Endpoints']['docker']['Host'].startswith('unix://'), 'requires local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-members-' + uuid.uuid4().hex[:12]

    def sql(query, user='postgres', db='postgres', ok=True):
        r = subprocess.run([*docker, 'exec', '-i', name, 'psql', '-h', '127.0.0.1', '-X', '-At', '-v',
                            'ON_ERROR_STOP=1', '-U', user, '-d', db], input=query,
                           capture_output=True, text=True, timeout=15)
        assert (r.returncode == 0) == ok, r.stderr
        return r.stdout.strip()

    def members():
        return sql("SELECT m.rolname,r.rolname,g.rolname,a.admin_option,a.inherit_option,a.set_option FROM pg_auth_members a JOIN pg_roles m ON m.oid=a.member JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles g ON g.oid=a.grantor ORDER BY 1,2,3")

    def edge(role='gl_old', member='gl_member', grantor='gl_writer'):
        return f'GRANT "{role}" TO "{member}" WITH ADMIN FALSE, INHERIT TRUE, SET TRUE GRANTED BY "{grantor}";'

    try:
        subprocess.run([*docker, 'run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::5432',
                        '--memory', '1g', '--cpus', '2', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', IMAGE,
                        '-c', 'log_statement=all'], check=True, stdout=subprocess.DEVNULL)
        for _ in range(150):
            r = subprocess.run([*docker, 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], capture_output=True)
            if r.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError('Disposable PostgreSQL failed to start')
        assert_postgres_major(sql)
        sql('CREATE ROLE gl_writer LOGIN NOINHERIT; CREATE ROLE gl_member LOGIN NOINHERIT; CREATE ROLE gl_first LOGIN; CREATE ROLE gl_child; CREATE ROLE gl_leaf LOGIN; CREATE ROLE "gl"";member" LOGIN; CREATE ROLE "gl"";group"; CREATE ROLE gl_group; CREATE ROLE gl_old; CREATE ROLE gl_a; CREATE ROLE gl_b; CREATE ROLE z_wait; CREATE ROLE gl_parent; CREATE ROLE gl_holder; CREATE ROLE gl_login LOGIN; CREATE ROLE gl_owned; CREATE ROLE gl_priv SUPERUSER; CREATE DATABASE gl_data;')
        groups = ['gl_group', 'gl_old', 'gl";group', 'gl_a', 'gl_b', 'z_wait', 'gl_parent', 'gl_holder', 'gl_login', 'gl_owned', 'gl_priv', 'missing', 'gl_writer']
        for role in groups:
            if role not in ['gl_writer', 'gl_priv', 'missing', 'gl_holder']:
                sql('GRANT "' + role.replace('"', '""') + '" TO gl_writer WITH ADMIN TRUE, INHERIT FALSE, SET FALSE')
        sql(edge('gl_child', 'gl_leaf', 'postgres'))
        sql(edge(), user='gl_writer')
        sql('CREATE TABLE sample(a int); INSERT INTO sample VALUES(42); GRANT SELECT ON sample TO gl_group; CREATE SCHEMA owned AUTHORIZATION gl_owned;', db='gl_data')
        port = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
        dsn = f'host=127.0.0.1 port={port} user=gl_writer dbname=postgres sslmode=disable password={MARKER}'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = config_at(root)
            config.write_text(config.read_text().replace('databases=["gl_data"]', 'databases=["postgres"]')
                              .replace('read_timeout_seconds=3', 'membership_write_roles=' + json.dumps(groups) + '\nread_timeout_seconds=3'))
            configured = config.read_text()
            managed = ('gl_member', 'gl";member', 'gl_child')
            desired = [('gl_member', 'role:gl_group', ['MEMBER']), ('gl";member', 'role:gl";group', ['MEMBER']), ('gl_child', 'role:gl_group', ['MEMBER'])]
            original = [('gl_member', 'role:gl_old', ['MEMBER'])]
            intent(root, desired, managed=managed)
            baseline = members()
            sql('SELECT * FROM sample', user='gl_member', db='gl_data', ok=False)
            p = run(binary, config, dsn)
            assert p['membership_changes_cluster_wide'] and not p['applied'] and len(p['changes']) == 4
            assert members() == baseline
            assert all('GRANTED BY "gl_writer"' in c['cmd'] for c in p['changes'])
            assert any('"gl"";group" TO "gl"";member"' in c['cmd'] for c in p['changes'])
            assert run(binary, config, dsn, write=p['plan_id'])['applied']
            assert sql('SELECT * FROM sample', user='gl_member', db='gl_data') == '42'
            assert sql('SELECT * FROM sample', user='gl_leaf', db='gl_data') == '42'
            assert sql('SET ROLE gl_group; SELECT current_user', user='gl_member').splitlines()[-1] == 'gl_group'
            assert sql("SELECT a.admin_option,a.inherit_option,a.set_option,g.rolname FROM pg_auth_members a JOIN pg_roles m ON m.oid=a.member JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles g ON g.oid=a.grantor WHERE m.rolname='gl_member' AND r.rolname='gl_group'") == 'f|t|t|gl_writer'
            noop = run(binary, config, dsn)
            assert not noop['changed'] and not noop['membership_changes_cluster_wide']
            assert not run(binary, config, dsn, write=noop['plan_id'])['applied']
            run(binary, config, dsn, write=p['plan_id'], ok=False)
            intent(root, original, managed=managed)
            p = run(binary, config, dsn)
            run(binary, config, dsn, write=p['plan_id'])
            assert members() == baseline
            sql('SELECT * FROM sample', user='gl_member', db='gl_data', ok=False)
            sql('SELECT * FROM sample', user='gl_leaf', db='gl_data', ok=False)

            for kind in ['oid', 'login', 'attribute', 'actor-flags', 'inherit-option', 'set-option', 'admin-option', 'admin-right', 'grantor', 'duplicate-grantor']:
                intent(root, [('gl_member', 'role:gl_a', ['MEMBER'])] if kind == 'oid' else desired, managed=managed)
                if kind == 'actor-flags':
                    sql('ALTER ROLE gl_writer CREATEDB')
                p = run(binary, config, dsn)
                if kind == 'oid':
                    sql('DROP ROLE gl_a; CREATE ROLE gl_a; GRANT gl_a TO gl_writer WITH ADMIN TRUE, INHERIT FALSE, SET FALSE')
                elif kind == 'login':
                    sql('ALTER ROLE gl_group LOGIN')
                elif kind == 'attribute':
                    sql('ALTER ROLE gl_member INHERIT')
                elif kind == 'actor-flags':
                    sql('ALTER ROLE gl_writer NOCREATEDB CREATEROLE')
                elif kind in ['inherit-option', 'set-option', 'admin-option']:
                    option = {'inherit-option': 'INHERIT FALSE', 'set-option': 'SET FALSE', 'admin-option': 'ADMIN TRUE'}[kind]
                    sql('GRANT gl_old TO gl_member WITH ' + option + ' GRANTED BY gl_writer', user='gl_writer')
                elif kind == 'admin-right':
                    sql('REVOKE ADMIN OPTION FOR gl_group FROM gl_writer GRANTED BY postgres RESTRICT')
                elif kind == 'grantor':
                    sql('REVOKE gl_old FROM gl_member GRANTED BY gl_writer RESTRICT', user='gl_writer')
                    sql(edge(grantor='postgres'))
                else:
                    sql(edge(grantor='postgres'))
                snapshot = members()
                run(binary, config, dsn, write=p['plan_id'], ok=False)
                assert members() == snapshot, kind
                if kind == 'login':
                    sql('ALTER ROLE gl_group NOLOGIN')
                elif kind == 'attribute':
                    sql('ALTER ROLE gl_member NOINHERIT')
                elif kind == 'actor-flags':
                    sql('ALTER ROLE gl_writer NOCREATEROLE NOCREATEDB')
                elif kind in ['inherit-option', 'set-option', 'admin-option']:
                    sql(edge(), user='gl_writer')
                elif kind == 'admin-right':
                    sql('GRANT gl_group TO gl_writer WITH ADMIN TRUE, INHERIT FALSE, SET FALSE')
                elif kind in ['grantor', 'duplicate-grantor']:
                    sql('REVOKE gl_old FROM gl_member GRANTED BY postgres RESTRICT')
                    if kind == 'grantor':
                        sql(edge(), user='gl_writer')
            assert members() == baseline
            # An unchanged MEMBER atom with noncanonical options must not be accepted as canonical.
            intent(root, original, managed=managed)
            sql('GRANT gl_old TO gl_member WITH SET FALSE GRANTED BY gl_writer', user='gl_writer')
            run(binary, config, dsn, ok=False)
            sql(edge(), user='gl_writer')

            intent(root, desired, managed=managed)
            config.write_text(configured.replace('membership_write_roles=' + json.dumps(groups), 'membership_write_roles=[]'))
            run(binary, config, dsn, ok=False)
            config.write_text(configured.replace('databases=["postgres"]', 'databases=["gl_data"]'))
            run(binary, config, dsn.replace('dbname=postgres', 'dbname=gl_data'), ok=False)
            config.write_text(configured)
            intent(root, desired + [('gl_member', 'db:postgres', ['CREATE'])], managed=managed)
            run(binary, config, dsn, ok=False)
            for member, role, privilege in [('gl_member', 'gl_login', 'MEMBER'), ('gl_member', 'gl_owned', 'MEMBER'),
                                             ('gl_member', 'gl_priv', 'MEMBER'), ('postgres', 'gl_group', 'MEMBER'),
                                             ('gl_group', 'gl_group', 'MEMBER'), ('gl_writer', 'gl_group', 'MEMBER'),
                                             ('gl_member', 'gl_writer', 'MEMBER'), ('gl_member', 'missing', 'MEMBER'),
                                             ('gl_member', 'gl_group', 'SELECT')]:
                intent(root, [(member, 'role:' + role, [privilege])], managed=(member,))
                snapshot = members()
                run(binary, config, dsn, ok=False)
                assert members() == snapshot
            for parent, options in [('gl_priv', ''), ('gl_owned', ''), ('gl_parent', ' WITH SET FALSE')]:
                sql('GRANT ' + parent + ' TO gl_group' + options)
                intent(root, desired, managed=managed)
                snapshot = members()
                run(binary, config, dsn, ok=False)
                assert members() == snapshot
                sql('REVOKE ' + parent + ' FROM gl_group GRANTED BY postgres RESTRICT')
            sql('GRANT gl_holder TO gl_writer WITH ADMIN FALSE, INHERIT TRUE, SET TRUE')
            intent(root, [('gl_holder', 'role:gl_group', ['MEMBER'])], managed=('gl_holder',))
            run(binary, config, dsn, ok=False)
            sql('REVOKE gl_holder FROM gl_writer GRANTED BY postgres RESTRICT')
            # The second canonical GRANT creates a cycle: PostgreSQL rejects it and rolls back the first.
            intent(root, [('gl_b', 'role:gl_a', ['MEMBER']), ('gl_a', 'role:gl_b', ['MEMBER'])], managed=('gl_a', 'gl_b'))
            p = run(binary, config, dsn)
            snapshot = members()
            failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert 'statement failed' in failure.stderr and members() == snapshot
            logs = subprocess.check_output([*docker, 'logs', name], stderr=subprocess.STDOUT, text=True)
            assert 'GRANT "gl_a" TO "gl_b" WITH ADMIN FALSE' in logs and 'GRANT "gl_b" TO "gl_a" WITH ADMIN FALSE' in logs

            # Raw concurrent insertion is invisible to the preview but blocks the second GRANT's unique key.
            holder = subprocess.Popen([*docker, 'exec', '-i', name, 'psql', '-h', '127.0.0.1', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-U', 'gl_writer', '-d', 'postgres'],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                holder.stdin.write('BEGIN; ' + edge('z_wait') + " SELECT 'held';\n")
                holder.stdin.flush()
                while holder.stdout.readline().strip() != 'held':
                    assert holder.poll() is None, 'membership holder failed'
                intent(root, [('gl_first', 'role:gl_a', ['MEMBER']), ('gl_member', 'role:z_wait', ['MEMBER'])], managed=('gl_first', 'gl_member'))
                p = run(binary, config, dsn)
                snapshot = members()
                start = time.monotonic()
                run(binary, config, dsn, write=p['plan_id'], ok=False)
                assert time.monotonic() - start < 8 and members() == snapshot
                logs = subprocess.check_output([*docker, 'logs', name], stderr=subprocess.STDOUT, text=True)
                assert 'GRANT "gl_a" TO "gl_first" WITH ADMIN FALSE' in logs and logs.count('GRANT "z_wait" TO "gl_member" WITH ADMIN FALSE') >= 2
            finally:
                holder.communicate('ROLLBACK;\n', timeout=10)
            assert members() == baseline
            holder = subprocess.Popen([*docker, 'exec', '-i', name, 'psql', '-X', '-At', '-U', 'postgres', '-d', 'postgres'],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                holder.stdin.write("BEGIN; SELECT pg_advisory_xact_lock(1196576334, 1); SELECT 'held';\n")
                holder.stdin.flush()
                while holder.stdout.readline().strip() != 'held':
                    assert holder.poll() is None, 'coordinator lock holder failed'
                intent(root, desired, managed=managed)
                p = run(binary, config, dsn)
                failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
                assert 'advisory lock' in failure.stderr and members() == baseline
            finally:
                holder.communicate('ROLLBACK;\n', timeout=10)
            p = run(binary, config, dsn)
            run(binary, config, dsn, write=p['plan_id'])
            intent(root, original, managed=managed)
            p = run(binary, config, dsn)
            run(binary, config, dsn, write=p['plan_id'])
            assert members() == baseline
            assert sorted(p.name for p in root.iterdir()) == ['config.toml', 'intent.toml']
            print('PostgreSQL membership server version:', sql('SHOW server_version'))
            print('PostgreSQL membership: canonical flags/exact grantor, NOINHERIT and cross-DB SELECT/SET ROLE, quoted names, inverse, stale identity/flags/admin/grantor, allowlist/coordinator/owner/privilege ancestry refusal, cycle and blocked-grant rollback, advisory lock release and redaction passed')
    finally:
        subprocess.run([*docker, 'stop', name], capture_output=True, timeout=30, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'rust/target/debug/grantline-rs')
    parser.add_argument('--docker', action='store_true')
    parser.add_argument('--docker-context')
    args = parser.parse_args()
    if args.docker:
        docker_test(str(args.binary.resolve()), args.docker_context)
    else:
        parser.error('--docker is required; this test never contacts configured services')


if __name__ == '__main__':
    main()
