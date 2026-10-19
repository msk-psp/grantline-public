#!/usr/bin/env python3
"""PostgreSQL writer boundaries and disposable official-server transaction checks."""
import argparse
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

from check_rust_postgres import IMAGE, MARKER, ROOT


def config_at(root):
    path = root / 'config.toml'
    path.write_text('intent="intent.toml"\n[adapters.pg-test]\ntype="postgres"\n'
                    'dsn_env="GL_WRITER_UNUSED_READER"\nadmin_dsn_env="GL_WRITER_ADMIN"\n'
                    'probe_dsn_envs={gl_user="GL_WRITER_UNUSED_PROBE"}\n'
                    'databases=["gl_data"]\nread_timeout_seconds=3\n'
                    '[adapters.unrelated]\ntype="clickhouse"\nurl_env="GL_WRITER_UNUSED_READER"\n')
    intent(root, [('gl_user', 'table:gl_data.public.a_target', ['SELECT'])])
    return path


def intent(root, rows, managed=('gl_user', 'gl_group')):
    text = 'managed_subjects=' + json.dumps(managed) + '\nmanaged_systems=["pg-test"]\n'
    for subject, resource, privileges in rows:
        text += ('[[grants]]\nsystem="pg-test"\nsubject=' + json.dumps(subject) + '\nresource='
                 + json.dumps(resource) + '\nprivs=' + json.dumps(privileges) + '\n')
    (root / 'intent.toml').write_text(text)


def run(binary, config, dsn=None, *, write=None, live=True, ok=True, extra=None):
    env = dict(os.environ, PGHOST='invalid.example.com', PGUSER='ambient-admin', PGPASSWORD=MARKER,
               PGSERVICE='not-a-service', GL_WRITER_UNUSED_READER=MARKER, GL_WRITER_UNUSED_PROBE=MARKER)
    env.pop('GL_WRITER_ADMIN', None)
    if dsn is not None:
        env['GL_WRITER_ADMIN'] = dsn
    env.update(extra or {})
    args = [binary, '-c', str(config), 'apply', '--system', 'pg-test', '--json']
    if live:
        args += ['--live']
    if write is not None:
        args += ['--write']
        if write:
            args += ['--expect', write]
    result = subprocess.run(args, env=env, cwd='/', text=True, capture_output=True, timeout=12)
    assert MARKER not in result.stdout + result.stderr, 'credential escaped output'
    assert (result.returncode == 0) == ok, result.stderr
    return json.loads(result.stdout) if ok else result


def boundary(binary):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = config_at(root)
        for dsn in [None, 'password=' + MARKER, 'host=/tmp user=admin dbname=gl_data',
                    'host=a,b user=admin dbname=gl_data', 'host=localhost dbname=gl_data',
                    'host=localhost user=admin', 'host=localhost user=admin dbname=other',
                    'host=localhost user=admin dbname=gl_data options=bad',
                    'host=localhost hostaddr=127.0.0.1 user=admin dbname=gl_data',
                    'host=127.0.0.1 port=1 user=admin dbname=gl_data password=' + MARKER]:
            run(binary, config, dsn, ok=False)
        if hasattr(os, 'mkfifo'):
            for filename in ['config.toml', 'intent.toml']:
                path = root / filename
                saved = path.read_bytes()
                path.unlink()
                os.mkfifo(path, 0o600)
                failure = run(binary, config, ok=False)
                assert 'regular file' in failure.stderr
                path.unlink()
                path.write_bytes(saved)
        original = config.read_text()
        for before, after in [('admin_dsn_env="GL_WRITER_ADMIN"', ''),
                              ('databases=["gl_data"]', 'databases=["*"]'),
                              ('databases=["gl_data"]', 'databases=["gl_data","other"]'),
                              ('databases=["gl_data"]', 'databases=["gl_data"]\nexclude_databases=["other"]'),
                              ('read_timeout_seconds=3', 'read_timeout_seconds=0')]:
            config.write_text(original.replace(before, after))
            run(binary, config, 'host=localhost user=admin dbname=gl_data', ok=False)
        config.write_text(original)
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            server.settimeout(0.1)
            stop = threading.Event()
            calls = []

            def stalled():
                while not stop.is_set():
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        continue
                    calls.append(1)
                    with conn:
                        stop.wait(4)

            thread = threading.Thread(target=stalled, daemon=True)
            thread.start()
            dsn = f'host=127.0.0.1 port={server.getsockname()[1]} user=admin dbname=gl_data password={MARKER}'
            try:
                run(binary, config, dsn, live=False, ok=False)
                run(binary, config, dsn, write='', ok=False)
                assert not calls, 'missing network/write authorization contacted the server'
                start = time.monotonic()
                run(binary, config, dsn, ok=False)
                assert 2 <= time.monotonic() - start < 7 and len(calls) == 1
            finally:
                stop.set()
                thread.join(timeout=5)
        assert sorted(p.name for p in root.iterdir()) == ['config.toml', 'intent.toml'], 'preview created files'
    print('PostgreSQL writer boundary: explicit credentials/live/review, DSN/TLS options, scope and deadline passed')


def docker_test(binary, context):
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    ctx = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert ctx['Endpoints']['docker']['Host'].startswith('unix://'), 'requires local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-pg-writer-' + uuid.uuid4().hex[:12]

    def sql(query, user='postgres', db='gl_data'):
        result = subprocess.run([*docker, 'exec', '-i', name, 'psql', '-h', '127.0.0.1', '-X', '-v',
                                 'ON_ERROR_STOP=1', '-At', '-U', user, '-d', db], input=query,
                                text=True, capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    def acl():
        # Compare semantic ACLs, including grantor and delegation, rather than NULL vs materialized defaults.
        return sql("SELECT n.nspname,c.relname,a.grantee,a.grantor,a.privilege_type,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='public' AND c.relkind='r' ORDER BY 1,2,3,4,5,6")

    def all_acl():
        return sql("""SELECT * FROM (
          SELECT 'table' k,n.nspname||'.'||c.relname object,a.grantee,a.grantor,a.privilege_type,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND c.relkind='r'
          UNION ALL SELECT 'schema',n.nspname,a.grantee,a.grantor,a.privilege_type,a.is_grantable FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'
          UNION ALL SELECT 'db',d.datname,a.grantee,a.grantor,a.privilege_type,a.is_grantable FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE NOT d.datistemplate
        ) q ORDER BY 1,2,3,4,5,6""")

    def allowed(subject, table, privilege):
        return sql(f"SELECT has_table_privilege('{subject}','{table}','{privilege}')") == 't'

    try:
        subprocess.run([*docker, 'run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::5432',
                        '--memory', '1g', '--cpus', '2', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', IMAGE,
                        '-c', 'log_statement=all'], check=True, stdout=subprocess.DEVNULL)
        for _ in range(150):
            ready = subprocess.run([*docker, 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError('Disposable PostgreSQL failed to start')
        sql('CREATE ROLE gl_owner LOGIN; CREATE ROLE gl_user LOGIN; CREATE ROLE gl_group; CREATE ROLE gl_other; CREATE DATABASE gl_data OWNER gl_owner;', db='postgres')
        sql('CREATE TABLE a_target(a int); CREATE TABLE old_target(a int); CREATE TABLE "odd"";table"(a int); GRANT SELECT ON old_target TO gl_user;', user='gl_owner')
        port = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
        dsn = f'host=127.0.0.1 port={port} user=gl_owner dbname=gl_data sslmode=disable password={MARKER}'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = config_at(root)
            original_intent = (root / 'intent.toml').read_bytes()
            original_config = config.read_bytes()
            before = acl()
            intent(root, [('gl_user', 'table:gl_data.public.a_target', ['SELECT', 'INSERT']),
                          ('gl_group', 'table:gl_data.public.odd";table', ['SELECT'])])
            p = run(binary, config, dsn)
            assert p['changed'] and not p['applied'] and len(p['changes']) == 4 and acl() == before
            assert not p['effective_access_verified']
            assert any('"odd"";table"' in c['cmd'] for c in p['changes']), p
            result = run(binary, config, dsn, write=p['plan_id'])
            assert result['applied'] and result['plan_id'] == p['plan_id']
            assert allowed('gl_user', 'a_target', 'SELECT') and allowed('gl_user', 'a_target', 'INSERT')
            assert not allowed('gl_user', 'a_target', 'DELETE') and not allowed('gl_user', 'old_target', 'SELECT')
            assert sql('SELECT has_table_privilege(\'gl_group\',\'"odd"";table"\',\'SELECT\')') == 't'
            no_change = run(binary, config, dsn)
            assert not no_change['changed'] and not run(binary, config, dsn, write=no_change['plan_id'])['applied']
            run(binary, config, dsn, write=p['plan_id'], ok=False)
            # Undo is a NEW intent and review, never blind replay of saved SQL.
            intent(root, [('gl_user', 'table:gl_data.public.old_target', ['SELECT'])])
            inverse = run(binary, config, dsn)
            assert run(binary, config, dsn, write=inverse['plan_id'])['applied'] and acl() == before
            (root / 'intent.toml').write_bytes(original_intent)
            for kind in ['intent', 'config', 'acl', 'object', 'role', 'session']:
                p = run(binary, config, dsn)
                saved_intent = (root / 'intent.toml').read_bytes()
                if kind == 'intent':
                    (root / 'intent.toml').write_bytes(saved_intent + b'\n')
                elif kind == 'config':
                    config.write_bytes(original_config + b'\n')
                elif kind == 'acl':
                    sql('GRANT UPDATE ON a_target TO gl_user', user='gl_owner')
                elif kind == 'object':
                    sql('DROP TABLE a_target; CREATE TABLE a_target(a int)', user='gl_owner')
                elif kind == 'role':
                    sql('ALTER ROLE gl_user NOLOGIN')
                snapshot = acl()
                changed_dsn = dsn.replace('user=gl_owner', 'user=postgres') if kind == 'session' else dsn
                run(binary, config, changed_dsn, write=p['plan_id'], ok=False)
                assert acl() == snapshot, kind
                (root / 'intent.toml').write_bytes(saved_intent)
                config.write_bytes(original_config)
                if kind == 'acl':
                    sql('REVOKE UPDATE ON a_target FROM gl_user', user='gl_owner')
                elif kind == 'role':
                    sql('ALTER ROLE gl_user LOGIN')
            # Unsupported inputs must not silently become executable SQL or partial plans.
            for subject, resource, privileges in [
                    ('gl_user', 'role:gl_group', ['MEMBER']), ('gl_user', 'schema:other.public', ['USAGE']),
                    ('gl_user', 'db:other', ['CREATE']), ('gl_user', 'default:gl_data.public@gl_owner', ['SELECT']),
                    ('gl_user', 'table:other.public.a_target', ['SELECT']), ('missing', 'table:gl_data.public.a_target', ['SELECT']),
                    ('PUBLIC', 'table:gl_data.public.a_target', ['SELECT']), ('gl_owner', 'table:gl_data.public.a_target', ['UPDATE']),
                    ('postgres', 'table:gl_data.public.a_target', ['SELECT'])]:
                intent(root, [(subject, resource, privileges)], managed=(subject,))
                snapshot = acl()
                run(binary, config, dsn, ok=False)
                assert acl() == snapshot
            for setup, cleanup in [
                    ('CREATE VIEW v_target AS SELECT 1 a', 'DROP VIEW v_target'),
                    ('CREATE TABLE v_target(a int) PARTITION BY RANGE(a)', 'DROP TABLE v_target'),
                    ('CREATE TABLE v_target(a int) INHERITS(a_target)', 'DROP TABLE v_target')]:
                sql(setup, user='gl_owner')
                intent(root, [('gl_user', 'table:gl_data.public.v_target', ['SELECT'])])
                run(binary, config, dsn, ok=False)
                sql(cleanup, user='gl_owner')
            (root / 'intent.toml').write_bytes(original_intent)
            for setup, cleanup in [
                    ('GRANT SELECT(a) ON a_target TO gl_group', 'REVOKE SELECT(a) ON a_target FROM gl_group'),
                    ('GRANT SELECT ON a_target TO gl_group WITH GRANT OPTION', 'REVOKE SELECT ON a_target FROM gl_group')]:
                sql(setup, user='gl_owner')
                snapshot = acl()
                run(binary, config, dsn, ok=False)
                assert acl() == snapshot
                sql(cleanup, user='gl_owner')
            # Non-owner grantor must not collapse to a single permission atom.
            sql('GRANT SELECT ON a_target TO gl_other WITH GRANT OPTION', user='gl_owner')
            sql('SET ROLE gl_other; GRANT SELECT ON a_target TO gl_user')
            intent(root, [('gl_user', 'table:gl_data.public.a_target', ['INSERT'])])
            snapshot = acl()
            run(binary, config, dsn, ok=False)
            assert acl() == snapshot
            sql('REVOKE SELECT ON a_target FROM gl_other CASCADE', user='gl_owner')
            # PostgreSQL can report an ineffective GRANT only as a warning; verify and roll back all ACLs.
            sql('CREATE TABLE z_denied(a int); ALTER TABLE z_denied OWNER TO gl_other; GRANT UPDATE ON z_denied TO gl_owner')
            intent(root, [('gl_user', 'table:gl_data.public.a_target', ['SELECT']),
                          ('gl_user', 'table:gl_data.public.z_denied', ['SELECT'])])
            p = run(binary, config, dsn)
            snapshot = acl()
            failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert 'postcondition failed' in failure.stderr, failure.stderr
            assert acl() == snapshot and not allowed('gl_user', 'a_target', 'SELECT')
            logs = subprocess.check_output([*docker, 'logs', name], stderr=subprocess.STDOUT, text=True)
            assert 'GRANT SELECT ON TABLE "public"."a_target" TO "gl_user";' in logs
            assert 'GRANT SELECT ON TABLE "public"."z_denied" TO "gl_user";' in logs
            assert 'ROLLBACK' in logs
            sql('DROP TABLE z_denied')
            # A server event trigger rejects the second SQL with a sensitive diagnostic.
            sql('CREATE TABLE z_failure(a int)', user='gl_owner')
            sql("CREATE FUNCTION gl_fail() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF current_query() LIKE '%z_failure%' THEN RAISE EXCEPTION '" + MARKER + "'; END IF; END $$; CREATE EVENT TRIGGER gl_failure ON ddl_command_start WHEN TAG IN ('GRANT') EXECUTE FUNCTION gl_fail()")
            intent(root, [('gl_user', 'table:gl_data.public.a_target', ['SELECT']),
                          ('gl_user', 'table:gl_data.public.z_failure', ['SELECT'])])
            p = run(binary, config, dsn)
            snapshot = acl()
            failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert 'statement failed' in failure.stderr and acl() == snapshot
            # A stalled DCL also rolls back the earlier grant within the configured deadline.
            sql("CREATE OR REPLACE FUNCTION gl_fail() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF current_query() LIKE '%z_failure%' THEN PERFORM pg_sleep(10); END IF; END $$")
            p = run(binary, config, dsn)
            start = time.monotonic()
            run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert time.monotonic() - start < 8 and acl() == snapshot
            sql('DROP EVENT TRIGGER gl_failure; DROP FUNCTION gl_fail(); DROP TABLE z_failure')
            (root / 'intent.toml').write_bytes(original_intent)
            # NOWAIT prevents changes when another transaction holds a conflicting table lock.
            holder = subprocess.Popen([*docker, 'exec', '-i', name, 'psql', '-X', '-At', '-U', 'postgres', '-d', 'gl_data'],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                holder.stdin.write("BEGIN; LOCK TABLE a_target IN ACCESS EXCLUSIVE MODE; SELECT 'locked';\n")
                holder.stdin.flush()
                while holder.stdout.readline().strip() != 'locked':
                    assert holder.poll() is None, 'lock holder failed'
                p = run(binary, config, dsn)
                snapshot = acl()
                failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
                assert 'lock affected table' in failure.stderr and acl() == snapshot
            finally:
                holder.communicate('ROLLBACK;\n', timeout=10)
            # R3g2: all three object kinds share one review and transaction.
            sql('CREATE ROLE gl_scoped LOGIN; CREATE ROLE gl_scope_group; CREATE ROLE "gl"";scoped" LOGIN; CREATE SCHEMA app AUTHORIZATION gl_owner; CREATE SCHEMA old_scope AUTHORIZATION gl_owner; CREATE SCHEMA "odd"";schema" AUTHORIZATION gl_owner; GRANT USAGE ON SCHEMA old_scope TO gl_scoped; GRANT USAGE ON SCHEMA app TO gl_other')
            scoped_subjects = ('gl_scoped', 'gl_scope_group', 'gl";scoped')
            baseline = all_acl()
            desired = [('gl_scoped', 'db:gl_data', ['CONNECT', 'CREATE', 'TEMPORARY']),
                       ('gl_scoped', 'schema:gl_data.app', ['USAGE', 'CREATE']),
                       ('gl_scoped', 'table:gl_data.public.a_target', ['SELECT']),
                       ('gl_scope_group', 'schema:gl_data.app', ['USAGE']),
                       ('gl_scope_group', 'schema:gl_data.public', ['USAGE']),
                       ('gl";scoped', 'schema:gl_data.odd";schema', ['USAGE', 'CREATE'])]
            intent(root, desired, managed=scoped_subjects)
            p = run(binary, config, dsn)
            assert all_acl() == baseline and len(p['changes']) == 11 and not p['applied']
            assert any('ON DATABASE "gl_data"' in c['cmd'] for c in p['changes'])
            assert any('ON SCHEMA "odd"";schema" TO "gl"";scoped"' in c['cmd'] for c in p['changes'])
            assert run(binary, config, dsn, write=p['plan_id'])['applied']
            assert sql("SELECT has_database_privilege('gl_scoped','gl_data','CREATE') AND has_schema_privilege('gl_scoped','app','USAGE') AND has_schema_privilege('gl_scoped','app','CREATE') AND has_table_privilege('gl_scoped','a_target','SELECT')") == 't'
            assert sql("SELECT has_schema_privilege('gl_scoped','old_scope','USAGE')") == 'f'
            assert sql("SELECT has_schema_privilege('gl_other','app','USAGE')") == 't'
            assert not run(binary, config, dsn)['changed']
            # Review revoking every newly assigned DB/schema/table privilege and restoring the old one.
            intent(root, [('gl_scoped', 'schema:gl_data.old_scope', ['USAGE'])], managed=scoped_subjects)
            inverse = run(binary, config, dsn)
            assert run(binary, config, dsn, write=inverse['plan_id'])['applied'] and all_acl() == baseline
            assert sql("SELECT has_database_privilege('gl_scoped','gl_data','CREATE')") == 'f'
            # Direct CONNECT/TEMPORARY revocation does not remove PUBLIC's effective defaults.
            assert sql("SELECT has_database_privilege('gl_scoped','gl_data','CONNECT') AND has_database_privilege('gl_scoped','gl_data','TEMPORARY')") == 't'

            for kind in ['schema-oid', 'schema-name', 'schema-owner', 'schema-acl', 'database-owner', 'database-acl']:
                intent(root, desired, managed=scoped_subjects)
                p = run(binary, config, dsn)
                if kind == 'schema-oid':
                    sql('DROP SCHEMA "odd"";schema"; CREATE SCHEMA "odd"";schema" AUTHORIZATION gl_owner')
                elif kind == 'schema-name':
                    sql('ALTER SCHEMA app RENAME TO renamed_app')
                elif kind == 'schema-owner':
                    sql('ALTER SCHEMA app OWNER TO gl_other')
                elif kind == 'schema-acl':
                    sql('GRANT CREATE ON SCHEMA app TO gl_other')
                elif kind == 'database-owner':
                    sql('ALTER DATABASE gl_data OWNER TO gl_other')
                else:
                    sql('GRANT CREATE ON DATABASE gl_data TO gl_other')
                snapshot = all_acl()
                run(binary, config, dsn, write=p['plan_id'], ok=False)
                assert all_acl() == snapshot, kind
                if kind == 'schema-name':
                    sql('ALTER SCHEMA renamed_app RENAME TO app')
                elif kind == 'schema-owner':
                    # OWNER TO merges ACL entries; restore this fixture's unrelated direct USAGE explicitly.
                    sql('ALTER SCHEMA app OWNER TO gl_owner; GRANT USAGE ON SCHEMA app TO gl_other')
                elif kind == 'schema-acl':
                    sql('REVOKE CREATE ON SCHEMA app FROM gl_other')
                elif kind == 'database-owner':
                    sql('ALTER DATABASE gl_data OWNER TO gl_owner')
                elif kind == 'database-acl':
                    sql('REVOKE CREATE ON DATABASE gl_data FROM gl_other')
            assert all_acl() == baseline
            for subject, resource, privileges in [
                    ('gl_scoped', 'schema:gl_data.missing', ['USAGE']),
                    ('gl_scoped', 'schema:gl_data.app', ['CONNECT']),
                    ('gl_scoped', 'db:gl_data', ['USAGE']),
                    ('gl_scoped', 'db:other', ['CREATE']),
                    ('gl_scoped', 'schema:other.app', ['USAGE']),
                    ('PUBLIC', 'db:gl_data', ['CREATE']), ('PUBLIC', 'schema:gl_data.app', ['CREATE']),
                    ('postgres', 'schema:gl_data.app', ['CREATE']), ('postgres', 'db:gl_data', ['CREATE']),
                    ('gl_owner', 'db:gl_data', ['CONNECT']), ('gl_owner', 'schema:gl_data.app', ['USAGE']),
                    ('gl_owner', 'schema:gl_data.public', ['USAGE'])]:
                intent(root, [(subject, resource, privileges)], managed=(subject,))
                snapshot = all_acl()
                run(binary, config, dsn, ok=False)
                assert all_acl() == snapshot
            for scope, privilege in [('SCHEMA app', 'CREATE'), ('DATABASE gl_data', 'CREATE')]:
                sql(f'GRANT {privilege} ON {scope} TO gl_other WITH GRANT OPTION', user='gl_owner')
                sql(f'SET ROLE gl_other; GRANT {privilege} ON {scope} TO gl_scoped')
                intent(root, desired, managed=scoped_subjects)
                snapshot = all_acl()
                run(binary, config, dsn, ok=False)
                assert all_acl() == snapshot
                sql(f'REVOKE {privilege} ON {scope} FROM gl_other CASCADE', user='gl_owner')
            # Missing grant options produce warnings after DB CREATE succeeded; verify full rollback.
            sql('CREATE SCHEMA z_denied AUTHORIZATION gl_other; GRANT USAGE ON SCHEMA z_denied TO gl_owner')
            mixed = [('gl_scoped', 'db:gl_data', ['CREATE']),
                     ('gl_scoped', 'schema:gl_data.app', ['CREATE']),
                     ('gl_scoped', 'schema:gl_data.z_denied', ['CREATE'])]
            intent(root, mixed, managed=scoped_subjects)
            p = run(binary, config, dsn)
            snapshot = all_acl()
            failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert 'postcondition failed' in failure.stderr and all_acl() == snapshot
            sql('DROP SCHEMA z_denied')
            # Raise after earlier DB/schema grants, then delay the same last table GRANT.
            sql('CREATE TABLE z_failure(a int)', user='gl_owner')
            sql("CREATE FUNCTION gl_fail() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF current_query() LIKE '%z_failure%' THEN RAISE EXCEPTION '" + MARKER + "'; END IF; END $$; CREATE EVENT TRIGGER gl_failure ON ddl_command_start WHEN TAG IN ('GRANT') EXECUTE FUNCTION gl_fail()")
            mixed[-1] = ('gl_scoped', 'table:gl_data.public.z_failure', ['SELECT'])
            intent(root, mixed, managed=scoped_subjects)
            p = run(binary, config, dsn)
            snapshot = all_acl()
            failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert 'statement failed' in failure.stderr and all_acl() == snapshot
            # Unexpected server-side ownership changes must also fail the postcondition.
            sql("CREATE OR REPLACE FUNCTION gl_fail() RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN IF current_query() LIKE '%z_failure%' THEN ALTER SCHEMA app OWNER TO gl_other; END IF; END $$")
            p = run(binary, config, dsn)
            failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert 'postcondition failed' in failure.stderr and all_acl() == snapshot
            assert sql("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='app'") == 'gl_owner'
            sql("CREATE OR REPLACE FUNCTION gl_fail() RETURNS event_trigger LANGUAGE plpgsql SECURITY INVOKER AS $$ BEGIN IF current_query() LIKE '%z_failure%' THEN PERFORM pg_sleep(10); END IF; END $$")
            p = run(binary, config, dsn)
            start = time.monotonic()
            run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert time.monotonic() - start < 8 and all_acl() == snapshot
            sql('DROP EVENT TRIGGER gl_failure; DROP FUNCTION gl_fail(); DROP TABLE z_failure')

            # This writer's advisory lock covers DB/schema-only plans as well as table plans.
            holder = subprocess.Popen([*docker, 'exec', '-i', name, 'psql', '-X', '-At', '-U', 'postgres', '-d', 'gl_data'],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                holder.stdin.write("BEGIN; SELECT pg_advisory_xact_lock(1196576334, 1); SELECT 'locked';\n")
                holder.stdin.flush()
                while holder.stdout.readline().strip() != 'locked':
                    assert holder.poll() is None, 'advisory lock holder failed'
                for rows in [desired, [('gl_scoped', 'db:gl_data', ['CREATE'])], [('gl_scoped', 'schema:gl_data.app', ['CREATE'])]]:
                    intent(root, rows, managed=scoped_subjects)
                    p = run(binary, config, dsn)  # Preview does not need the writer lock.
                    snapshot = all_acl()
                    failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
                    assert 'advisory lock' in failure.stderr and all_acl() == snapshot
            finally:
                holder.communicate('ROLLBACK;\n', timeout=10)
            intent(root, desired, managed=scoped_subjects)
            p = run(binary, config, dsn)
            assert run(binary, config, dsn, write=p['plan_id'])['applied'], 'writer lock was not released'
            intent(root, [('gl_scoped', 'schema:gl_data.old_scope', ['USAGE'])], managed=scoped_subjects)
            p = run(binary, config, dsn)
            run(binary, config, dsn, write=p['plan_id'])
            assert all_acl() == baseline

            # A quoted database name binds its actual OID, not just the configured spelling.
            quoted_db = 'gl";database'
            sql('CREATE DATABASE "gl"";database" OWNER gl_owner', db='postgres')
            config.write_text(config.read_text().replace('databases=["gl_data"]', 'databases=[' + json.dumps(quoted_db) + ']'))
            quoted_dsn = dsn.replace('dbname=gl_data', "dbname='" + quoted_db + "'")
            intent(root, [('gl_scoped', 'db:' + quoted_db, ['CREATE'])], managed=scoped_subjects)
            p = run(binary, config, quoted_dsn)
            sql('DROP DATABASE "gl"";database"; CREATE DATABASE "gl"";database" OWNER gl_owner', db='postgres')
            snapshot = all_acl()
            run(binary, config, quoted_dsn, write=p['plan_id'], ok=False)
            assert all_acl() == snapshot
            p = run(binary, config, quoted_dsn)
            assert 'DATABASE "gl"";database"' in p['changes'][0]['cmd']
            assert run(binary, config, quoted_dsn, write=p['plan_id'])['applied']
            intent(root, [], managed=scoped_subjects)
            p = run(binary, config, quoted_dsn)
            run(binary, config, quoted_dsn, write=p['plan_id'])
            assert all_acl() == snapshot
            sql('DROP DATABASE "gl"";database"', db='postgres')
            config.write_bytes(original_config)
            (root / 'intent.toml').write_bytes(original_intent)
            print('PostgreSQL schema/database writer: mixed grants/revokes/inverse, all privileges/quoted identifiers, stale schema/database identity/owner/ACL, exact delegation refusal, warning/error/timeout rollback and cooperative lock passed')
            run(binary, config, dsn.replace('sslmode=disable', 'sslmode=prefer'), ok=False)
            assert sorted(p.name for p in root.iterdir()) == ['config.toml', 'intent.toml']
            print('PostgreSQL writer server version:', sql('SHOW server_version'))
            print('PostgreSQL writer Docker: dry-run/no-op, quoted grant/revoke/inverse, stale config/intent/ACL/OID/role/session, unsupported scopes/delegation, full rollback, NOWAIT contention, TLS refusal and secret redaction passed')
    finally:
        subprocess.run([*docker, 'stop', name], capture_output=True, timeout=30, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'rust/target/debug/grantline-rs')
    parser.add_argument('--docker', action='store_true')
    parser.add_argument('--docker-context')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    boundary(binary)
    if args.docker:
        docker_test(binary, args.docker_context)


if __name__ == '__main__':
    main()
