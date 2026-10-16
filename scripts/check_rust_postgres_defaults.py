#!/usr/bin/env python3
"""Creator-bound default privileges on a disposable official PostgreSQL server."""
import argparse
import json
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from check_rust_postgres import IMAGE, MARKER, ROOT
from check_rust_postgres_writer import config_at, intent, run


def docker_test(binary, context):
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    info = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert info['Endpoints']['docker']['Host'].startswith('unix://'), 'requires local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-defaults-' + uuid.uuid4().hex[:12]

    def sql(query, user='postgres', db='gl_data', ok=True):
        r = subprocess.run([*docker, 'exec', '-i', name, 'psql', '-h', '127.0.0.1', '-X', '-At', '-v',
                            'ON_ERROR_STOP=1', '-U', user, '-d', db], input=query,
                           capture_output=True, text=True, timeout=15)
        assert (r.returncode == 0) == ok, r.stderr
        return r.stdout.strip()

    def defaults(raw=False):
        if raw:
            return sql('SELECT oid,defaclrole,defaclnamespace,defaclobjtype,defaclacl FROM pg_default_acl ORDER BY 1')
        return sql('SELECT d.defaclrole,d.defaclnamespace,d.defaclobjtype,a.grantee,a.grantor,a.privilege_type,a.is_grantable FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a ORDER BY 1,2,3,4,5,6,7')

    def object_acls():
        return sql("SELECT c.oid,c.relowner,c.relacl FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' ORDER BY 1")

    def default_sql(schema, operation, subject='gl_user', privilege='SELECT', creator='gl_creator'):
        quote = lambda s: '"' + s.replace('"', '""') + '"'
        return f'ALTER DEFAULT PRIVILEGES FOR ROLE {quote(creator)} IN SCHEMA {quote(schema)} {operation} {privilege} ON TABLES ' + ('TO ' if operation == 'GRANT' else 'FROM ') + quote(subject)

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
        sql('CREATE ROLE gl_creator LOGIN; CREATE ROLE gl_other LOGIN; CREATE ROLE gl_bare LOGIN; CREATE ROLE gl_user LOGIN; CREATE ROLE gl_group; CREATE ROLE "gl"";user" LOGIN; CREATE ROLE "gl"";creator" LOGIN; CREATE DATABASE gl_data; CREATE DATABASE other_db;', db='postgres')
        sql('CREATE SCHEMA bare; GRANT CREATE ON SCHEMA bare TO gl_bare; CREATE SCHEMA app AUTHORIZATION gl_creator; CREATE SCHEMA old_scope AUTHORIZATION gl_creator; CREATE SCHEMA other_scope AUTHORIZATION gl_creator; CREATE SCHEMA "odd"";schema" AUTHORIZATION "gl"";creator"; CREATE SCHEMA z_failure AUTHORIZATION gl_creator; CREATE SCHEMA a_first AUTHORIZATION gl_creator; GRANT CREATE ON SCHEMA app TO gl_other; GRANT USAGE ON SCHEMA app,old_scope,other_scope,"odd"";schema" TO PUBLIC;')
        sql('CREATE TABLE app.existing(a int); INSERT INTO app.existing VALUES(42)', user='gl_creator')
        sql(default_sql('old_scope', 'GRANT'), user='gl_creator')
        port = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
        dsn = f'host=127.0.0.1 port={port} user=gl_creator dbname=gl_data sslmode=disable password={MARKER}'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = config_at(root)
            scopes = [f'default:gl_data.{s}@gl_creator' for s in ['app', 'old_scope', 'other_scope', 'a_first', 'z_failure', 'missing']]
            scopes += ['default:gl_data.bare@gl_bare', 'default:gl_data.odd";schema@gl";creator', 'default:gl_data.app@gl_other', 'default:other_db.app@gl_creator']
            configured = config.read_text().replace('read_timeout_seconds=3', 'default_write_scopes=' + json.dumps(scopes) + '\nread_timeout_seconds=3')
            config.write_text(configured)
            managed = ('gl_user', 'gl_group')
            original = [('gl_user', 'default:gl_data.old_scope@gl_creator', ['SELECT'])]
            desired = [('gl_user', 'default:gl_data.app@gl_creator', ['SELECT', 'INSERT']),
                       ('gl_group', 'default:gl_data.app@gl_creator', ['SELECT'])]

            def declare(rows):
                intent(root, rows, managed=managed)

            declare(desired)
            baseline = defaults()
            objects = object_acls()
            p = run(binary, config, dsn)
            assert p['default_changes_future_objects_only'] and not p['membership_changes_cluster_wide']
            assert not p['effective_access_verified'] and not p['applied'] and len(p['changes']) == 4
            assert defaults() == baseline and object_acls() == objects
            assert all('ALTER DEFAULT PRIVILEGES FOR ROLE "gl_creator" IN SCHEMA ' in c['cmd'] for c in p['changes'])
            assert run(binary, config, dsn, write=p['plan_id'])['applied']
            assert sql("SELECT r.rolname,g.rolname,a.is_grantable FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a JOIN pg_roles r ON r.oid=d.defaclrole JOIN pg_roles g ON g.oid=a.grantor WHERE d.defaclnamespace='app'::regnamespace ORDER BY 1,2,3") == 'gl_creator|gl_creator|f\ngl_creator|gl_creator|f\ngl_creator|gl_creator|f'
            noop = run(binary, config, dsn)
            assert not noop['changed'] and not noop['default_changes_future_objects_only']
            assert not run(binary, config, dsn, write=noop['plan_id'])['applied']
            run(binary, config, dsn, write=p['plan_id'], ok=False)
            # Defaults use the actual creating role, schema and DB; existing objects are unchanged.
            sql('CREATE TABLE app.after(a int); INSERT INTO app.after VALUES(42)', user='gl_creator')
            assert sql('SELECT * FROM app.after', user='gl_user') == '42'
            sql('INSERT INTO app.after VALUES(43)', user='gl_user')
            sql('DELETE FROM app.after', user='gl_user', ok=False)
            sql('SELECT * FROM app.existing', user='gl_user', ok=False)
            sql('CREATE TABLE other_scope.after(a int)', user='gl_creator')
            sql('CREATE TABLE app.other_creator(a int)', user='gl_other')
            sql('SELECT * FROM other_scope.after', user='gl_user', ok=False)
            sql('SELECT * FROM app.other_creator', user='gl_user', ok=False)
            # Membership in the creator does not apply the creator's defaults to member-owned objects.
            sql('GRANT gl_creator TO gl_other')
            sql('CREATE TABLE app.member_created(a int)', user='gl_other')
            sql('SELECT * FROM app.member_created', user='gl_user', ok=False)
            sql('REVOKE gl_creator FROM gl_other')
            assert sql('SELECT count(*) FROM pg_default_acl', db='other_db') == '0'
            retained = [('gl_user', 'table:gl_data.app.after', ['SELECT', 'INSERT']),
                        ('gl_group', 'table:gl_data.app.after', ['SELECT'])]
            declare(original + retained)
            inverse = run(binary, config, dsn)
            assert run(binary, config, dsn, write=inverse['plan_id'])['applied']
            assert defaults() == baseline
            assert sql('SELECT count(*) FROM app.after', user='gl_user') == '2', 'inverse default must not edit existing object ACLs'
            sql('CREATE TABLE app.after_inverse(a int)', user='gl_creator')
            sql('SELECT * FROM app.after_inverse', user='gl_user', ok=False)
            sql('DROP TABLE app.after,other_scope.after,app.other_creator,app.member_created,app.after_inverse')
            assert object_acls() == objects

            # Full catalog binding includes raw default row identity and other object types.
            for kind in ['default-oid', 'default-options', 'other-type', 'global', 'schema-oid', 'schema-owner', 'recipient-flags', 'creator-flags', 'creator-oid', 'session']:
                declare(desired)
                p = run(binary, config, dsn)
                if kind == 'default-oid':
                    sql(default_sql('old_scope', 'REVOKE') + ';' + default_sql('old_scope', 'GRANT'), user='gl_creator')
                elif kind == 'default-options':
                    sql(default_sql('old_scope', 'GRANT') + ' WITH GRANT OPTION', user='gl_creator')
                elif kind == 'other-type':
                    sql('ALTER DEFAULT PRIVILEGES FOR ROLE gl_creator IN SCHEMA app GRANT USAGE ON SEQUENCES TO gl_group', user='gl_creator')
                elif kind == 'global':
                    sql('ALTER DEFAULT PRIVILEGES FOR ROLE gl_creator GRANT SELECT ON TABLES TO gl_group', user='gl_creator')
                elif kind == 'schema-oid':
                    sql('DROP SCHEMA other_scope; CREATE SCHEMA other_scope AUTHORIZATION gl_creator; GRANT USAGE ON SCHEMA other_scope TO PUBLIC')
                elif kind == 'schema-owner':
                    sql('ALTER SCHEMA app OWNER TO gl_other')
                elif kind == 'recipient-flags':
                    sql('ALTER ROLE gl_user NOLOGIN')
                elif kind == 'creator-flags':
                    sql('ALTER ROLE gl_creator CREATEDB')
                elif kind == 'creator-oid':
                    # A separate empty creator can be dropped/recreated without destroying the fixture.
                    quoted = 'default:gl_data.odd";schema@gl";creator'
                    intent(root, [('gl";user', quoted, ['SELECT'])], managed=('gl";user',))
                    qdsn = dsn.replace('user=gl_creator', "user='gl\";creator'")
                    p = run(binary, config, qdsn)
                    sql('ALTER SCHEMA "odd"";schema" OWNER TO gl_creator; DROP ROLE "gl"";creator"; CREATE ROLE "gl"";creator" LOGIN; ALTER SCHEMA "odd"";schema" OWNER TO "gl"";creator"')
                before = defaults(raw=True)
                active_dsn = qdsn if kind == 'creator-oid' else dsn.replace('user=gl_creator', 'user=postgres') if kind == 'session' else dsn
                run(binary, config, active_dsn, write=p['plan_id'], ok=False)
                assert defaults(raw=True) == before, kind
                if kind == 'default-options':
                    sql(default_sql('old_scope', 'REVOKE') + ';' + default_sql('old_scope', 'GRANT'), user='gl_creator')
                elif kind == 'other-type':
                    sql('ALTER DEFAULT PRIVILEGES FOR ROLE gl_creator IN SCHEMA app REVOKE USAGE ON SEQUENCES FROM gl_group', user='gl_creator')
                elif kind == 'global':
                    sql('ALTER DEFAULT PRIVILEGES FOR ROLE gl_creator REVOKE SELECT ON TABLES FROM gl_group', user='gl_creator')
                elif kind == 'schema-owner':
                    sql('ALTER SCHEMA app OWNER TO gl_creator; GRANT CREATE ON SCHEMA app TO gl_other')
                elif kind == 'recipient-flags':
                    sql('ALTER ROLE gl_user LOGIN')
                elif kind == 'creator-flags':
                    sql('ALTER ROLE gl_creator NOCREATEDB')
            assert defaults() == baseline
            declare(desired)
            config.write_text(configured.replace('default_write_scopes=' + json.dumps(scopes), 'default_write_scopes=[]'))
            run(binary, config, dsn, ok=False)
            config.write_text(configured)
            for subject, resource, privileges in [
                    ('gl_user', 'default:gl_data.app@gl_other', ['SELECT']),
                    ('gl_user', 'default:other_db.app@gl_creator', ['SELECT']),
                    ('gl_user', 'default:gl_data.missing@gl_creator', ['SELECT']),
                    ('missing', 'default:gl_data.app@gl_creator', ['SELECT']),
                    ('PUBLIC', 'default:gl_data.app@gl_creator', ['SELECT']),
                    ('postgres', 'default:gl_data.app@gl_creator', ['SELECT']),
                    ('pg_read_all_data', 'default:gl_data.app@gl_creator', ['SELECT']),
                    ('gl_creator', 'default:gl_data.app@gl_creator', ['SELECT']),
                    ('gl_user', 'default:gl_data.app@gl_creator', ['ALL']),
                    ('gl_user', 'default:gl_data.*@gl_creator', ['SELECT'])]:
                intent(root, [(subject, resource, privileges)], managed=(subject,))
                before = defaults(raw=True)
                run(binary, config, dsn, ok=False)
                assert defaults(raw=True) == before
            declare(desired + [('gl_user', 'table:gl_data.app.existing', ['SELECT'])])
            failure = run(binary, config, dsn, ok=False)
            assert 'default-only' in failure.stderr
            # Existing binary atom must not hide a grant option on an unchanged declaration.
            sql(default_sql('old_scope', 'GRANT') + ' WITH GRANT OPTION', user='gl_creator')
            declare(original)
            failure = run(binary, config, dsn, ok=False)
            assert 'Delegated' in failure.stderr
            sql(default_sql('old_scope', 'REVOKE') + ';' + default_sql('old_scope', 'GRANT'), user='gl_creator')
            # Other-type defaults stay intact across successful table-default transactions.
            sql('ALTER DEFAULT PRIVILEGES FOR ROLE gl_creator IN SCHEMA app GRANT USAGE ON SEQUENCES TO gl_group', user='gl_creator')
            other_type = defaults()
            declare(desired)
            p = run(binary, config, dsn)
            run(binary, config, dsn, write=p['plan_id'])
            declare(original)
            p = run(binary, config, dsn)
            run(binary, config, dsn, write=p['plan_id'])
            assert defaults() == other_type
            sql('ALTER DEFAULT PRIVILEGES FOR ROLE gl_creator IN SCHEMA app REVOKE USAGE ON SEQUENCES FROM gl_group', user='gl_creator')
            # Quoted creator, schema and recipient are SQL identifiers, never statement fragments.
            quoted = 'default:gl_data.odd";schema@gl";creator'
            intent(root, [('gl";user', quoted, ['SELECT'])], managed=('gl";user',))
            qdsn = dsn.replace('user=gl_creator', "user='gl\";creator'")
            p = run(binary, config, qdsn)
            assert 'FOR ROLE "gl"";creator" IN SCHEMA "odd"";schema" GRANT SELECT ON TABLES TO "gl"";user";' in p['changes'][0]['cmd']
            run(binary, config, qdsn, write=p['plan_id'])
            sql('CREATE TABLE "odd"";schema".sample(a int); INSERT INTO "odd"";schema".sample VALUES(42)', user='gl";creator')
            assert sql('SELECT * FROM "odd"";schema".sample', user='gl";user') == '42'
            sql('DROP TABLE "odd"";schema".sample', user='gl";creator')
            intent(root, [], managed=('gl";user',))
            p = run(binary, config, qdsn)
            run(binary, config, qdsn, write=p['plan_id'])
            assert defaults() == baseline

            # A creator need not own the schema: ordinary CREATE is sufficient.
            config.write_text(configured.replace('default_write_scopes=' + json.dumps(scopes), 'default_write_scopes=["default:gl_data.bare@gl_bare"]'))
            declare(original + [('gl_user', 'default:gl_data.bare@gl_bare', ['SELECT'])])
            bare_dsn = dsn.replace('user=gl_creator', 'user=gl_bare')
            p = run(binary, config, bare_dsn)
            run(binary, config, bare_dsn, write=p['plan_id'])
            # Preserve the other creator's managed default while removing bare's new edge.
            declare(original)
            p = run(binary, config, bare_dsn)
            run(binary, config, bare_dsn, write=p['plan_id'])
            assert defaults() == baseline

            config.write_text(configured)
            # Fail/stall only the second statement; the earlier default row must roll back too.
            declare(original + [('gl_user', 'default:gl_data.a_first@gl_creator', ['SELECT']),
                                ('gl_user', 'default:gl_data.z_failure@gl_creator', ['SELECT'])])
            sql("CREATE FUNCTION gl_fail() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF current_query() LIKE '%z_failure%' THEN RAISE EXCEPTION '" + MARKER + "'; END IF; END $$; CREATE EVENT TRIGGER gl_failure ON ddl_command_start WHEN TAG IN ('ALTER DEFAULT PRIVILEGES') EXECUTE FUNCTION gl_fail()")
            before = defaults(raw=True)
            p = run(binary, config, dsn)
            failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert 'statement failed' in failure.stderr and defaults(raw=True) == before
            sql("CREATE OR REPLACE FUNCTION gl_fail() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF current_query() LIKE '%z_failure%' THEN PERFORM pg_sleep(10); END IF; END $$")
            p = run(binary, config, dsn)
            start = time.monotonic()
            run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert time.monotonic() - start < 8 and defaults(raw=True) == before
            logs = subprocess.check_output([*docker, 'logs', name], stderr=subprocess.STDOUT, text=True)
            for schema in ['a_first', 'z_failure']:
                assert default_sql(schema, 'GRANT') + ';' in logs
            assert 'ROLLBACK' in logs
            sql('DROP EVENT TRIGGER gl_failure; DROP FUNCTION gl_fail()')
            # A server-side unrelated default edit cannot pass the exact catalog postcondition.
            sql("CREATE FUNCTION gl_side_effect() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF current_query() LIKE '%a_first%' AND current_setting('grantline.injected',true) IS DISTINCT FROM 'yes' THEN PERFORM set_config('grantline.injected','yes',true); ALTER DEFAULT PRIVILEGES IN SCHEMA other_scope GRANT USAGE ON SEQUENCES TO gl_group; END IF; END $$; CREATE EVENT TRIGGER gl_side ON ddl_command_end WHEN TAG IN ('ALTER DEFAULT PRIVILEGES') EXECUTE FUNCTION gl_side_effect()")
            p = run(binary, config, dsn)
            failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
            assert 'postcondition failed' in failure.stderr and defaults(raw=True) == before, failure.stderr
            sql('DROP EVENT TRIGGER gl_side; DROP FUNCTION gl_side_effect()')
            # Cooperative advisory lock covers default-only plans and releases after rollback.
            holder = subprocess.Popen([*docker, 'exec', '-i', name, 'psql', '-X', '-At', '-U', 'postgres', '-d', 'gl_data'],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                holder.stdin.write("BEGIN; SELECT pg_advisory_xact_lock(1196576334,1); SELECT 'held';\n")
                holder.stdin.flush()
                while holder.stdout.readline().strip() != 'held':
                    assert holder.poll() is None, 'advisory lock holder failed'
                p = run(binary, config, dsn)
                failure = run(binary, config, dsn, write=p['plan_id'], ok=False)
                assert 'advisory lock' in failure.stderr and defaults(raw=True) == before
            finally:
                holder.communicate('ROLLBACK;\n', timeout=10)
            p = run(binary, config, dsn)
            run(binary, config, dsn, write=p['plan_id'])
            declare(original)
            p = run(binary, config, dsn)
            run(binary, config, dsn, write=p['plan_id'])
            assert defaults() == baseline and object_acls() == objects
            assert sorted(p.name for p in root.iterdir()) == ['config.toml', 'intent.toml']
            print('PostgreSQL defaults server version:', sql('SHOW server_version'))
            print('PostgreSQL defaults: authenticated creator/quoted scope, future SELECT/INSERT, existing/other creator/schema/DB isolation, inverse, exact grantor/options, stale identities/all default types, default-off/mixed/global/delegation refusal, later error/timeout/unexpected side-effect rollback, advisory lock and redaction passed')
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
