#!/usr/bin/env python3
"""Expanded privilege parity on disposable, digest-pinned PostgreSQL/ClickHouse."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
from check_rust_postgres import IMAGE as PG_IMAGE
from check_rust_clickhouse import IMAGE as CH_IMAGE
from check_rust_postgres_writer import intent as pg_intent
from check_rust_clickhouse_writer import intent as ch_intent

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'rust/target/debug/grantline-rs'


def test(kind, image, port, context):
    docker = ['docker', '--context', context]
    info = json.loads(subprocess.check_output([*docker, 'context', 'inspect'], text=True))[0]
    assert info['Endpoints']['docker']['Host'].startswith('unix://')
    name = 'grantline-parity-' + kind + '-' + uuid.uuid4().hex[:10]

    def sql(query, user=None, db=None, ok=True):
        if kind == 'pg':
            args = ['psql', '-h', '127.0.0.1', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-U', user or 'postgres', '-d', db or 'gl_data']
        else:
            args = ['clickhouse-client', '--user', user or 'default', '--multiquery']
        r = subprocess.run([*docker, 'exec', '-i', name, *args], input=query, text=True, capture_output=True, timeout=20)
        assert (r.returncode == 0) == ok, r.stderr
        return r.stdout.strip()

    try:
        args = ['-e', 'POSTGRES_HOST_AUTH_METHOD=trust'] if kind == 'pg' else ['--ulimit', 'nofile=262144:262144']
        subprocess.run([*docker, 'run', '-d', '--rm', '--name', name, '-p', f'127.0.0.1::{port}', '--memory', '2g', '--cpus', '2', *args, image], check=True, stdout=subprocess.DEVNULL)
        for _ in range(150):
            cmd = ['pg_isready', '-h', '127.0.0.1', '-U', 'postgres'] if kind == 'pg' else ['clickhouse-client', '--query', 'SELECT 1']
            if subprocess.run([*docker, 'exec', name, *cmd], capture_output=True).returncode == 0:
                break
            time.sleep(.2)
        else:
            raise RuntimeError(kind + ' failed to start')
        mapped = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports'][f'{port}/tcp'][0]['HostPort']
        with tempfile.TemporaryDirectory(prefix='grantline-parity-') as tmp:
            root = Path(tmp)
            cfg = root / 'config.toml'
            env = dict(os.environ)
            system = kind + '-test'

            def run(*extra, write=None, ok=True):
                r = subprocess.run([str(BINARY), '-c', str(cfg), 'apply', '--live', '--system', system, '--json', *extra, *(['--write', '--expect', write] if write else [])], env=env, text=True, capture_output=True, timeout=20)
                assert (r.returncode == 0) == ok, r.stderr
                return json.loads(r.stdout) if ok else r

            def converge(*extra):
                preview = run(*extra)
                assert preview['changed'], preview
                assert run(*extra, write=preview['plan_id'])['applied']
                assert not run(*extra)['changed']
                run(*extra, write=preview['plan_id'], ok=False)
                return preview

            if kind == 'pg':
                sql('CREATE ROLE gl_owner LOGIN; CREATE ROLE gl_user LOGIN; CREATE DATABASE gl_data OWNER gl_owner;', db='postgres')
                sql('CREATE TABLE a_target(a int); CREATE VIEW v_target AS SELECT a FROM a_target; CREATE SCHEMA app;', user='gl_owner')
                # Remove defaults in this fixture to isolate PUBLIC changes and their inverse.
                sql('REVOKE ALL ON DATABASE gl_data FROM PUBLIC; REVOKE ALL ON SCHEMA public FROM PUBLIC;')
                cfg.write_text('intent="intent.toml"\n[adapters.pg-test]\ntype="postgres"\ndsn_env="GL_PARITY_DSN"\nadmin_dsn_env="GL_PARITY_DSN"\ndatabases=["gl_*"]\nread_timeout_seconds=5\npostgres_write_public=true\npostgres_write_relations=["table:gl_data.public.v_target"]\ndefault_write_scopes=["default:gl_data.app@gl_owner"]\n')
                env['GL_PARITY_DSN'] = f'host=127.0.0.1 port={mapped} user=gl_owner dbname=postgres sslmode=disable'
                pg_intent(root, [('gl_user', 'table:gl_data.public.a_target', ['ALL']), ('gl_user', 'schema:gl_data.app', ['ALL']), ('gl_user', 'db:gl_data', ['ALL']), ('gl_user', 'table:gl_data.public.v_target', ['SELECT'])], managed=('gl_user',))
                run(ok=False)  # Multi-database config needs an explicit one-DB selection.
                converge('--database', 'gl_data')
                assert sql("SELECT has_table_privilege('gl_user','a_target','DELETE') AND has_schema_privilege('gl_user','app','CREATE') AND has_database_privilege('gl_user','gl_data','TEMPORARY')") == 't'
                pg_intent(root, [], managed=('gl_user',))
                converge('--database', 'gl_data')
                assert sql("SELECT has_table_privilege('gl_user','a_target','SELECT')") == 'f'
                pg_intent(root, [('PUBLIC', 'table:gl_data.public.a_target', ['SELECT'])], managed=('PUBLIC',))
                converge('--database', 'gl_data')
                assert sql("SELECT has_table_privilege('gl_user','a_target','SELECT')") == 't'
                pg_intent(root, [], managed=('PUBLIC',))
                converge('--database', 'gl_data')
                pg_intent(root, [('PUBLIC', 'default:gl_data.app@gl_owner', ['ALL'])], managed=('PUBLIC',))
                converge('--database', 'gl_data')
                sql('CREATE TABLE app.future(a int)', user='gl_owner')
                assert sql("SELECT has_table_privilege('gl_user','app.future','SELECT')") == 't'
                # Defaults are future-only; retain this new relation's direct PUBLIC ACLs.
                sql('DROP TABLE app.future', user='gl_owner')
                pg_intent(root, [], managed=('PUBLIC',))
                converge('--database', 'gl_data')
                # Private CA is verified, including hostname; sslmode=require never disables verification.
                cert, key = root / 'ca.pem', root / 'key.pem'
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
                csr, leaf, extensions = root / 'server.csr', root / 'server.pem', root / 'extensions.cnf'
                extensions.write_text('subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
                subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', str(root / 'server-key.pem'), '-out', str(csr)], check=True, capture_output=True)
                subprocess.run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(cert), '-CAkey', str(key), '-CAcreateserial', '-days', '1', '-extfile', str(extensions), '-out', str(leaf)], check=True, capture_output=True)
                key = root / 'server-key.pem'
                subprocess.run([*docker, 'cp', str(leaf), name + ':/tmp/gl-cert.pem'], check=True, stdout=subprocess.DEVNULL)
                subprocess.run([*docker, 'cp', str(key), name + ':/tmp/gl-key.pem'], check=True, stdout=subprocess.DEVNULL)
                subprocess.run([*docker, 'exec', '-u', 'root', name, 'sh', '-c', 'chown postgres:postgres /tmp/gl-key.pem; chmod 600 /tmp/gl-key.pem'], check=True)
                sql("ALTER SYSTEM SET ssl='on'; ALTER SYSTEM SET ssl_cert_file='/tmp/gl-cert.pem'; ALTER SYSTEM SET ssl_key_file='/tmp/gl-key.pem'; SELECT pg_reload_conf();")
                time.sleep(.3)
                cfg.write_text(cfg.read_text() + 'ca_bundle_env="GL_PARITY_CA"\n')
                env['GL_PARITY_CA'] = str(cert)
                env['GL_PARITY_DSN'] = env['GL_PARITY_DSN'].replace('127.0.0.1', 'localhost').replace('sslmode=disable', 'sslmode=require')
                assert not run('--database', 'gl_data')['changed']
                env['GL_PARITY_DSN'] = env['GL_PARITY_DSN'].replace('localhost', '127.0.0.1')
                run('--database', 'gl_data', ok=False)
                env.pop('GL_PARITY_CA')
                run('--database', 'gl_data', ok=False)
                print('PostgreSQL parity: table/schema/database ALL, explicit DB selection, view ACL, PUBLIC/direct/default ALL, inverses/no-op/stale review, private CA and hostname failures passed')
            else:
                sql("""CREATE DATABASE analytics ENGINE=Atomic; CREATE TABLE analytics.events(a UInt8) ENGINE=Memory; CREATE USER gl_user,gl_writer; GRANT SHOW ACCESS,SHOW DATABASES ON *.* TO gl_writer; GRANT SELECT ON system.* TO gl_writer; GRANT ALL ON analytics.* TO gl_writer WITH GRANT OPTION; CREATE TABLE analytics.lookup(id UInt64,value String) ENGINE=Memory; INSERT INTO analytics.lookup VALUES(1, 'ok'); CREATE DICTIONARY analytics.d(id UInt64,value String) PRIMARY KEY id SOURCE(CLICKHOUSE(HOST '127.0.0.1' PORT 9000 USER 'default' DB 'analytics' TABLE 'lookup')) LIFETIME(0) LAYOUT(HASHED()); INSERT INTO analytics.events VALUES(1); CREATE VIEW analytics.v SQL SECURITY DEFINER AS SELECT a FROM analytics.events;""")
                cfg.write_text('intent="intent.toml"\n[adapters.ch-test]\ntype="clickhouse"\nurl_env="GL_PARITY_CH"\nadmin_url_env="GL_PARITY_CH"\nclickhouse_write_tables=["table:analytics.events","table:analytics.d","table:analytics.v"]\nclickhouse_write_databases=["db:analytics"]\nclickhouse_write_privileges=["ALL"]\n')
                env['GL_PARITY_CH'] = f'http://gl_writer@127.0.0.1:{mapped}/'
                for resource in ['table:analytics.events', 'db:analytics']:
                    for privileges in [['ALTER'], ['CREATE'], ['DROP'], ['SHOW'], ['OPTIMIZE'], ['dictGet'], ['ALL']]:
                        ch_intent(root, [('gl_user', resource, privileges)])
                        converge()
                        ch_intent(root, [])
                        converge()
                for resource, privilege, query, expected in [('table:analytics.d','dictGet',"SELECT dictGet('analytics.d','value',toUInt64(1))",'ok'), ('table:analytics.v','SELECT','SELECT a FROM analytics.v','1')]:
                    sql(query, user='gl_user', ok=False)
                    ch_intent(root, [('gl_user',resource,[privilege])])
                    converge()
                    assert sql(query,user='gl_user') == expected
                    ch_intent(root, [])
                    converge()
                    sql(query,user='gl_user',ok=False)
                ch_intent(root, [('gl_user', 'table:analytics.events', ['OPTIMIZE'])])
                cfg.write_text(cfg.read_text().replace('clickhouse_write_privileges=["ALL"]', 'clickhouse_write_privileges=[]'))
                run(ok=False)
                assert sql("SELECT count() FROM system.grants WHERE user_name='gl_user'") == '0'
                print('ClickHouse parity: table/database ALTER/CREATE/DROP/SHOW/OPTIMIZE/dictGet/ALL, grouped single-statement apply/inverse/no-op/stale review actual dictionary/view access and denial, and explicit privilege authorization passed')
    finally:
        subprocess.run([*docker, 'stop', name], capture_output=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=['pg', 'ch'], required=True)
    parser.add_argument('--docker-context', default=None)
    args = parser.parse_args()
    context = args.docker_context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    test(args.kind, PG_IMAGE if args.kind == 'pg' else CH_IMAGE, 5432 if args.kind == 'pg' else 8123, context)


if __name__ == '__main__':
    main()
