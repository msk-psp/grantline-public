#!/usr/bin/env python3
"""Native PostgreSQL reader boundaries; --docker verifies a disposable official server."""
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

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'postgres@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24'
MARKER = 'NEVER-OUTPUT-CREDENTIAL'


def config_at(root):
    config = root / 'config.toml'
    config.write_text('intent="intent.toml"\nsnapshots="history"\n[adapters.pg-test]\ntype="postgres"\ndsn_env="GRANTLINE_R3C_READER"\nadmin_dsn_env="GRANTLINE_R3C_ADMIN"\nread_timeout_seconds=3\nexclude_databases=["gl_skip"]\n')
    (root / 'intent.toml').write_text('managed_subjects=["gl_subject","gl_noinherit","gl_descendant"]\nmanaged_systems=["pg-test"]\n[[grants]]\nsystem="pg-test"\nsubject="gl_subject"\nresource="table:gl_data.public.events"\nprivs=["SELECT"]\n[[grants]]\nsystem="pg-test"\nsubject="gl_subject"\nresource="table:gl_blocked.public.secret"\nprivs=["SELECT"]\n')
    return config


def run(binary, config, dsn, *command, live=True, check=True):
    env = dict(os.environ, GRANTLINE_R3C_ADMIN='host=127.0.0.1 port=1 user=admin dbname=postgres password=' + MARKER,
               PGHOST='invalid.example.com', PGUSER='admin', PGPASSWORD=MARKER, PGSERVICE='not-a-service',
               GRANTLINE_R3C_READER=dsn or '')
    if dsn is None:
        env.pop('GRANTLINE_R3C_READER', None)
    result = subprocess.run([binary, '-c', str(config), *command, *(['--live'] if live else [])],
                            env=env, cwd='/', text=True, capture_output=True, timeout=15)
    assert MARKER not in result.stdout + result.stderr, 'credential escaped through output'
    if not check:
        return result
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def blind(plan):
    assert not plan['observed'] and not plan['changes'] and plan['unobserved'], plan
    assert plan['observation_complete'] is False


def boundary(binary):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = config_at(root)
        for dsn in [None, 'password=' + MARKER, 'host=/tmp user=reader dbname=postgres',
                    'host=a,b user=reader dbname=postgres', 'host=localhost user=reader',
                    'host=localhost dbname=postgres', 'host=localhost user=reader dbname=postgres options=bad',
                    'host=localhost hostaddr=127.0.0.1 user=reader dbname=postgres',
                    'host=127.0.0.1 port=1 user=reader dbname=postgres password=' + MARKER]:
            blind(run(binary, config, dsn, 'plan', '--json'))
        # A TCP peer that accepts but never authenticates must not hang the CLI.
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            server.settimeout(0.2)
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
                        stop.wait(5)

            thread = threading.Thread(target=stalled, daemon=True)
            thread.start()
            dsn = f'host=127.0.0.1 port={server.getsockname()[1]} user=reader dbname=postgres password={MARKER}'
            try:
                blind(run(binary, config, dsn, 'plan', '--json', live=False))
                assert not calls, 'offline command contacted service'
                start = time.monotonic()
                blind(run(binary, config, dsn, 'plan', '--json'))
                assert 2 <= time.monotonic() - start < 7 and len(calls) == 1
                count = len(calls)
                conflict = run(binary, config, dsn, 'plan', '--observed', 'unused', '--json', check=False)
                assert conflict.returncode != 0 and len(calls) == count
            finally:
                stop.set()
                thread.join(timeout=6)
        original = config.read_text()
        for text in [original.replace('read_timeout_seconds=3', 'read_timeout_seconds=0'),
                     original.replace('dsn_env="GRANTLINE_R3C_READER"', ''),
                     original.replace('type="postgres"', 'type="postgres"\nkind="clickhouse"')]:
            config.write_text(text)
            result = run(binary, config, None, 'plan', '--json', check=False)
            if result.returncode == 0:
                blind(json.loads(result.stdout))
            else:
                assert 'type and kind' in result.stderr
        print('PostgreSQL boundaries: 9 invalid/unavailable DSNs, offline isolation, stalled authentication deadline, source conflict, config validation and secret redaction passed')


def docker_test(binary, context):
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    ctx = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert ctx['Endpoints']['docker']['Host'].startswith('unix://'), 'integration test requires a local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-r3c-' + uuid.uuid4().hex[:12]

    def sql(query, db='postgres', user='postgres', check=True):
        result = subprocess.run([*docker, 'exec', '-i', name, 'psql', '-h', '127.0.0.1', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-U', user, '-d', db],
                                input=query, text=True, capture_output=True, timeout=30)
        if check:
            assert result.returncode == 0, result.stderr
            return result.stdout
        return result

    try:
        subprocess.run([*docker, 'run', '-d', '--rm', '--name', name, '-p', '127.0.0.1::5432', '--memory', '1g', '--cpus', '2',
                        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', IMAGE], check=True, stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 60
        while True:
            result = sql('SELECT 1', check=False)
            if result.returncode == 0 and result.stdout == '1\n':
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('Disposable PostgreSQL failed to start')
            time.sleep(0.2)
        sql('''
CREATE ROLE gl_observer LOGIN;
ALTER ROLE gl_observer SET default_transaction_read_only=on;
CREATE ROLE gl_owner;
CREATE ROLE gl_base;
CREATE ROLE gl_nested;
CREATE ROLE gl_subject LOGIN;
CREATE ROLE gl_noinherit;
CREATE ROLE gl_descendant;
CREATE ROLE "gl\"\"quoted" LOGIN;
GRANT gl_base TO gl_nested;
GRANT gl_nested TO gl_subject;
GRANT gl_base TO gl_noinherit WITH INHERIT FALSE;
GRANT gl_noinherit TO gl_descendant;
CREATE DATABASE gl_data OWNER gl_owner;
CREATE DATABASE gl_blocked;
REVOKE CONNECT ON DATABASE gl_blocked FROM PUBLIC;
CREATE DATABASE gl_skip;
''')
        sql('''
CREATE TABLE public.events(a int,b int);
ALTER TABLE public.events OWNER TO gl_owner;
GRANT SELECT ON public.events TO gl_base;
GRANT SELECT ON public.events TO "gl\"\"quoted" WITH GRANT OPTION;
CREATE TABLE public."odd\"\"table"(a int);
GRANT SELECT ON public."odd\"\"table" TO "gl\"\"quoted";
CREATE TABLE public.untouched(a int);
ALTER TABLE public.untouched OWNER TO gl_owner;
CREATE TABLE public.frozen(a int);
ALTER TABLE public.frozen OWNER TO gl_owner;
REVOKE ALL ON public.frozen FROM gl_owner;
ALTER DEFAULT PRIVILEGES FOR ROLE gl_owner IN SCHEMA public GRANT SELECT ON TABLES TO gl_base;
CREATE SCHEMA columns;
CREATE TABLE columns.secrets(a int,b int);
GRANT SELECT(a) ON columns.secrets TO gl_base;
''', db='gl_data')
        hostport = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
        dsn = f'host=127.0.0.1 port={hostport} user=gl_observer dbname=postgres sslmode=disable password={MARKER}'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = config_at(root)
            plan = run(binary, config, dsn, 'plan', '--json')
            atoms = {(g['subject'], g['resource'], g['priv']): g for g in plan['observed']}
            expected = [('PUBLIC', 'db:gl_data', 'CONNECT'), ('PUBLIC', 'db:gl_data', 'TEMPORARY'),
                        ('gl_subject', 'role:gl_nested', 'MEMBER'), ('gl_nested', 'role:gl_base', 'MEMBER'),
                        ('gl_base', 'table:gl_data.public.events', 'SELECT'),
                        ('gl_base', 'default:gl_data.public@gl_owner', 'SELECT'),
                        ('gl"quoted', 'table:gl_data.public.odd"table', 'SELECT'),
                        ('gl_owner', 'table:gl_data.public.events', 'INSERT')]
            assert all(g in atoms for g in expected), (expected, plan)
            assert atoms[expected[0]]['source'] == 'implicit'
            assert atoms[expected[2]]['grantor'] == 'postgres'
            assert atoms[('gl_owner', 'table:gl_data.public.untouched', 'SELECT')]['source'] == 'implicit'
            assert atoms[expected[-1]]['source'] == 'explicit'  # relacl materialized by GRANT
            assert not any(g[0] in {'gl_noinherit', 'gl_descendant'} for g in atoms)
            assert not any(g[1].startswith('table:gl_data.columns.') for g in atoms)
            assert any('table:gl_blocked.' in u['prefixes'] for u in plan['unobserved'])
            assert any('table:gl_skip.' in u['prefixes'] for u in plan['unobserved'])
            assert not any(c['grant']['resource'].startswith(('table:gl_blocked.', 'table:gl_skip.')) for c in plan['changes'])
            assert any(f['title'] == 'frozen ACL (owner locked out)' and 'gl_data.public.frozen' in f['entities'] and f['system'] == 'pg-test' for f in plan['findings'])
            assert any(f['title'] == 'grant option is not modelled' for f in plan['findings'])
            assert any(g['resource'] == 'table:gl_blocked.public.secret' for g in plan['unverified'])
            graph = run(binary, config, dsn, 'graph', '--subject', 'gl_subject', '--json')
            assert graph['graph']['kind']['gl_subject'] == 'human'
            assert graph['graph']['kind']['gl_base'] == 'role'
            assert graph['routes_from']['gl_subject']['paths'], graph
            saved = run(binary, config, dsn, 'snapshot', '--json')
            assert Path(saved['path']).stat().st_mode & 0o077 == 0
            imported = run(binary, config, 'invalid ' + MARKER, 'plan', '--observed', saved['path'], '--json', live=False)
            assert imported['observed'] == plan['observed'] and imported['unobserved'] == plan['unobserved']
            # Excluding a database must never look like an empty database.
            original = config.read_text()
            config.write_text(original + 'databases=["postgres"]\n')
            excluded = run(binary, config, dsn, 'plan', '--json')
            assert not any(g['resource'].startswith(('table:gl_data.', 'schema:gl_data.', 'default:gl_data.')) for g in excluded['observed'])
            assert any('table:gl_data.' in u['prefixes'] for u in excluded['unobserved'])
            config.write_text(original)
            # Fail after table rows have been read: no partial per-DB grants may survive.
            sql('REVOKE SELECT ON pg_catalog.pg_default_acl FROM PUBLIC', db='gl_data')
            partial = run(binary, config, dsn, 'plan', '--json')
            assert any('table:gl_data.' in u['prefixes'] for u in partial['unobserved'])
            assert not any(g['resource'].startswith(('table:gl_data.', 'schema:gl_data.', 'default:gl_data.')) for g in partial['observed'])
            assert any(g['resource'] == 'db:gl_data' for g in partial['observed'])
            sql('GRANT SELECT ON pg_catalog.pg_default_acl TO PUBLIC', db='gl_data')
            sql('ALTER DEFAULT PRIVILEGES FOR ROLE gl_owner GRANT SELECT ON TABLES TO gl_base', db='gl_data')
            global_defaults = run(binary, config, dsn, 'plan', '--json')
            assert any('default:gl_data.' in u['prefixes'] for u in global_defaults['unobserved'])
            assert not any(g['resource'].startswith('default:gl_data.') for g in global_defaults['observed'])
            # Real server proves reader defaults reject a DDL write; no object remains.
            rejected = sql('CREATE TABLE public.gl_forbidden(a int)', db='gl_data', user='gl_observer', check=False)
            assert rejected.returncode and 'read-only transaction' in rejected.stderr
            denied = sql('SET default_transaction_read_only=off; CREATE TABLE public.gl_forbidden(a int)', db='gl_data', user='gl_observer', check=False)
            assert denied.returncode and 'permission denied' in denied.stderr
            data_denied = sql('SELECT * FROM public.events', db='gl_data', user='gl_observer', check=False)
            assert data_denied.returncode and 'permission denied' in data_denied.stderr
            assert sql("SELECT to_regclass('public.gl_forbidden') IS NULL", db='gl_data') == 't\n'
            blind(run(binary, config, dsn.replace('user=gl_observer', 'user=not_a_role'), 'plan', '--json'))
            # No silent plaintext downgrade when TLS is requested (or omitted).
            for tls in ['sslmode=require', 'sslmode=prefer', '']:
                blind(run(binary, config, dsn.replace('sslmode=disable', tls), 'plan', '--json'))
            # Maintenance failure makes the whole instance unknown.
            sql('REVOKE SELECT ON pg_catalog.pg_auth_members FROM PUBLIC')
            blind(run(binary, config, dsn, 'plan', '--json'))
            sql('GRANT SELECT ON pg_catalog.pg_auth_members TO PUBLIC')
            # The 10,001st row is an error, never a silently truncated role catalog.
            sql("DO $$ BEGIN FOR i IN 1..10001 LOOP EXECUTE format('CREATE ROLE gl_bounded_%s', i); END LOOP; END $$;")
            capped = run(binary, config, dsn, 'plan', '--json')
            blind(capped)
            assert any('row/byte limit' in u['note'] for u in capped['unobserved'])
            print('PostgreSQL server version:', sql('SHOW server_version').strip())
            print('PostgreSQL Docker: catalog scopes/defaults, PUBLIC/owner ACLs, grantors, quoted names, nested roles, unknown inheritance/columns/exclusions/unreachable DBs, graph/snapshot, partial rollback, TLS downgrade refusal, row cap and independent data/write refusal passed')
    finally:
        subprocess.run([*docker, 'stop', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)


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
