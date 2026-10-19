#!/usr/bin/env python3
"""Isolated S3 remote readers; --docker also checks official SeaweedFS Filer/IAM APIs."""
import argparse
import datetime
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from grantline.adapters.sigv4 import sign  # noqa: E402

IMAGE = 'chrislusf/seaweedfs@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d'
MARKER = 'NEVER-OUTPUT-CREDENTIAL'
KEY = 'GLTESTREADER'
SECRET = MARKER + '-synthetic'
ARN = 'arn:aws:iam::123456789012:policy/team'
READS = {'ListUsers', 'GetUser', 'ListUserPolicies', 'GetUserPolicy', 'ListAttachedUserPolicies',
         'ListGroups', 'GetGroup', 'ListGroupPolicies', 'GetGroupPolicy', 'ListAttachedGroupPolicies', 'GetPolicy', 'GetPolicyVersion'}


def policy(prefix='demo/team', actions=None):
    return dict(Version='2012-10-17', Statement=[dict(Effect='Allow', Action=actions or ['s3:GetObject'], Resource=f'arn:aws:s3:::{prefix}/*')])


def run(binary, config, endpoint, *command, live=True, check=True):
    env = dict(os.environ, GRANTLINE_R3D_ENDPOINT=endpoint, GRANTLINE_R3D_KEY=KEY, GRANTLINE_R3D_SECRET=SECRET,
               GRANTLINE_R3D_TOKEN=MARKER, GRANTLINE_R3D_ADMIN='http://127.0.0.1:1/' + MARKER,
               AWS_ACCESS_KEY_ID='DO-NOT-USE', AWS_SECRET_ACCESS_KEY=MARKER,
               HTTP_PROXY='http://127.0.0.1:1', HTTPS_PROXY='http://127.0.0.1:1', ALL_PROXY='http://127.0.0.1:1')
    result = subprocess.run([binary, '-c', str(config), *command, *(['--live'] if live else [])], env=env,
                            cwd='/', capture_output=True, text=True, timeout=20)
    assert MARKER not in result.stdout + result.stderr and SECRET not in result.stdout + result.stderr
    if not check:
        return result
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def config_at(root, source):
    cfg = root / 'config.toml'
    cfg.write_text('intent="intent.toml"\nsnapshots="history"\n[adapters.object-store]\ntype="s3"\nenforced="dynamic"\nread_timeout_seconds=2\n[adapters.object-store.planes.dynamic]\n' + source + '\nadmin_url_env="GRANTLINE_R3D_ADMIN"\nadmin_filer_url_env="GRANTLINE_R3D_ADMIN"\nadmin_auth_env="GRANTLINE_R3D_TOKEN"\n')
    (root / 'intent.toml').write_text('managed_subjects=["demo"]\nmanaged_systems=["object-store"]\n[[grants]]\nsystem="object-store"\nsubject="demo"\nresource="bucket:demo/team"\nprivs=["Read","Write"]\n')
    (root / 'trap.json').write_text(json.dumps(dict(identities=[dict(name='trap', actions=['Admin'])])))
    return cfg


def blind(plan):
    assert not plan['observed'] and not plan['changes'] and plan['unobserved'], plan
    assert not plan['observation_complete']


def xml(action, result):
    def add(parent, key, value):
        child = ET.SubElement(parent, key)
        if isinstance(value, dict):
            for k, v in value.items():
                add(child, k, v)
        elif isinstance(value, list):
            for v in value:
                add(child, 'member', v)
        else:
            child.text = str(value)
    root = ET.Element(action + 'Response', xmlns='https://iam.amazonaws.com/doc/2010-05-08/')
    add(root, action + 'Result', result)
    return ET.tostring(root)


def protocol(binary):
    state = dict(mode='healthy', calls=[], errors=[])
    files = {
        '/etc/iam/identities/demo.json': dict(name='demo', actions=['Admin'], credentials=[dict(secretKey=MARKER)]),
        '/etc/iam/identities/native.json': dict(name='native', actions=['Read:other']),
        '/etc/iam/groups/research.json': dict(name='research', members=['demo'], policy_names=['team']),
        '/etc/iam/policies/team.json': policy(),
        '/etc/iam/policies.json': {},
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, body, status=200, location=None):
            self.send_response(status)
            if location:
                self.send_header('Location', location)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            state['calls'].append(('GET', self.path))
            try:
                assert self.headers.get('Authorization') == 'Bearer ' + MARKER
                mode = state['mode']
                if mode == 'timeout':
                    time.sleep(3)
                if mode == 'redirect':
                    return self.send(b'', 302, '/leak')
                if mode == 'http403':
                    return self.send(MARKER.encode(), 403)
                if mode == 'bad-json':
                    return self.send(MARKER.encode())
                if mode == 'byte-cap':
                    return self.send(b' ' * (4 * 1024 * 1024 + 1))
                parsed = urllib.parse.urlsplit(self.path)
                path = parsed.path.removeprefix('/filer')
                if path == '/json':
                    value = dict(identities=[dict(name='demo', policy=policy(), credentials=[dict(secretKey=MARKER)])])
                    if mode == 'json-cap':
                        value['identities'] = [dict(name=f'user{i}', actions=[]) for i in range(10001)]
                    if mode == 'json-attachments':
                        value['identities'][0]['policy_names'] = ['missing']
                elif path.endswith('/'):
                    params = urllib.parse.parse_qs(parsed.query)
                    names = sorted(p for p in files if p.startswith(path))
                    after = params.get('lastFileName', [''])[0]
                    names = [p for p in names if p.rsplit('/', 1)[-1] > after]
                    first = names[:1]
                    value = dict(Path=path.rstrip('/'), Entries=[dict(FullPath=p, Mode=432) for p in first],
                                 LastFileName=first[-1].rsplit('/', 1)[-1] if first else '', ShouldDisplayLoadMore=len(names) > 1)
                    if mode == 'listing-field':
                        del value['ShouldDisplayLoadMore']
                    if mode == 'listing-escape' and first:
                        value['Entries'][0]['FullPath'] = '/outside/secret.json'
                    if mode == 'listing-loop':
                        value['ShouldDisplayLoadMore'] = True
                        value['LastFileName'] = after
                elif path in files:
                    value = files[path]
                    if mode == 'missing-policy' and '/policies/team' in path:
                        return self.send(MARKER.encode(), 404)
                else:
                    return self.send(b'', 404)
                self.send(json.dumps(value).encode())
            except Exception as exc:
                state['errors'].append(type(exc).__name__)
                self.send(b'fixture failed', 500)

        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            p = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode()).items()}
            action = p['Action']
            state['calls'].append(('POST', action))
            try:
                assert action in READS
                now = datetime.datetime.strptime(self.headers['X-Amz-Date'], '%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.UTC)
                url = f'http://{self.headers["Host"]}{self.path}'
                expected = sign('POST', url, KEY, SECRET, body, now=now, service='iam',
                                extra_headers={'Content-Type': 'application/x-www-form-urlencoded', 'X-Amz-Security-Token': MARKER})
                assert self.headers['Authorization'] == expected['authorization'], 'SigV4 mismatch'
                assert p['Version'] == '2010-05-08'
                mode = state['mode']
                if mode == 'iam-error':
                    return self.send(b'<ErrorResponse><Error>' + MARKER.encode() + b'</Error></ErrorResponse>')
                if mode == 'iam-dtd':
                    return self.send(b'<!DOCTYPE a [<!ENTITY x "secret">]><a>&x;</a>')
                user = p.get('UserName')
                result = {}
                if action == 'ListUsers':
                    users = ['demo'] if 'Marker' not in p else ['native']
                    if mode == 'iam-cap':
                        users = [f'user{i}' for i in range(10001)]
                    result = dict(Users=[dict(UserName=u) for u in users], IsTruncated='false' if 'Marker' in p or mode == 'iam-cap' else 'true', Marker='second')
                    if mode == 'iam-loop':
                        result['IsTruncated'] = 'true'
                    if mode == 'iam-truncation':
                        del result['IsTruncated']
                elif action == 'GetUser':
                    result = dict(User=dict(UserName=user))
                    if mode == 'iam-boundary' and user == 'demo':
                        result['User']['PermissionsBoundary'] = dict(PermissionsBoundaryArn=ARN)
                elif action in {'ListUserPolicies', 'ListGroupPolicies'}:
                    result = dict(PolicyNames=['personal'] if action == 'ListUserPolicies' and user == 'demo' else [], IsTruncated='false')
                elif action == 'GetUserPolicy':
                    result = dict(PolicyDocument=urllib.parse.quote(json.dumps(policy('demo/personal')), safe=''))
                elif action == 'ListAttachedUserPolicies':
                    if mode == 'iam-user-error' and user == 'demo':
                        return self.send(MARKER.encode(), 403)
                    result = dict(AttachedPolicies=[], IsTruncated='false')
                elif action == 'ListGroups':
                    result = dict(Groups=[dict(GroupName='research')], IsTruncated='false')
                elif action == 'GetGroup':
                    result = dict(Users=[dict(UserName='demo')], IsTruncated='false')
                    if mode == 'iam-group-status':
                        result['Group'] = dict(GroupName='research', Status='disabled')
                elif action == 'ListAttachedGroupPolicies':
                    result = dict(AttachedPolicies=[dict(PolicyName='team', PolicyArn=ARN)], IsTruncated='false')
                elif action == 'GetPolicy':
                    result = dict(Policy=dict(DefaultVersionId='v2'))
                elif action == 'GetPolicyVersion':
                    assert p['PolicyArn'] == ARN and p['VersionId'] == 'v2'
                    result = dict(PolicyVersion=dict(Document=urllib.parse.quote(json.dumps(policy()), safe='')))
                self.send(xml(action, result))
            except Exception as exc:
                state['errors'].append(type(exc).__name__)
                self.send(b'fixture failed', 500)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f'http://127.0.0.1:{server.server_port}'
        sources = {'json': 'url_env="GRANTLINE_R3D_ENDPOINT"\nauth_env="GRANTLINE_R3D_TOKEN"\nfile="trap.json"',
                   'filer': 'filer_url_env="GRANTLINE_R3D_ENDPOINT"\nfiler_auth_env="GRANTLINE_R3D_TOKEN"',
                   'iam': 'iam_url_env="GRANTLINE_R3D_ENDPOINT"\niam_key_env="GRANTLINE_R3D_KEY"\niam_secret_env="GRANTLINE_R3D_SECRET"\niam_session_token_env="GRANTLINE_R3D_TOKEN"'}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for kind, source in sources.items():
                config = config_at(root, source)
                url = endpoint + '/' + (kind + '/' if kind == 'iam' else kind)
                before = len(state['calls'])
                blind(run(binary, config, url, 'plan', '--json', live=False))
                assert len(state['calls']) == before
                plan = run(binary, config, url, 'plan', '--json')
                assert ('demo', 'bucket:demo/team', 'Read') in {(g['subject'], g['resource'], g['priv']) for g in plan['observed']}, plan
                assert plan['s3_previews'] and all(p['blocked'] and p['before'] is None and p['after'] is None for p in plan['s3_previews'])
                graph = run(binary, config, url, 'graph', '--subject', 'demo', '--json')
                assert graph['routes_from']['demo']['paths']
                if kind == 'iam':
                    assert any('native' in u['subjects'] for u in plan['unobserved'])
                    assert not any(e['src'] == 'demo' and e['dst'] == 'policy:' + ARN for e in graph['graph']['edges']), 'inherited policy gained direct route'
                saved = run(binary, config, url, 'snapshot', '--json')
                assert MARKER not in Path(saved['path']).read_text()
                before = len(state['calls'])
                imported = run(binary, config, 'invalid/' + MARKER, 'plan', '--observed', saved['path'], '--json', live=False)
                assert imported['observed'] == plan['observed'] and len(state['calls']) == before
                modes = ['redirect', 'http403', 'bad-json', 'byte-cap', 'timeout', 'json-cap', 'json-attachments'] if kind == 'json' else ['listing-field', 'listing-escape', 'listing-loop', 'missing-policy'] if kind == 'filer' else ['iam-error', 'iam-dtd', 'iam-cap', 'iam-loop', 'iam-truncation', 'iam-group-status']
                for mode in modes:
                    state['mode'] = mode
                    blind(run(binary, config, url, 'plan', '--json'))
                state['mode'] = 'healthy'
                if kind == 'iam':
                    state['mode'] = 'iam-boundary'
                    boundary = run(binary, config, url, 'plan', '--json')
                    assert not any(g['subject'] == 'demo' for g in boundary['observed'])
                    assert not any(c['grant']['subject'] == 'demo' for c in boundary['changes'])
                    state['mode'] = 'iam-user-error'
                    partial = run(binary, config, url, 'plan', '--json')
                    assert not any(g['subject'] == 'demo' for g in partial['observed'])
                    assert not any(c['grant']['subject'] == 'demo' for c in partial['changes'])
                    state['mode'] = 'healthy'
            assert not any('/leak' in call[1] for call in state['calls'])
            assert not state['errors'], state['errors']
            config = config_at(root, sources['json'] + '\nfiler_url_env="GRANTLINE_R3D_ENDPOINT"')
            blind(run(binary, config, endpoint, 'plan', '--json'))
            for url in ['file:///tmp/iam', endpoint + '/json?key=' + MARKER, endpoint + '/json#fragment', 'http://reader:' + MARKER + '@localhost/']:
                config = config_at(root, sources['json'])
                blind(run(binary, config, url, 'plan', '--json'))
            print('S3 HTTP: 3 readers, read-only/source isolation, SigV4 oracle, pagination, policy routes, snapshot/graph, 17 transport/collection failures, permissions boundary and URL/provider guards passed')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def docker_test(binary, context):
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    info = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert info['Endpoints']['docker']['Host'].startswith('unix://'), 'test requires a local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-r3d-' + uuid.uuid4().hex[:12]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixtures = root / 'fixtures'
        fixtures.mkdir(mode=0o755)
        seed = fixtures / 's3.json'
        seed.write_text(json.dumps(dict(identities=[dict(name='observer', credentials=[dict(accessKey=KEY, secretKey=SECRET)], actions=['Admin'])])))
        # The official entrypoint drops to seaweed; expose only these synthetic fixture files.
        fixtures.chmod(0o755)
        seed.chmod(0o644)
        try:
            subprocess.run([*docker, 'run', '-d', '--name', name, '--memory', '1g', '--cpus', '2',
                            '-p', '127.0.0.1::8888', '-p', '127.0.0.1::8333', '-p', '127.0.0.1::8334',
                            '--mount', f'type=bind,source={fixtures},target=/fixtures,readonly', IMAGE,
                            'server', '-dir=/data', '-ip=127.0.0.1', '-ip.bind=0.0.0.0', '-filer', '-s3',
                            '-s3.config=/fixtures/s3.json', '-s3.iam.readOnly=false', '-master.telemetry=false',
                            '-master.volumeSizeLimitMB=8', '-volume.max=1', '-s3.port.iceberg=0', '-s3.port.lance=0'], check=True, stdout=subprocess.DEVNULL)
            ports = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']
            filer = 'http://127.0.0.1:' + ports['8888/tcp'][0]['HostPort']
            iam = 'http://127.0.0.1:' + ports['8333/tcp'][0]['HostPort'] + '/'
            readonly = 'http://127.0.0.1:' + ports['8334/tcp'][0]['HostPort'] + '/'

            def call(action, **params):
                body = urllib.parse.urlencode(dict(Action=action, Version='2010-05-08', **params)).encode()
                headers = sign('POST', iam, KEY, SECRET, body, service='iam', extra_headers={'Content-Type': 'application/x-www-form-urlencoded'})
                with opener.open(urllib.request.Request(iam, data=body, headers=headers), timeout=5) as response:
                    return ET.fromstring(response.read())

            deadline = time.monotonic() + 60
            while True:
                try:
                    call('ListUsers')
                    break
                except (OSError, ET.ParseError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Disposable SeaweedFS failed to start') from None
                    time.sleep(0.2)
            call('CreateUser', UserName='demo')
            call('CreateUser', UserName='native')
            call('CreateUser', UserName='managed')
            call('CreateGroup', GroupName='research')
            call('AddUserToGroup', GroupName='research', UserName='demo')
            call('CreatePolicy', PolicyName='team', PolicyDocument=json.dumps(policy()))
            call('AttachGroupPolicy', GroupName='research', PolicyArn='arn:aws:iam:::policy/team')
            call('AttachUserPolicy', UserName='managed', PolicyArn='arn:aws:iam:::policy/team')
            call('PutGroupPolicy', GroupName='research', PolicyName='group-personal', PolicyDocument=json.dumps(policy('demo/group-inline')))
            call('PutUserPolicy', UserName='demo', PolicyName='personal', PolicyDocument=json.dumps(policy('demo/personal')))
            subprocess.run([*docker, 'exec', '-d', name, 'weed', 's3', '-filer=127.0.0.1:8888', '-port=8334',
                            '-config=/fixtures/s3.json', '-iam.readOnly=true', '-port.iceberg=0', '-port.lance=0'], check=True)
            writable = iam
            iam = readonly
            deadline = time.monotonic() + 30
            while True:
                try:
                    call('ListUsers')
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Read-only IAM gateway failed to start') from None
                    time.sleep(0.2)
            cfg = config_at(root, 'iam_url_env="GRANTLINE_R3D_ENDPOINT"\niam_key_env="GRANTLINE_R3D_KEY"\niam_secret_env="GRANTLINE_R3D_SECRET"')
            cfg.write_text(cfg.read_text().replace('read_timeout_seconds=2', 'read_timeout_seconds=10'))
            result = run(binary, cfg, iam, 'plan', '--json')
            assert ('demo', 'bucket:demo/team', 'Read') in {(g['subject'], g['resource'], g['priv']) for g in result['observed']}, result
            assert any('native' in u['subjects'] for u in result['unobserved'])
            assert any(g['subject'] == 'managed' and g['resource'] == 'bucket:demo/team' for g in result['observed'])
            assert any(g['subject'] == 'demo' and g['resource'] == 'bucket:demo/group-inline' for g in result['observed'])
            try:
                call('CreateUser', UserName='forbidden')
            except urllib.error.HTTPError as exc:
                error = ET.fromstring(exc.read())
                code = next((e.text for e in error.iter() if e.tag.rsplit('}', 1)[-1] == 'Code'), '')
                message = next((e.text for e in error.iter() if e.tag.rsplit('}', 1)[-1] == 'Message'), '').lower().replace('-', ' ')
                assert exc.code == 403 and code == 'AccessDenied' and ('read only' in message or 'write operations' in message), (code, message.replace(MARKER.lower(), '[redacted]'))
            else:
                raise AssertionError('Read-only IAM gateway accepted write')
            # Filer HTTP uses the same stored advanced IAM tree, no mirror on disk.
            cfg = config_at(root, 'filer_url_env="GRANTLINE_R3D_ENDPOINT"')
            result = run(binary, cfg, filer, 'plan', '--json')
            assert ('demo', 'bucket:demo/team', 'Read') in {(g['subject'], g['resource'], g['priv']) for g in result['observed']}, result
            assert any(g['subject'] == 'managed' and g['resource'] == 'bucket:demo/team' for g in result['observed']), result
            assert any(g['subject'] == 'demo' and g['resource'] == 'bucket:demo/group-inline' for g in result['observed']), result
            assert result['s3_previews'] and all(p['blocked'] for p in result['s3_previews'])
            assert 'forbidden' not in ET.tostring(call('ListUsers')).decode()
            assert writable != readonly
            # A direct Filer writer changes only an owning fixture identity, even when another identity is unknown.
            direct_url = filer + '/etc/iam/identities/parity.json'
            direct = dict(name='parity', actions=['Read:demo/parity/*'], credentials=[dict(accessKey='GLPARITY', secretKey=SECRET)])
            urllib.request.urlopen(urllib.request.Request(direct_url, data=json.dumps(direct).encode(), method='PUT', headers={'Content-Type':'application/json'}), timeout=5).close()
            cfg.write_text(cfg.read_text().replace('admin_filer_url_env="GRANTLINE_R3D_ADMIN"', 'admin_filer_url_env="GRANTLINE_R3D_ENDPOINT"'))
            (root / 'intent.toml').write_text('managed_subjects=["parity"]\nmanaged_systems=["object-store"]\n[[grants]]\nsystem="object-store"\nsubject="parity"\nresource="bucket:demo/parity"\nprivs=["Read","Write"]\n')
            args = ['apply','--system','object-store','--subject','parity','--json']
            preview = run(binary, cfg, filer, *args)
            assert preview['changed'] and not preview['applied']
            result = run(binary, cfg, filer, *args, '--write','--expect',preview['plan_id'])
            assert result['applied'] and not result['concurrent_admin_guarantee']
            with urllib.request.urlopen(direct_url, timeout=5) as response:
                after = json.load(response)
            assert after['credentials'] == direct['credentials'] and 'Write:demo/parity/*' in after['actions']
            assert not run(binary, cfg, filer, *args)['changed']
            # The unrelated policy and membership still resolve after the write.
            final = run(binary, cfg, filer, 'plan', '--json')
            assert any(g['subject']=='demo' and g['resource']=='bucket:demo/team' for g in final['observed'])
            print('SeaweedFS Docker: actual SigV4 IAM reads, nested policy routes, no-policy unknown, server-side IAM write refusal, direct Filer IAM tree and isolated owning-identity writer/no-op with unchanged keys/inheritance passed')
        except Exception:
            logs = subprocess.run([*docker, 'logs', '--tail', '80', name], text=True, capture_output=True, timeout=10)
            diagnostic = (logs.stdout + logs.stderr).replace(SECRET, '[redacted]').replace(MARKER, '[redacted]')
            print(diagnostic[-10000:], file=sys.stderr)
            raise
        finally:
            subprocess.run([*docker, 'rm', '-f', '-v', name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


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
