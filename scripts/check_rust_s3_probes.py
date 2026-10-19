#!/usr/bin/env python3
"""Read-only subject S3 probes: independent SigV4 oracle, HTTP boundaries and SeaweedFS."""
import argparse
import datetime
import hashlib
import hmac
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
from xml.sax.saxutils import escape

from check_rust_s3_network import IMAGE

ROOT = Path(__file__).resolve().parents[1]
KEY = 'GLSUBJECT'
SECRET = 'NEVER-OUTPUT-CREDENTIAL-synthetic'
TOKEN = 'SYNTHETIC-SESSION-TOKEN'
OBJECT = 'PRIVATE-OBJECT +%漢?.txt'
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def sign(method, url, key, secret, body=b'', timestamp=None, token=None, region='us-east-1', extra_headers=None):
    """Independent oracle: raw encoded URI, encoded/sorted query and SHA256/HMAC chain."""
    stamp = timestamp or datetime.datetime.now(datetime.UTC).strftime('%Y%m%dT%H%M%SZ')
    parsed = urllib.parse.urlsplit(url)
    digest = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
    headers = {'host': parsed.netloc, 'x-amz-date': stamp, 'x-amz-content-sha256': digest(body)}
    headers.update(extra_headers or {})
    if token:
        headers['x-amz-security-token'] = token
    names = ';'.join(sorted(headers))
    query = '&'.join(f'{k}={v}' for k, v in sorted((urllib.parse.quote(k, safe='-_.~'), urllib.parse.quote(v, safe='-_.~'))
                                                for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    canonical = '\n'.join([method, parsed.path or '/', query, ''.join(f'{k}:{headers[k].strip()}\n' for k in sorted(headers)), names, digest(body)])
    scope = f'{stamp[:8]}/{region}/s3/aws4_request'
    hashed = ('AWS4' + secret).encode()
    for part in (stamp[:8], region, 's3', 'aws4_request'):
        hashed = hmac.new(hashed, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(hashed, f'AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{digest(canonical.encode())}'.encode(), hashlib.sha256).hexdigest()
    headers['authorization'] = f'AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders={names}, Signature={signature}'
    return {k: v for k, v in headers.items() if k != 'host'}


def config_at(root, subjects=('demo',)):
    path = root / 'config.toml'
    text = 'intent="intent.toml"\nsnapshots="history"\n[adapters.s3]\ntype="s3"\nenforced="static"\nendpoint_env="GL_PROBE_ENDPOINT"\nread_timeout_seconds=2\n[adapters.s3.planes.static]\nfile="iam.json"\n'
    text += ''.join(f'[adapters.s3.probe_credentials.{json.dumps(s)}]\nkey_env="GL_PROBE_KEY"\nsecret_env="GL_PROBE_SECRET"\n' for s in subjects)
    path.write_text(text)
    (root / 'intent.toml').write_text('managed_subjects=[]\nmanaged_systems=[]\n')
    # The IAM observer must never become a source of probe credentials.
    (root / 'iam.json').write_text(json.dumps(dict(identities=[dict(name='demo', actions=['List:probe', 'Read:probe/team'], credentials=[dict(accessKey='GLOBServer', secretKey=SECRET)])])))
    return path


def baseline(root, rows):
    path = root / 'baseline.jsonl'
    records = [dict(run=dict(ts='2026-10-01T00:00:00+00:00', user='demo', systems=['s3']))]
    records += [dict(grant=dict(system='s3', subject=s, resource=r, priv=p)) for s, r, p in rows]
    path.write_text(''.join(json.dumps(r) + '\n' for r in records))
    return path


def run(binary, config, endpoint, observed=None, live=True, extra=None, write=False):
    env = dict(os.environ, GL_PROBE_ENDPOINT=endpoint or '', GL_PROBE_KEY=KEY, GL_PROBE_SECRET=SECRET,
               AWS_ACCESS_KEY_ID='GLOBServer', AWS_SECRET_ACCESS_KEY=SECRET,
               HTTP_PROXY='http://127.0.0.1:1', HTTPS_PROXY='http://127.0.0.1:1', ALL_PROXY='http://127.0.0.1:1')
    for k, v in (extra or {}).items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    command = [binary, '-c', str(config), 'probe', '--json']
    if observed:
        command += ['--observed', str(observed)]
    if live:
        command += ['--live']
    if write:
        command += ['--write']
    result = subprocess.run(command, cwd='/', env=env, text=True, capture_output=True, timeout=40)
    assert result.returncode == 0, result.stderr
    assert all(s not in result.stdout + result.stderr for s in [SECRET, TOKEN, OBJECT, urllib.parse.quote(OBJECT, safe='')]), 'secret or sampled object name escaped output'
    return json.loads(result.stdout)


def unknown(report, count):
    assert report['summary'] == dict(allow=0, deny=0, unknown=count), report
    assert not report['findings']


def protocol(binary):
    state = dict(mode='ok', calls=[], writes=0, token=None)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_probe(self, method):
            state['calls'].append((method, self.path))
            u = urllib.parse.urlsplit(self.path)
            args = urllib.parse.parse_qs(u.query, keep_blank_values=True)
            mode = state['mode']
            stamp = self.headers.get('x-amz-date', '')
            url = f'http://{self.headers["Host"]}{self.path}'
            expected = sign(method, url, KEY, SECRET, timestamp=stamp, token=state['token'])
            matches = all(self.headers.get(k) == v for k, v in expected.items())
            status, headers, body = 200, {}, b''
            assert SECRET not in self.path and 'Credential=' not in self.path
            assert u.path.startswith('/gateway/probe')
            if method == 'GET':
                assert args['list-type'] == ['2'] and args['max-keys'] == ['1'] and args['encoding-type'] == ['url']
                prefix = args['prefix'][0]
                key = prefix + OBJECT
                encode = lambda s: escape(urllib.parse.quote(s, safe=''))  # noqa: E731
                if mode == 'form-encoded':
                    encode = lambda s: escape(urllib.parse.quote_plus(s, safe=''))  # noqa: E731
                contents = f'<Contents><Key>{encode(key)}</Key></Contents>'
                count = 1
                if mode == 'empty':
                    contents, count = '', 0
                if mode == 'escaped':
                    contents = '<Contents><Key>outside%2Fobject</Key></Contents>'
                body = (f'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>probe</Name><Prefix>{encode(prefix)}</Prefix>'
                        f'<EncodingType>url</EncodingType><MaxKeys>1</MaxKeys><KeyCount>{count}</KeyCount><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>').encode()
                if mode == 'duplicate':
                    body = body.replace(b'<MaxKeys>1</MaxKeys>', b'<MaxKeys>1</MaxKeys><MaxKeys>1</MaxKeys>')
                if mode == 'wrong-bucket':
                    body = body.replace(b'<Name>probe</Name>', b'<Name>another</Name>')
                if mode == 'wrong-count':
                    body = body.replace(b'<KeyCount>1', b'<KeyCount>2')
                if mode == 'bad-xml':
                    body = b'<html>' + SECRET.encode()
                if mode == 'dtd':
                    body = b'<!DOCTYPE x [<!ENTITY a "secret">]>' + body
                if mode == 'wrong-namespace':
                    body = body.replace(b'http://s3.amazonaws.com/doc/2006-03-01/', b'http://example.com/not-s3')
                if mode == 'byte-limit':
                    body = b'x' * (1024 * 1024 + 1)
                if mode == 'total-bytes':
                    body = body.replace(b'</ListBucketResult>', b'<!--' + b'x' * (1024 * 1024 - 1000) + b'--></ListBucketResult>')
            else:
                assert not args and urllib.parse.unquote(u.path).endswith(OBJECT)
                headers.update(ETag='"synthetic"', **{'Content-Length': '123'})
                if mode == 'head-bad-metadata':
                    headers = {}
                if mode in {'head403', 'head-deny', 'head-expired'}:
                    status = 403
                    if mode != 'head403':
                        headers['x-amz-error-code'] = 'AccessDenied' if mode == 'head-deny' else 'ExpiredToken'
            if not matches or mode in {'denied', 'invalid-key', 'invalid-signature', 'expired', 'http500'}:
                status = 403
                code = dict(denied='AccessDenied', **{'invalid-key': 'InvalidAccessKeyId', 'invalid-signature': 'SignatureDoesNotMatch', 'expired': 'ExpiredToken'}).get(mode, 'SignatureDoesNotMatch')
                body = f'<Error><Code>{code}</Code><Message>{SECRET}</Message></Error>'.encode()
                if mode == 'http500':
                    status = 500
            if mode == 'redirect':
                status, headers = 302, dict(Location=f'http://127.0.0.1:{self.server.server_port}/leak')
            if mode == 'late-timeout':
                time.sleep(0.65)
            if mode == 'timeout':
                time.sleep(2.2)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            if 'Content-Length' not in headers:
                self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if method != 'HEAD':
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def do_GET(self):
            self.handle_probe('GET')

        def do_HEAD(self):
            self.handle_probe('HEAD')

        def do_PUT(self):
            state['writes'] += 1
            self.send_error(405)

        do_DELETE = do_PUT
        do_POST = do_PUT

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f'http://127.0.0.1:{server.server_port}/gateway/'
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = config_at(root)
            b = baseline(root, [('demo', 'bucket:probe/team', p) for p in ['List', 'Read', 'Write']])
            unknown(run(binary, config, endpoint, b, live=False), 3)
            assert not state['calls']
            healthy = run(binary, config, endpoint, b)
            assert healthy['summary'] == dict(allow=2, deny=0, unknown=1), healthy
            assert len(state['calls']) == 2, 'List and Read must share one sampled listing'
            state.update(mode='form-encoded', calls=[])
            assert run(binary, config, endpoint, b)['summary'] == healthy['summary']
            state.update(mode='ok', calls=[])
            live = run(binary, config, endpoint)
            assert live['summary']['allow'] == 2, live
            original = config.read_text()
            config.write_text(original + 'session_token_env="GL_SESSION"\n')
            state['token'] = TOKEN
            assert run(binary, config, endpoint, b, extra={'GL_SESSION': TOKEN})['summary'] == healthy['summary']
            unknown(run(binary, config, endpoint, b, extra={'GL_SESSION': None}), 3)
            config.write_text(original)
            state['token'] = None
            for mode in ['invalid-key', 'invalid-signature', 'expired', 'http500', 'redirect', 'bad-xml', 'dtd', 'wrong-namespace', 'duplicate', 'wrong-bucket', 'wrong-count', 'escaped', 'byte-limit', 'timeout']:
                state.update(mode=mode, calls=[])
                failed = run(binary, config, endpoint, b)
                unknown(failed, 3)
                if mode == 'redirect':
                    assert len(state['calls']) == 1
            state.update(mode='denied', calls=[])
            denied = run(binary, config, endpoint, b)
            assert denied['summary'] == dict(allow=0, deny=1, unknown=2) and len(denied['findings']) == 1
            for mode in ['empty', 'head403', 'head-expired', 'head-bad-metadata']:
                state.update(mode=mode, calls=[])
                r = run(binary, config, endpoint, b)
                assert r['summary'] == dict(allow=1, deny=0, unknown=2), (mode, r)
            state.update(mode='head-deny', calls=[])
            r = run(binary, config, endpoint, b)
            assert r['summary'] == dict(allow=1, deny=1, unknown=1)
            # Read-only credentials can use a configured sample without ListBucket.
            config.write_text(original + '[adapters.s3.probe_objects]\n"bucket:probe/team"=' + json.dumps('team/' + OBJECT) + '\n')
            b = baseline(root, [('demo', 'bucket:probe/team', 'Read')])
            state.update(mode='ok', calls=[])
            assert run(binary, config, endpoint, b)['summary']['allow'] == 1 and state['calls'][0][0] == 'HEAD'
            config.write_text(config.read_text().replace(json.dumps('team/' + OBJECT), '"outside/key"'))
            state['calls'] = []
            unknown(run(binary, config, endpoint, b), 1)
            assert not state['calls']
            config.write_text(original)
            for extra in [{'GL_PROBE_KEY': None}, {'GL_PROBE_SECRET': None}, {'GL_PROBE_SECRET': 'WRONG-SYNTHETIC'}]:
                unknown(run(binary, config, endpoint, b, extra=extra), 1)
            config.write_text(original.split('[adapters.s3.probe_credentials.')[0])
            state['calls'] = []
            unknown(run(binary, config, endpoint, b), 1)
            assert not state['calls'], 'IAM file/AWS/admin credentials must not be consumed'
            config.write_text(original)
            for bad in [None, endpoint + '?password=bad', endpoint.replace('http:', 'https:'), 'file:///tmp/not-s3', 'http://user:password@localhost/']:
                unknown(run(binary, config, bad, b), 1)
            unsupported = baseline(root, [('demo', r, 'Read') for r in ['bucket:*', 'bucket:probe/team*/nested', 'bucket:probe/a/../b', 'role:reader']])
            state['calls'] = []
            unknown(run(binary, config, endpoint, unsupported), 4)
            assert not state['calls']
            # Total budget expiry must invalidate the earlier successful scope.
            slow = baseline(root, [('demo', 'bucket:probe/a', 'List'), ('demo', 'bucket:probe/z', 'List')])
            config.write_text(original.replace('read_timeout_seconds=2', 'read_timeout_seconds=1'))
            state.update(mode='late-timeout', calls=[])
            r = run(binary, config, endpoint, slow)
            unknown(r, 2)
            assert all('partial results discarded' in p['how'] for p in r['probes'])
            config.write_text(original.replace('read_timeout_seconds=2', 'read_timeout_seconds=30'))
            state.update(mode='ok', calls=[])
            large = baseline(root, [('demo', f'bucket:probe/scope{i}', 'Read') for i in range(257)])
            r = run(binary, config, endpoint, large)
            unknown(r, 257)
            assert len(state['calls']) == 512 and all('budget' in p['how'] for p in r['probes'])
            state.update(mode='total-bytes', calls=[])
            large = baseline(root, [('demo', f'bucket:probe/scope{i}', 'List') for i in range(17)])
            unknown(run(binary, config, endpoint, large), 17)
            assert not state['writes']
            print('S3 probe HTTP: independent GET/HEAD SigV4 encoding and session-token oracle, scope/cache isolation, 14 error cases, real AccessDenied vs auth/generic HEAD failures, explicit samples, no credential fallback, total deadline/request/byte budgets, zero writes and redaction passed')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def docker_test(binary, context):
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    info = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert info['Endpoints']['docker']['Host'].startswith('unix://'), 'requires local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-r3e3-' + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixtures = root / 'fixtures'
        fixtures.mkdir(mode=0o755)
        fixtures.chmod(0o755)
        # SeaweedFS native object scopes require a wildcard to cover descendant keys.
        accounts = [('observer', 'GLOBServer', ['Admin']), ('demo', KEY, ['List:probe', 'Read:probe/team/*']),
                    ('write-test', 'GLWRITE', ['Write:probe/team/*']), ('read-only', 'GLREADONLY', ['Read:probe/team/*']), ('list-only', 'GLLISTONLY', ['List:probe']), ('denied', 'GLDENIED', ['List:another'])]
        seed = fixtures / 's3.json'
        seed.write_text(json.dumps(dict(identities=[dict(name=n, credentials=[dict(accessKey=k, secretKey=SECRET)], actions=a) for n, k, a in accounts])))
        seed.chmod(0o644)
        try:
            subprocess.run([*docker, 'run', '-d', '--name', name, '--memory', '1g', '--cpus', '2', '-p', '127.0.0.1::8333',
                            '--mount', f'type=bind,source={fixtures},target=/fixtures,readonly', IMAGE,
                            'server', '-dir=/data', '-ip=127.0.0.1', '-ip.bind=0.0.0.0', '-filer', '-s3', '-s3.config=/fixtures/s3.json',
                            '-master.telemetry=false', '-master.volumeSizeLimitMB=8', '-volume.max=1', '-s3.port.iceberg=0', '-s3.port.lance=0'], check=True, stdout=subprocess.DEVNULL)
            ports = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']
            endpoint = 'http://127.0.0.1:' + ports['8333/tcp'][0]['HostPort']

            def call(method, path, key='GLOBServer', body=None):
                url = endpoint + '/' + urllib.parse.quote(path, safe='/')
                req = urllib.request.Request(url, data=body, headers=sign(method, url, key, SECRET, body or b''), method=method)
                return OPENER.open(req, timeout=5)

            deadline = time.monotonic() + 60
            while True:
                try:
                    with call('PUT', 'probe', body=b''):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Disposable SeaweedFS failed to start') from None
                    time.sleep(0.2)
            with call('PUT', 'probe/team/' + OBJECT, body=b'synthetic data never read by probe'):
                pass
            config = config_at(root)
            original = config.read_text()
            b = baseline(root, [('demo', 'bucket:probe/team', p) for p in ['List', 'Read', 'Write']])
            r = run(binary, config, endpoint, b)
            assert r['summary'] == dict(allow=2, deny=0, unknown=1), r
            # Existing object only; all native traffic is listing or HEAD, no content GET.
            state = [('denied', 'GLDENIED', 'List', dict(allow=0, deny=1, unknown=0)),
                     ('read-only', 'GLREADONLY', 'Read', dict(allow=0, deny=0, unknown=1)),
                     ('list-only', 'GLLISTONLY', 'Read', dict(allow=0, deny=0, unknown=1))]
            for subject, key, privilege, expected in state:
                config_at(root, (subject,))
                b = baseline(root, [(subject, 'bucket:probe/team', privilege)])
                r = run(binary, config, endpoint, b, extra={'GL_PROBE_KEY': key})
                assert r['summary'] == expected, r
            config_at(root, ('read-only',))
            config.write_text(config.read_text() + '[adapters.s3.probe_objects]\n"bucket:probe/team"=' + json.dumps('team/' + OBJECT) + '\n')
            b = baseline(root, [('read-only', 'bucket:probe/team', 'Read')])
            assert run(binary, config, endpoint, b, extra={'GL_PROBE_KEY': 'GLREADONLY'})['summary']['allow'] == 1
            config.write_text(original)
            b = baseline(root, [('demo', 'bucket:probe/empty', 'Read')])
            unknown(run(binary, config, endpoint, b), 1)
            b = baseline(root, [('demo', 'bucket:probe/team', 'List')])
            for extra in [{'GL_PROBE_KEY': 'GLDOESNOTEXIST'}, {'GL_PROBE_SECRET': 'WRONG-SYNTHETIC'}]:
                unknown(run(binary, config, endpoint, b, extra=extra), 1)
            try:
                with call('PUT', 'probe/team/forbidden', key=KEY, body=b'forbidden'):
                    raise AssertionError('Subject accepted an ungranted write')
            except urllib.error.HTTPError as exc:
                assert exc.code == 403
            try:
                with call('HEAD', 'probe/team/forbidden'):
                    raise AssertionError('Forbidden write left an object')
            except urllib.error.HTTPError as exc:
                assert exc.code == 404
            config_at(root, ('write-test',))
            b = baseline(root, [('write-test', 'bucket:probe/team', 'Write')])
            result = run(binary, config, endpoint, b, extra={'GL_PROBE_KEY': 'GLWRITE'}, write=True)
            assert result['summary'] == dict(allow=1, deny=0, unknown=0), result
            assert 'probe object deleted' in result['probes'][0]['how'], result
            url = endpoint + '/probe?list-type=2&prefix=team%2F_grantline-probe%2F'
            with OPENER.open(urllib.request.Request(url, headers=sign('GET', url, 'GLOBServer', SECRET)), timeout=5) as response:
                assert b'<Contents>' not in response.read(), 'write probe object was not cleaned up'
            print('SeaweedFS S3 probes: actual encoded-key SigV4 List/HEAD, read-only sample without List, List AccessDenied, ambiguous HEAD/empty scope, invalid keys/signature, default-off Write, independent write refusal and explicit unique-object PUT/DELETE cleanup passed')
        finally:
            subprocess.run([*docker, 'rm', '-f', '-v', name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'rust/target/debug/grantline-rs')
    parser.add_argument('--docker', action='store_true')
    parser.add_argument('--docker-context')
    args = parser.parse_args()
    protocol(str(args.binary.resolve()))
    if args.docker:
        docker_test(str(args.binary.resolve()), args.docker_context)


if __name__ == '__main__':
    main()
