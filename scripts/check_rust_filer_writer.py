#!/usr/bin/env python3
"""Filer identity writes preserve source secrets, attachments and review boundaries."""
import base64
import copy
import hashlib
import hmac
import json
import os
import stat
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MARKER = 'SYNTHETIC-FILER-SECRET-DO-NOT-PRINT'


def main():
    original = dict(name='demo', actions=['Read:demo/team'], credentials=[dict(accessKey='demo', secretKey=MARKER)])
    s = dict(identity=copy.deepcopy(original), writes=0, mode='', revision=1, errors=[])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, value, status=200):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('ETag', '"' + str(s['revision']) + '"')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            if self.headers.get('Authorization') != 'Bearer ' + MARKER:
                return self.send({}, 401)
            if path == '/etc/iam/identities/demo.json':
                return self.send(s['identity'])
            if path.endswith('/'):
                names = ['/etc/iam/identities/demo.json'] if path.endswith('/identities/') else []
                if s['mode'] == 'inherited' and path.endswith('/policies/'):
                    names = ['/etc/iam/policies/team.json']
                return self.send(dict(Path=path.rstrip('/'), Entries=[dict(FullPath=p, Mode=432) for p in names], LastFileName='', ShouldDisplayLoadMore=False))
            if path == '/etc/iam/policies/team.json':
                return self.send(dict(Version='2012-10-17', Statement=[dict(Effect='Allow', Action=['s3:GetObject'], Resource=['arn:aws:s3:::demo/team/*'])]))
            return self.send({}, 404)

        def do_PUT(self):
            try:
                assert self.path == '/etc/iam/identities/demo.json'
                token = self.headers['Authorization'].removeprefix('Bearer ')
                a, b, sig = token.split('.')
                expected = base64.urlsafe_b64encode(hmac.new(MARKER.encode(), (a + '.' + b).encode(), hashlib.sha256).digest()).decode().rstrip('=')
                assert hmac.compare_digest(sig, expected)
                exp = json.loads(base64.urlsafe_b64decode(b + '=' * (-len(b) % 4)))['exp']
                assert time.time() < exp <= time.time() + 11
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if s['mode'] == 'conflict':
                    return self.send({}, 412)
                assert self.headers['If-Match'] == '"' + str(s['revision']) + '"'
                s['identity'] = body
                s['revision'] += 1
                s['writes'] += 1
                self.send({})
            except Exception as exc:
                s['errors'].append(type(exc).__name__)
                self.send({}, 500)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='grantline-filer-') as tmp:
            root = Path(tmp)
            cfg = root / 'grantline.toml'
            cfg.write_text('intent="intent.toml"\n[adapters.s3]\ntype="s3"\nenforced="filer"\n[adapters.s3.planes.filer]\nfiler_url_env="GL_FILER_URL"\nfiler_auth_env="GL_FILER_TOKEN"\nadmin_filer_url_env="GL_FILER_URL"\nadmin_filer_jwt_env="GL_FILER_TOKEN"\nconditional_write=true\n')
            desired = root / 'intent.toml'
            desired.write_text('managed_subjects=["demo"]\nmanaged_systems=["s3"]\n[[grants]]\nsystem="s3"\nsubject="demo"\nresource="bucket:demo/team"\nprivs=["Read","Write"]\n')
            env = dict(os.environ, GL_FILER_URL=f'http://127.0.0.1:{server.server_port}', GL_FILER_TOKEN=MARKER)

            def run(*extra, ok=True):
                r = subprocess.run([str(ROOT / 'rust/target/debug/grantline-rs'), '-c', str(cfg), 'apply', '--system', 's3', '--live', '--json', *extra], env=env, text=True, capture_output=True, timeout=20)
                assert MARKER not in r.stdout + r.stderr
                assert (r.returncode == 0) == ok, r.stderr
                return json.loads(r.stdout) if ok else r

            p = run()
            assert p['changed'] and not p['applied'] and s['writes'] == 0
            desired.write_text(desired.read_text() + '\n')
            run('--write', '--expect', p['plan_id'], ok=False)
            assert s['writes'] == 0
            p = run()
            s['mode'] = 'conflict'
            assert 'revision conflict' in run('--write', '--expect', p['plan_id'], ok=False).stderr
            assert s['identity'] == original
            s['mode'] = ''
            result = run('--write', '--expect', p['plan_id'])
            assert result['applied'] and not result['concurrent_admin_guarantee']
            assert s['identity']['credentials'] == original['credentials']
            assert any(a in ['Write:demo/team', 'Write:demo/team/*'] for a in s['identity']['actions']), s['identity']['actions']
            backup = Path(result['backup'])
            assert stat.S_IMODE(backup.stat().st_mode) == 0o600
            assert json.loads(backup.read_text())['before'] == original
            assert not run()['changed']
            run('--write', '--expect', p['plan_id'], ok=False)
            s['identity']['unmodelled'] = True
            before = s['writes']
            run(ok=False)
            assert s['writes'] == before
            s['identity'] = dict(name='demo', actions=[], policy_names=['team'], credentials=original['credentials'])
            s['mode'] = 'inherited'
            before = s['writes']
            run(ok=False)
            assert s['writes'] == before and not s['errors'], s['errors']
        print('Filer writer: preview/no-op, stale review, JWT, ETag conflict, private backup, credential/metadata preservation and inherited-policy refusal passed')
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
