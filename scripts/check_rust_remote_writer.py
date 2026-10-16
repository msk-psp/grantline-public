#!/usr/bin/env python3
"""Conditional remote JSON writes, private recovery, conflict and uncertain outcomes."""
import hashlib
import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKER = 'synthetic-remote-fixture'


def main():
    original = json.dumps({'identities': [{'name': 'demo', 'actions': ['Read:probe/old/*'], 'credentials': [{'accessKey': 'demo-key', 'secretKey': MARKER}]}]}).encode()
    state = dict(body=original, mode='normal', puts=0, gets=0)

    def etag():
        return '"' + hashlib.sha256(state['body']).hexdigest() + '"'

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            assert self.path == '/iam.json' and self.headers['Authorization'] == 'Bearer ' + MARKER
            state['gets'] += 1
            self.send_response(200)
            if state['mode'] != 'missing':
                self.send_header('ETag', ('W/' if state['mode'] == 'weak' else '') + etag())
            self.end_headers()
            self.wfile.write(state['body'])

        def do_PUT(self):
            assert self.path == '/iam.json' and self.headers['Authorization'] == 'Bearer ' + MARKER
            state['puts'] += 1
            data = self.rfile.read(int(self.headers['Content-Length']))
            if state['mode'] == 'conflict' or self.headers.get('If-Match') != etag():
                self.send_response(412)
            elif state['mode'] == 'redirect':
                self.send_response(302)
                self.send_header('Location', '/leak')
            else:
                if state['mode'] != 'ineffective':
                    state['body'] = data
                self.send_response(500 if state['mode'] == 'error' else 200)
            self.end_headers()
            self.wfile.write(MARKER.encode())

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.toml'
            config.write_text('intent="intent.toml"\n[adapters.s3]\ntype="s3"\nread_timeout_seconds=3\n[adapters.s3.planes.static]\nurl_env="GL_REMOTE_READER"\nadmin_url_env="GL_REMOTE_ADMIN"\nadmin_auth_env="GL_REMOTE_AUTH"\nconditional_write=true\n')
            (root / 'intent.toml').write_text('managed_subjects=["demo"]\n[[grants]]\nsystem="s3"\nsubject="demo"\nresource="bucket:probe/team"\nprivs=["Read"]\n')
            env = dict(os.environ, GL_REMOTE_ADMIN=f'http://127.0.0.1:{server.server_port}/iam.json', GL_REMOTE_AUTH=MARKER, GL_REMOTE_READER='http://127.0.0.1:1/never')

            def run(*args, ok=True):
                r = subprocess.run([str(ROOT / 'rust/target/debug/grantline-rs'), '-c', str(config), *args, '--system', 's3', '--json'], env=env, text=True, capture_output=True, timeout=10)
                assert MARKER not in r.stdout + r.stderr
                assert (r.returncode == 0) == ok, r.stderr
                return json.loads(r.stdout) if ok else r.stderr

            for mode in ['normal', 'conflict', 'error', 'redirect', 'ineffective']:
                state.update(body=original, mode=mode, puts=0, gets=0)
                p = run('apply', '--live')
                assert p['changed'] and not p['applied'] and not list(root.glob('*.backup.json'))
                run('apply', '--live', '--write', '--expect', 'stale', ok=False)
                assert state['puts'] == 0
                if mode == 'normal':
                    applied = run('apply', '--live', '--write', '--expect', p['plan_id'])
                    assert applied['applied'] and not applied['service_reload_verified']
                    b = Path(applied['backup'])
                    assert b.stat().st_mode & 0o777 == 0o600
                    assert json.loads(state['body'])['identities'][0]['credentials'][0]['secretKey'] == MARKER
                    after = state['body']
                    run('restore', '--live', '--backup', str(b))
                    assert state['body'] == after
                    restored = run('restore', '--live', '--backup', str(b), '--write')
                    assert restored['restored'] and state['body'] == original
                    run('restore', '--live', '--backup', str(b), '--write', ok=False)
                else:
                    error = run('apply', '--live', '--write', '--expect', p['plan_id'], ok=False)
                    assert ('conflict' if mode == 'conflict' else 'unknown') in error
                    assert state['puts'] == 1
                for b in root.glob('*.backup.json'):
                    b.unlink()
            for mode in ['weak', 'missing']:
                state.update(body=original, mode=mode, puts=0)
                run('apply', '--live', ok=False)
                assert state['puts'] == 0
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    print('PASS: remote conditional JSON preview/write, stale and 412 conflicts, private byte-exact restore, preserved credentials, no retry/redirect and uncertain post-dispatch outcomes')


if __name__ == '__main__':
    main()
