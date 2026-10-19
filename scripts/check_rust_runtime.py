#!/usr/bin/env python3
"""Isolated parallel-read/cache, private env_file, verified TLS and drift-notify contracts."""
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'rust/target/debug/grantline-rs'
MARKER = 'NEVER-OUTPUT-SYNTHETIC-TOKEN'


def main():
    state = dict(active=0, peak=0, gets=0, posts=[])
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            with lock:
                state['gets'] += 1
                state['active'] += 1
                state['peak'] = max(state['peak'], state['active'])
            try:
                time.sleep(.08)
                body = json.dumps({'identities': [{'name': 'demo', 'actions': ['Read:demo/team']}]}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                with lock:
                    state['active'] -= 1

        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            state['posts'].append((self.path, json.loads(body)))
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"ok":true,"ts":"1"}')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    child = None
    tls_server = None
    try:
        with tempfile.TemporaryDirectory(prefix='grantline-runtime-') as tmp:
            work = Path(tmp)
            intent = work / 'intent.toml'
            intent.write_text('')
            cfg = work / 'config.toml'
            common = 'intent="intent.toml"\nsnapshots="history"\n[web]\ncache_ttl_seconds=60\n'
            adapters = ''.join(f'\n[adapters.demo{i}]\ntype="s3"\n[adapters.demo{i}.planes.static]\nurl_env="GL_RUNTIME_ENDPOINT"\n' for i in range(3))
            cfg.write_text(common + adapters)
            env = dict(os.environ, GL_RUNTIME_ENDPOINT=f'http://127.0.0.1:{server.server_port}/iam', GL_RUNTIME_TOKEN=MARKER)

            def run(*args, config=cfg, environ=env, ok=True):
                r = subprocess.run([str(BINARY), '-c', str(config), *args], cwd=ROOT, env=environ, capture_output=True, text=True, timeout=30)
                assert MARKER not in r.stdout + r.stderr
                assert (r.returncode == 0) == ok, r.stderr
                return json.loads(r.stdout) if ok else r

            plan = run('plan', '--live', '--json')
            assert len(plan['observed']) == 3 and not plan['unobserved']
            assert state['peak'] == 3, state
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            child = subprocess.Popen([str(BINARY), '-c', str(cfg), 'serve', '--live', '--port', str(port)], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            def catalog(query=''):
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/catalog{query}', timeout=10) as r:
                    return json.load(r)
            for _ in range(100):
                try:
                    catalog()
                    break
                except OSError:
                    assert child.poll() is None
                    time.sleep(.02)
            else:
                raise AssertionError('console did not start')
            count = state['gets']
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                rows = list(pool.map(lambda _: catalog(), range(24)))
            assert all(len(r['plan']['observed']) == 3 for r in rows)
            assert state['gets'] == count, 'warm readers repeated network observation'
            catalog('?refresh=1')
            assert state['gets'] == count + 3
            intent.write_text('managed_subjects=[]\n')
            catalog()
            assert state['gets'] == count + 6, 'intent revision must invalidate the cache'
            child.terminate()
            child.wait(timeout=10)
            child = None

            # Startup loads a private env_file before creating runtime threads.
            env_file = work / '.env'
            env_file.write_text(f'GL_RUNTIME_ENDPOINT={env["GL_RUNTIME_ENDPOINT"]}\nGL_RUNTIME_TOKEN={MARKER}\n')
            env_file.chmod(0o600)
            cfg.write_text('env_file=".env"\n' + common + adapters)
            isolated = {k: v for k, v in env.items() if not k.startswith('GL_RUNTIME_')}
            assert len(run('plan', '--live', '--json', environ=isolated)['observed']) == 3
            env_file.chmod(0o644)
            run('plan', '--live', '--json', environ=isolated, ok=False)
            env_file.chmod(0o600)

            # Positive TLS, untrusted roots and hostname mismatch use the same mock.
            def openssl(*args):
                subprocess.run(['openssl', *args], cwd=work, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=Grantline Test CA', '-addext', 'basicConstraints=critical,CA:TRUE')
            openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost')
            (work / 'extensions').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
            openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'extensions')
            tls_server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(work / 'server.pem', work / 'server.key')
            tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
            threading.Thread(target=tls_server.serve_forever, daemon=True).start()
            env.update(GL_RUNTIME_CA=str(work / 'ca.pem'), GL_RUNTIME_ENDPOINT=f'https://localhost:{tls_server.server_port}/iam')
            cfg.write_text(common + adapters.replace('url_env="GL_RUNTIME_ENDPOINT"', 'url_env="GL_RUNTIME_ENDPOINT"\nca_bundle_env="GL_RUNTIME_CA"'))
            assert len(run('plan', '--live', '--json')['observed']) == 3
            env['GL_RUNTIME_ENDPOINT'] = f'https://127.0.0.1:{tls_server.server_port}/iam'
            wrong = run('plan', '--live', '--json')
            assert not wrong['observed'] and len(wrong['unobserved']) == 3
            env['GL_RUNTIME_ENDPOINT'] = f'https://localhost:{tls_server.server_port}/iam'
            cfg.write_text(common + adapters)
            assert not run('plan', '--live', '--json')['observed'], 'untrusted CA must not work'

            # Notifications hit only the disposable local HTTP mock, never Slack.
            env['GL_RUNTIME_ENDPOINT'] = f'http://127.0.0.1:{server.server_port}/iam'
            cfg.write_text(common + adapters + f'\n[notify.slack]\nbot_token_env="GL_RUNTIME_TOKEN"\nchannel="demo-channel"\napi_url="http://127.0.0.1:{server.server_port}/"\n')
            first = run('notify', '--live', '--json')
            assert first['comparison'] is None and not first['sent']
            second = run('notify', '--live', '--json')
            assert not second['sent'] and not state['posts']
            third = run('notify', '--live', '--send', '--json')
            assert third['sent'] and len(state['posts']) == 1
            assert state['posts'][0][0] == '/chat.postMessage'
            assert state['posts'][0][1]['channel'] == 'demo-channel'
            print('Native runtime: parallel reads, shared cache/refresh/revision invalidation, private env_file, verified private CA/hostname and isolated drift notification passed.')
    finally:
        if child:
            child.terminate()
            child.wait(timeout=10)
        server.shutdown()
        server.server_close()
        if tls_server:
            tls_server.shutdown()
            tls_server.server_close()


if __name__ == '__main__':
    main()
