#!/usr/bin/env python3
"""S3 write probes are explicit, conditionally unique and report cleanup failure."""
import json
import subprocess
import tempfile
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from check_rust_s3_probes import ROOT, KEY, SECRET, sign, config_at, baseline, run


def main():
    s = dict(mode='allow', calls=[], keys=[], errors=[])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_write(self):
            try:
                s['calls'].append(self.command)
                assert self.path.startswith('/probe/team/_grantline-probe/')
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                put = self.command == 'PUT'
                assert body == (b'grantline probe\n' if put else b'')
                extra = {'if-none-match': '*'} if put else {}
                if put:
                    assert self.headers['If-None-Match'] == '*'
                    s['keys'].append(self.path)
                expected = sign(self.command, f'http://{self.headers["Host"]}{self.path}', KEY, SECRET, body, timestamp=self.headers['X-Amz-Date'], extra_headers=extra)
                assert self.headers['Authorization'] == expected['authorization']
                if s['mode'] == 'disconnect' and put:
                    self.close_connection = True
                    return
                status = 403 if (s['mode'] == 'deny' and put or s['mode'] == 'cleanup-failure' and not put) else 412 if s['mode'] == 'collision' and put else 200 if put else 204
                payload = b'<Error><Code>AccessDenied</Code></Error>' if status == 403 else b''
                self.send_response(status)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as exc:
                s['errors'].append(type(exc).__name__)
                self.send_error(500)

        do_PUT = handle_write
        do_DELETE = handle_write

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = config_at(root)
            observed = baseline(root, [('demo', 'bucket:probe/team', 'Write')])
            binary = str(ROOT / 'rust/target/debug/grantline-rs')
            endpoint = f'http://127.0.0.1:{server.server_port}'
            assert run(binary, cfg, endpoint, observed)['summary']['unknown'] == 1 and not s['calls']
            refused = subprocess.run([binary, '-c', str(cfg), 'probe', '--write'], capture_output=True, timeout=5)
            assert refused.returncode != 0 and not s['calls']
            for mode, verdict, calls, note in [('allow', 'allow', ['PUT', 'DELETE'], 'probe object deleted'), ('deny', 'deny', ['PUT'], 'PUT failed'), ('collision', 'unknown', ['PUT'], 'PUT failed'), ('cleanup-failure', 'allow', ['PUT', 'DELETE'], 'LEFT BEHIND'), ('disconnect', 'unknown', ['PUT'], 'outcome unknown')]:
                s.update(mode=mode, calls=[])
                result = run(binary, cfg, endpoint, observed, write=True)
                assert result['summary'][verdict] == 1 and s['calls'] == calls, result
                assert note in result['probes'][0]['how'], result
            assert len(s['keys']) == len(set(s['keys'])) and not s['errors'], s
            print('S3 Write probe: explicit live/write, independent conditional PUT/DELETE signatures, unique keys, ACL denial, collision, cleanup failure and uncertain PUT reporting passed')
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
