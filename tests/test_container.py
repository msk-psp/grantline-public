"""Container binding stays opt-in; --image additionally checks the actual Docker runtime."""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from grantline import cli, web

root = Path(__file__).resolve().parent.parent
config = str(root / 'examples/demo/grantline.toml')
for args, host in (([], '127.0.0.1'), (['--host', '0.0.0.0'], '0.0.0.0')):
    with patch.object(web, 'serve') as serve:
        assert cli.main(['-c', config, 'serve', *args]) == 0
        assert serve.call_args.kwargs['host'] == host
    with patch.object(web, 'HTTPServer') as server:
        web.serve(lambda: (set(), [], []), 8420, host=host)
        assert server.call_args.args[0] == (host, 8420)
print('ok CLI bind address reaches HTTPServer; loopback remains the default')


def smoke(image):
    def docker(*args):
        return subprocess.check_output(['docker', *args], text=True).strip()
    docker('run', '--rm', '--entrypoint', 'python', image, '-c',
           'from pathlib import Path; p=Path("/app"); '
           'assert not any((p/n).exists() for n in ("grantline.toml", ".git", "demo/snapshots", "demo/audit.jsonl", "demo/approvals")); '
           'assert not list(p.rglob("*.env"))')
    container = docker('run', '--rm', '-d', '-p', '127.0.0.1::8420', image)
    try:
        port = docker('port', container, '8420/tcp').rsplit(':', 1)[1]
        base = 'http://127.0.0.1:' + port
        def request(path, **kwargs):
            req = urllib.request.Request(base + path, headers={'Host': 'localhost:8420', **kwargs.pop('headers', {})}, **kwargs)
            return urllib.request.urlopen(req, timeout=3)
        deadline = time.monotonic() + 30
        while True:
            try:
                with request('/login') as response: assert response.status == 200
                break
            except (OSError, urllib.error.URLError):
                if time.monotonic() >= deadline:
                    raise AssertionError('container did not become ready: ' + docker('logs', container)) from None
                time.sleep(.2)
        for locale in ('en', 'ko', 'ja', 'zh-CN'):
            for path in ('/', '/login', '/services', '/matrix', '/act'):
                with request(path, headers={'Cookie': 'grantline_lang=' + locale}) as response:
                    body = response.read().decode()
                    assert response.status == 200 and f'<html lang="{locale}">' in body
        with request('/api/graph.json') as response:
            data = json.load(response)
            assert {'postgres', 'postgres-staging', 'clickhouse', 's3'} <= data['instances'].keys()
        for logo in ('postgresql.png', 'seaweedfs.png'):
            with request('/static/' + logo) as response:
                assert response.headers['Content-Type'] == 'image/png'
                assert response.read() == (web._STATIC / logo).read_bytes()
        try:
            request('/services', headers={'Host': 'untrusted.example'})
            raise AssertionError('untrusted Host was accepted')
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
        assert docker('exec', container, 'python', '-c', 'import os, psycopg; print(os.geteuid()); print(psycopg.__version__)').splitlines()[0] == '10001'
        assert docker('inspect', container, '--format', '{{.State.Running}}') == 'true'
        print('ok Docker runtime: non-root, PostgreSQL driver, demo, four locales, images, Host boundary')
    finally:
        subprocess.run(['docker', 'stop', '-t', '2', container], check=True, stdout=subprocess.DEVNULL)


if sys.argv[1:2] == ['--image']:
    smoke(sys.argv[2])
