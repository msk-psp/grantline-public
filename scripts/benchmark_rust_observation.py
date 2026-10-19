#!/usr/bin/env python3
"""Reproducible local fixture and three-service latency comparison; no real services."""
import argparse
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
WORKER = '''import json,sys
sys.path.insert(0,sys.argv[1])
from grantline.cli import _load,_observe_and_plan
it,adapters,_,_,_= _load(sys.argv[2])
o,changes,f,u,_,unknown=_observe_and_plan(it,adapters)
print(json.dumps(dict(observed=sorted([[g.system,g.subject,g.resource,g.priv] for g in o]),changes=sum(len(c.all_grants) for c in changes),unknown=len(unknown))))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'rust/target/release/grantline-rs')
    parser.add_argument('--runs', type=int, default=12)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    assert 3 <= args.runs <= 100
    s = dict(active=0, peak=0, calls=0)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            with lock:
                s['active'] += 1
                s['peak'] = max(s['peak'], s['active'])
                s['calls'] += 1
            try:
                time.sleep(.1)
                body = b'{"identities":[{"name":"demo","actions":["Read:demo/team/*"]}]}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                with lock:
                    s['active'] -= 1

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    child = None
    try:
        with tempfile.TemporaryDirectory(prefix='grantline-observation-benchmark-') as tmp:
            work = Path(tmp)
            worker = work / 'worker.py'
            worker.write_text(WORKER)
            cfg = work / 'grantline.toml'
            (work / 'intent.toml').write_text('')
            cfg.write_text('intent="intent.toml"\n[web]\ncache_ttl_seconds=60\n' + ''.join(f'[adapters.s3-{i}]\ntype="s3"\n[adapters.s3-{i}.planes.static]\nurl_env="GL_BENCH_ENDPOINT"\n' for i in range(3)))
            env = dict(os.environ, GL_BENCH_ENDPOINT=f'http://127.0.0.1:{server.server_port}/iam')
            results = dict(runs=args.runs, includes='process startup, imports/config, observation, planning, JSON output', cases={})
            for label, config, live in [('fixture', ROOT / 'examples/demo/grantline.toml', False), ('three_100ms_services', cfg, True)]:
                timings = {'python': [], 'rust_release': []}
                peaks = {}
                commands = {'python': [sys.executable, str(worker), str(ROOT), str(config)], 'rust_release': [str(args.binary.resolve()), '-c', str(config), 'plan', '--json', *(['--live'] if live else [])]}
                expected = None
                for _ in range(args.runs):
                    for runtime, command in commands.items():
                        s['peak'] = 0
                        started = time.perf_counter()
                        r = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
                        elapsed = (time.perf_counter() - started) * 1000
                        assert r.returncode == 0, r.stderr
                        value = json.loads(r.stdout)
                        if runtime == 'rust_release':
                            value = dict(observed=sorted([[g['system'],g['subject'],g['resource'],g['priv']] for g in value['observed']]), changes=len(value['changes']), unknown=len(value['unobserved']))
                        expected = value if expected is None else expected
                        assert value == expected, 'observed permissions/plans differ'
                        timings[runtime].append(elapsed)
                        peaks[runtime] = max(peaks.get(runtime, 0), s['peak'])
                results['cases'][label] = dict(grants=len(expected['observed']), changes=expected['changes'], unknown=expected['unknown'], runtimes={name: dict(median_ms=round(statistics.median(ts),3),p95_ms=round(sorted(ts)[int((len(ts)-1)*.95)],3),peak_remote_reads=peaks[name]) for name,ts in timings.items()})
            with socket.socket() as free:
                free.bind(('127.0.0.1', 0))
                port = free.getsockname()[1]
            child = subprocess.Popen([str(args.binary.resolve()), '-c', str(cfg), 'serve', '--live', '--host', '127.0.0.1', '--port', str(port)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            url = f'http://127.0.0.1:{port}/api/catalog'
            for _ in range(200):
                try:
                    with urllib.request.urlopen(url, timeout=3) as response:
                        assert len(json.load(response)['plan']['observed']) == 3
                    break
                except OSError:
                    assert child.poll() is None
                    time.sleep(.03)
            else:
                raise RuntimeError('cache benchmark server unavailable')
            calls = s['calls']; times=[]
            for _ in range(24):
                started = time.perf_counter()
                with urllib.request.urlopen(url, timeout=3) as response:
                    assert len(json.load(response)['plan']['observed']) == 3
                times.append((time.perf_counter()-started)*1000)
            assert s['calls'] == calls
            results['warm_console'] = dict(requests=24,additional_remote_reads=s['calls']-calls,median_ms=round(statistics.median(times),3),p95_ms=round(sorted(times)[22],3))
            if args.output:
                args.output.write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps(results, indent=2))
    finally:
        if child:
            child.terminate()
            child.wait(timeout=5)
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
