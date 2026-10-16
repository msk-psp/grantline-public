#!/usr/bin/env python3
"""Verify local IAM grant/revoke/restore using a disposable official SeaweedFS server."""
import argparse
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from check_rust_s3_probes import IMAGE, OPENER, sign

ROOT = Path(__file__).resolve().parents[1]
SECRET = 'NEVER-OUTPUT-CREDENTIAL-synthetic'


def native(binary, config, *args, mask=None):
    result = subprocess.run([binary, '-c', str(config), *args, '--json'], text=True,
                            capture_output=True, cwd='/', timeout=20,
                            preexec_fn=(lambda: os.umask(mask)) if mask is not None else None)
    assert SECRET not in result.stdout + result.stderr
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def docker_test(binary, context):
    context = context or subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    info = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]
    assert info['Endpoints']['docker']['Host'].startswith('unix://'), 'requires local Docker socket'
    docker = ['docker', '--context', context]
    name = 'grantline-r3f-' + uuid.uuid4().hex[:12]
    # Opening a FIFO before checking its type would hang the writer indefinitely.
    for filename in ['iam.json', 'config.toml', 'intent.toml']:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            config = root / 'config.toml'
            config.write_text('intent="intent.toml"\n[adapters.s3]\ntype="s3"\n[adapters.s3.planes.static]\nfile="iam.json"\n')
            (root / 'intent.toml').write_text('')
            (root / 'iam.json').write_text('{"identities":[]}')
            (root / filename).unlink()
            os.mkfifo(root / filename, 0o600)
            result = subprocess.run([binary, '-c', str(config), 'apply', '--system', 's3', '--json'],
                                    text=True, capture_output=True, timeout=5)
            assert result.returncode != 0 and 'regular file' in result.stderr
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        fixtures = root / 'fixtures'
        fixtures.mkdir(mode=0o755)
        fixtures.chmod(0o755)
        source = fixtures / 'iam.json'
        source.write_text(json.dumps(dict(identities=[
            dict(name='observer', actions=['Admin'], credentials=[dict(accessKey='GLOBServer', secretKey=SECRET)]),
            dict(name='demo', actions=['Read:probe/old/*'], credentials=[dict(accessKey='GLSUBJECT', secretKey=SECRET)])
        ]), indent=2) + '\n')
        source.chmod(0o644)
        original = source.read_bytes()
        config = root / 'config.toml'
        config.write_text('intent="intent.toml"\n[adapters.s3]\ntype="s3"\n[adapters.s3.planes.static]\nfile="fixtures/iam.json"\n')
        (root / 'intent.toml').write_text('managed_subjects=["demo"]\n[[grants]]\nsystem="s3"\nsubject="demo"\nresource="bucket:probe/team"\nprivs=["Read"]\n')
        preview = native(binary, config, 'apply', '--system', 's3')
        assert source.read_bytes() == original and len(list(fixtures.iterdir())) == 1
        assert preview['previews'][0]['after'] == ['Read:probe/team/*']

        def check_server(allowed, denied):
            try:
                subprocess.run([*docker, 'run', '-d', '--name', name, '--memory', '1g', '--cpus', '2', '-p', '127.0.0.1::8333',
                                '--mount', f'type=bind,source={fixtures},target=/fixtures,readonly', IMAGE,
                                'server', '-dir=/data', '-ip=127.0.0.1', '-ip.bind=0.0.0.0', '-filer', '-s3', '-s3.config=/fixtures/iam.json',
                                '-master.telemetry=false', '-master.volumeSizeLimitMB=8', '-volume.max=1', '-s3.port.iceberg=0', '-s3.port.lance=0'],
                               check=True, stdout=subprocess.DEVNULL)
                ports = json.loads(subprocess.check_output([*docker, 'inspect', name], text=True))[0]['NetworkSettings']['Ports']
                endpoint = 'http://127.0.0.1:' + ports['8333/tcp'][0]['HostPort']

                def request(method, path, key='GLOBServer', body=None, query=''):
                    url = endpoint + '/' + urllib.parse.quote(path, safe='/') + query
                    req = urllib.request.Request(url, data=body, headers=sign(method, url, key, SECRET, body or b''), method=method)
                    try:
                        with OPENER.open(req, timeout=5) as r:
                            return r.status
                    except urllib.error.HTTPError as exc:
                        return exc.code

                deadline = time.monotonic() + 60
                while True:
                    try:
                        if request('PUT', 'probe', body=b'') == 200:
                            break
                    except OSError:
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Disposable SeaweedFS failed to start')
                    time.sleep(0.2)
                obj = 'sample +%漢?.txt'
                for scope in ('old', 'team', 'team-sibling'):
                    assert request('PUT', f'probe/{scope}/{obj}', body=b'synthetic fixture') == 200
                assert request('HEAD', f'probe/{allowed}/{obj}', key='GLSUBJECT') == 200
                for scope in [denied, 'team-sibling']:
                    assert request('HEAD', f'probe/{scope}/{obj}', key='GLSUBJECT') == 403, scope
                assert request('GET', 'probe', key='GLSUBJECT', query='?list-type=2&max-keys=1') == 403
                assert request('PUT', f'probe/{allowed}/forbidden', key='GLSUBJECT', body=b'forbidden') == 403
                assert request('DELETE', f'probe/{allowed}/{obj}', key='GLSUBJECT') == 403
                assert request('HEAD', f'probe/{allowed}/{obj}') == 200
                assert request('HEAD', f'probe/{allowed}/forbidden') == 404
            finally:
                subprocess.run([*docker, 'rm', '-f', '-v', name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)

        check_server('old', 'team')
        # A strict caller umask must not leave an unreadable/non-restorable backup.
        lock = fixtures / '.iam.json.grantline.lock'
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        applied = native(binary, config, 'apply', '--system', 's3', '--write', '--expect', preview['plan_id'], mask=0o777)
        assert applied['applied'] and not applied['service_reload_verified']
        updated = json.loads(source.read_bytes())
        assert updated['identities'][0] == json.loads(original)['identities'][0]
        assert updated['identities'][1]['credentials'] == json.loads(original)['identities'][1]['credentials']
        assert os.stat(applied['backup']).st_mode & 0o777 == 0o600
        assert json.loads(Path(applied['backup']).read_bytes())['before'].encode() == original
        check_server('team', 'old')
        restored = native(binary, config, 'restore', '--system', 's3', '--backup', applied['backup'], '--write')
        assert restored['restored'] and not restored['service_reload_verified']
        assert source.read_bytes() == original
        check_server('old', 'team')
        print('SeaweedFS local writer: before -> applied -> exact restore, actual scoped SigV4 HEAD, revoked/sibling denial, Read never grants List/PUT/DELETE, unchanged credentials, private backup and denied-write absence passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'rust/target/debug/grantline-rs')
    parser.add_argument('--docker', action='store_true', required=True, help='required; local safety tests run with cargo test')
    parser.add_argument('--docker-context')
    args = parser.parse_args()
    docker_test(str(args.binary.resolve()), args.docker_context)


if __name__ == '__main__':
    main()
