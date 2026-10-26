#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Firmware-only Secure Boot qualification; no kernel or system image."""
import argparse
import datetime
import struct
import shutil
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid
from store_audit import check_revocation, X509
from auth_update import create


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('probe', 'update-probe', 'firmware', 'variables', 'vars-tool', 'openssl',
                 'uefisign', 'makefs', 'mkimg', 'qemu', 'qemu-data', 'work'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    paths = {name: value.resolve(strict=True) for name, value in vars(a).items() if name != 'work'}
    work = a.work.resolve()
    if not work.is_relative_to('/usr/obj/usr/src') or work == Path('/usr/obj/usr/src'):
        p.error('work must be a new directory below /usr/obj/usr/src')
    inputs = {name: {'path': str(path), 'sha256': digest(path)}
              for name, path in paths.items() if path.is_file()}
    work.mkdir(parents=True, mode=0o700)
    keys = work / 'keys'
    keys.mkdir(mode=0o700)
    here = Path(__file__).resolve().parent
    sources = {str(path): digest(path) for path in here.glob("*.py")}
    results = {}
    with (work / 'prepare.log').open('w') as log:
        def run(*args):
            subprocess.run([str(v) for v in args], check=True, stdout=log, stderr=log)
        for name in ('PK', 'KEK', 'db', 'secondary', 'replacement', 'stranger'):
            run(paths['openssl'], 'req', '-new', '-x509', '-newkey', 'rsa:3072',
                '-noenc', '-keyout', keys / (name + '.key'), '-out', keys / (name + '.pem'),
                '-days', '7', '-sha256', '-subj', '/CN=5BSD disposable firmware test ' + name,
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign')
            (keys / (name + '.key')).chmod(0o600)
        owner = str(uuid.uuid4())
        run(paths['vars_tool'], '--input', paths['variables'], '--output', work / 'enrolled.fd',
            '--set-pk', owner, keys / 'PK.pem', '--add-kek', owner, keys / 'KEK.pem',
            '--add-db', owner, keys / 'db.pem', '--add-db', owner, keys / 'secondary.pem',
            '--secure-boot', '--no-microsoft')
        # Offline trust-store construction tests boot-time dbx enforcement; it
        # does not exercise authenticated SetVariable or a live key transition.
        run(paths['vars_tool'], '--input', work / 'enrolled.fd',
            '--output', work / 'revoked.fd', '--add-dbx-cert', owner, keys / 'db.pem')
        for name in ('enrolled', 'revoked'):
            run(paths['vars_tool'], '--input', work / (name + '.fd'),
                '--output-json', work / (name + '.json'))
        for name in ('db', 'secondary'):
            run(paths['openssl'], 'x509', '-in', keys / (name + '.pem'),
                '-outform', 'DER', '-out', keys / (name + '.der'))
        check_revocation(json.loads((work / 'enrolled.json').read_text()),
                         json.loads((work / 'revoked.json').read_text()),
                         (keys / 'db.der').read_bytes(), (keys / 'secondary.der').read_bytes())
        for name in ('db', 'secondary', 'replacement', 'stranger'):
            run(paths['uefisign'], '-k', keys / (name + '.key'), '-c', keys / (name + '.pem'),
                '-o', work / (name + '.efi'), paths['probe'])
        run(paths['uefisign'], '-k', keys / 'db.key', '-c', keys / 'db.pem',
            '-o', work / 'update.efi', paths['update_probe'])
        run(paths['uefisign'], '-k', keys / 'replacement.key', '-c', keys / 'replacement.pem',
            '-o', work / 'update-replacement.efi', paths['update_probe'])
        run(paths['openssl'], 'x509', '-in', keys / 'replacement.pem',
            '-outform', 'DER', '-out', keys / 'replacement.der')
        replacement = (keys / 'replacement.der').read_bytes()
        payload = (X509 + struct.pack('<III', 44 + len(replacement), 0, 16 + len(replacement)) +
                   uuid.UUID(owner).bytes_le + replacement)
        update_inputs = work / 'update-inputs'
        update_inputs.mkdir()
        (update_inputs / 'db.expected').write_bytes(payload)
        data = bytearray((work / 'db.efi').read_bytes())
        marker = 'FIRMWARE_PROBE_EXECUTED'.encode('utf-16le')
        if data.count(marker) != 1:
            raise ValueError('probe must contain one execution message for payload tampering')
        offset = data.index(marker)
        data[offset] = ord('X')
        (work / 'tampered.efi').write_bytes(data)
        (work / 'tamper.json').write_text(json.dumps({'input_sha256': digest(work / 'db.efi'),
            'output_sha256': digest(work / 'tampered.efi'), 'offset': offset,
            'before': ord('F'), 'after': ord('X')}, indent=2) + '\n')
        for name, probe, variables, expect, control in (
            ('setup', paths['probe'], paths['variables'], 'disabled', None),
            ('approved', work / 'db.efi', work / 'enrolled.fd', 'enabled', None),
            ('unsigned', paths['probe'], work / 'enrolled.fd', 'rejected', 'approved'),
            ('stranger', work / 'stranger.efi', work / 'enrolled.fd', 'rejected', 'approved'),
            ('tampered', work / 'tampered.efi', work / 'enrolled.fd', 'rejected', 'approved'),
            ('secondary', work / 'secondary.efi', work / 'enrolled.fd', 'enabled', None),
            ('revocation-control', work / 'secondary.efi', work / 'revoked.fd', 'enabled', None),
            ('revoked-signer', work / 'db.efi', work / 'revoked.fd', 'rejected', 'revocation-control'),
            ('replacement-before', work / 'replacement.efi', work / 'enrolled.fd', 'rejected', 'approved'),
            ('auth-update', work / 'update.efi', work / 'enrolled.fd', 'auth-update', None),
            ('replacement-after', work / 'replacement.efi', work / 'auth-update/vars.fd', 'enabled', None),
            ('retired-after', work / 'db.efi', work / 'auth-update/vars.fd', 'rejected', 'replacement-after'),
            ('auth-replay', work / 'update-replacement.efi', work / 'auth-update/vars.fd', 'auth-replay', None)):
            command = [sys.executable, '-B', here / 'run.py', '--probe', probe,
                       '--variables', variables, '--work', work / name, '--expect', expect]
            for field in ('firmware', 'qemu', 'qemu_data', 'makefs', 'mkimg'):
                command += ['--' + field.replace('_', '-'), paths[field]]
            if expect == 'auth-update':
                # Earlier VM controls ensure this is a later whole-second timestamp.
                timestamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
                for label, signer in (('valid', 'KEK'), ('invalid', 'stranger')):
                    create(paths['openssl'], 'db', timestamp, payload, keys / (signer + '.key'),
                           keys / (signer + '.pem'), update_inputs / ('db.' + label + '.auth'))
                (update_inputs / 'timestamp.txt').write_text(timestamp.isoformat() + '\n')
                command += ['--data-root', update_inputs]
            if expect == 'auth-replay':
                replay_inputs = work / 'replay-inputs'
                replay_inputs.mkdir()
                for file in ('db.expected', 'db.valid.auth'):
                    shutil.copyfile(update_inputs / file, replay_inputs / file)
                newer = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
                previous = datetime.datetime.fromisoformat((update_inputs / 'timestamp.txt').read_text().strip())
                if newer <= previous:
                    raise ValueError('clock did not advance beyond the prior update')
                create(paths['openssl'], 'db', newer, payload, keys / 'KEK.key',
                       keys / 'KEK.pem', replay_inputs / 'db.newer.auth')
                (replay_inputs / 'timestamp.txt').write_text(newer.isoformat() + '\n')
                command += ['--data-root', replay_inputs]
            if expect == 'rejected':
                command += ['--control', work / control / 'result.json']
            run(*command)
            result = work / name / 'result.json'
            if json.loads(result.read_text())['result'] != 'PASS':
                raise ValueError('case did not pass: ' + name)
            results[name] = digest(result)
        run(paths['vars_tool'], '--input', work / 'auth-update/vars.fd',
            '--output-json', work / 'updated.json')
        updated = json.loads((work / 'updated.json').read_text())
        databases = [v for v in updated['variables'] if v['name'] == 'db' and
                     v['guid'] == 'd719b2cb-3d3a-4596-a3bc-dad00e67656f']
        if (len(databases) != 1 or databases[0]['attr'] != 39 or
                bytes.fromhex(databases[0]['data']) != payload):
            raise ValueError('persisted authenticated db update differs')
    for value in inputs.values():
        if digest(Path(value['path'])) != value['sha256']:
            raise ValueError('suite input changed: ' + value['path'])
    for path, expected in sources.items():
        if digest(Path(path)) != expected:
            raise ValueError('suite source changed: ' + path)
    (work / 'result.json').write_text(json.dumps({'scope': 'firmware-only', 'result': 'PASS',
        'inputs': inputs, 'cases_sha256': results,
        'sources_sha256': sources,
        'store_audit': 'only-dbx-certificate-append',
        'store_exports_sha256': {name: digest(work / name) for name in ('enrolled.json', 'revoked.json')},
        'loader_qualified': False, 'system_boot_qualified': False,
        'certificate_revocation_enforcement_qualified': True,
        'trust_stores_sha256': {name: digest(work / name) for name in ('enrolled.fd', 'revoked.fd')},
        'certificates_sha256': {path.name: digest(path) for path in keys.glob('*.pem')},
        'authenticated_db_replacement_qualified': True,
        'cross_boot_db_replay_qualified': True,
        'updated_store_export_sha256': digest(work / 'updated.json'),
        'key_lifecycle_qualified': False}, indent=2) + '\n')
    print(work / 'result.json')


if __name__ == '__main__':
    main()
