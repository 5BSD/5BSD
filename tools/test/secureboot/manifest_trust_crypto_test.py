# SPDX-License-Identifier: BSD-2-Clause
"""Prepare disposable signers and qualify native manifest trust, without firmware."""
import argparse
import importlib.util
import json
import hashlib
import tempfile
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]

def prepare(work, openssl, roles=('firmware', 'generation', 'application', 'repository')):
    os.umask(0o077)
    work.mkdir(mode=0o700, parents=False, exist_ok=False)
    spec = importlib.util.spec_from_file_location('generation_boot',
        ROOT / 'tools/build/capimage/generation_boot.py')
    boot = importlib.util.module_from_spec(spec); spec.loader.exec_module(boot)
    for role in roles:
        directory = work / role; directory.mkdir(mode=0o700)
        key, cert = directory / 'private.key', directory / 'public.crt'
        subprocess.run([str(openssl), 'req', '-new', '-x509', '-newkey', 'rsa:3072',
            '-noenc', '-sha256', '-days', '2', '-keyout', str(key), '-out', str(cert),
            '-subj', '/CN=5BSD DISPOSABLE ' + role,
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign'],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        key.chmod(0o600)
        artifacts, report = boot.sign_loader_manifest(b'kernel sha256=' + b'a'*64 + b'\n',
            dict(key=str(key), certificate=str(cert), openssl=str(openssl)), directory)
        for name, data in artifacts.items():
            (directory / name).write_bytes(data)
        (directory / 'signing.json').write_text(json.dumps(report, sort_keys=True) + '\n')

def qualify(work, firmware_probe, compiled_probe):
    firmware = work / 'firmware'; generation = work / 'generation'
    tampered = Path(tempfile.mkdtemp(prefix='tampered-', dir=work))
    for name in ('manifest', 'manifest.sig', 'manifest.certs'):
        shutil.copyfile(generation / name, tampered / name)
    with (tampered / 'manifest').open('ab') as stream:
        stream.write(b'tampered\n')
    cases = [
        ('firmware-accepts-firmware', firmware_probe, '-', firmware, 0),
        ('firmware-rejects-generation', firmware_probe, '-', generation, 1),
        ('compiled-accepts-generation', compiled_probe, '-', generation, 0),
        ('compiled-rejects-firmware', compiled_probe, '-', firmware, 1),
        ('compiled-rejects-revoked-generation', compiled_probe, str(generation / 'public.crt'), generation, 1),
        ('compiled-rejects-tampering', compiled_probe, '-', tampered, 1),
    ]
    for role in ('application', 'repository'):
        cases.append(('compiled-rejects-' + role, compiled_probe, '-', work / role, 1))
    for label, data in (('empty', b''), ('duplicate', (generation / 'manifest.sig').read_bytes() * 2)):
        payload = Path(tempfile.mkdtemp(prefix=label + '-signature-', dir=work))
        for member in ('manifest', 'manifest.certs'):
            shutil.copyfile(generation / member, payload / member)
        (payload / 'manifest.sig').write_bytes(data)
        cases.append(('compiled-rejects-' + label + '-signature', compiled_probe, '-', payload, 1))
    results = []
    for name, probe, revoked, payload, expected in cases:
        result = subprocess.run([str(probe), str(firmware / 'public.crt'), revoked,
            str(payload / 'manifest.sig')], capture_output=True, text=True, timeout=30)
        row = dict(case=name, expected=expected, actual=result.returncode,
                   stdout=result.stdout, stderr=result.stderr)
        if expected == 0:
            row['reason_matched'] = result.stdout == 'accepted\n' and result.stderr == ''
        elif 'revoked' in name:
            row['reason_matched'] = 'Certificate is on forbidden list' in result.stderr
        elif 'tampering' in name or 'signature' in name:
            row['reason_matched'] = 'Unverified ' + str(payload / 'manifest') in result.stdout
        else:
            row['reason_matched'] = 'BR_ERR_X509_NOT_TRUSTED' in result.stderr
        results.append(row)
    report = dict(scope='native-manifest-cryptography-with-firmware-transport-fixtures',
        result='PASS' if all(r['actual']==r['expected'] and r['reason_matched'] for r in results) else 'FAIL',
        firmware_verified=False, generation_authorization_verified=False,
        rollback_protection_verified=False, cases=results,
        artifacts_sha256={str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (firmware_probe, compiled_probe, firmware / 'public.crt',
                         generation / 'public.crt', firmware / 'manifest.sig',
                         generation / 'manifest.sig', tampered / 'manifest',
                         *(work / role / name for role in ('application', 'repository')
                           for name in ('public.crt', 'manifest', 'manifest.sig', 'manifest.certs')),
                         *(payload / 'manifest.sig' for name, _, _, payload, _ in cases if 'signature' in name))})
    (work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    if report['result'] != 'PASS':
        raise SystemExit('native trust qualification failed; see ' + str(work / 'results.json'))
    print('PASS: ' + str(len(cases)) + ' native manifest trust cases; firmware not qualified')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--openssl', type=Path, default=Path('/usr/bin/openssl'))
    parser.add_argument('--firmware-probe', type=Path)
    parser.add_argument('--compiled-probe', type=Path)
    args = parser.parse_args()
    if args.prepare:
        if args.firmware_probe or args.compiled_probe:
            parser.error('prepare and qualification are separate steps')
        prepare(args.work, args.openssl)
    else:
        if not args.firmware_probe or not args.compiled_probe:
            parser.error('both independently built probes are required')
        qualify(args.work, args.firmware_probe, args.compiled_probe)

if __name__ == '__main__':
    main()
