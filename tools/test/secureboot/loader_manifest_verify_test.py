# SPDX-License-Identifier: BSD-2-Clause
"""Qualify compiled generation trust in the real native build helper, not firmware."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def qualify(verifier, fixtures):
    verifier = verifier.resolve(strict=True)
    before = hashlib.sha256(verifier.read_bytes()).hexdigest()
    cases = [('generation', fixtures / 'generation', 0)]
    cases += [(role, fixtures / role, 1) for role in ('firmware', 'application', 'repository')]
    with tempfile.TemporaryDirectory(prefix='loader-manifest-reject-') as tmp:
        for name, mutation in (
                ('payload', lambda d: (d / 'manifest').write_bytes((d / 'manifest').read_bytes()+b'changed\n')),
                ('empty-signature', lambda d: (d / 'manifest.sig').write_bytes(b'')),
                ('wrong-certificate', lambda d: shutil.copyfile(fixtures / 'firmware/public.crt', d / 'manifest.certs'))):
            directory = Path(tmp) / name
            directory.mkdir()
            for member in ('manifest', 'manifest.sig', 'manifest.certs'):
                shutil.copyfile(fixtures / 'generation' / member, directory / member)
            mutation(directory)
            cases.append((name, directory, 1))
        rows = []
        for name, directory, expected in cases:
            result = subprocess.run([str(verifier), str(directory / 'manifest.sig')],
                                    capture_output=True, text=True, timeout=30)
            accepted = result.stdout == 'accepted\n' and result.stderr == ''
            rows.append(dict(case=name, expected=expected, actual=result.returncode,
                             stdout=result.stdout, stderr=result.stderr,
                             passed=result.returncode == expected and (accepted if expected == 0 else not accepted)))
    if hashlib.sha256(verifier.read_bytes()).hexdigest() != before:
        raise ValueError('verifier changed during qualification')
    report = dict(result='PASS' if all(row['passed'] for row in rows) else 'FAIL',
                  scope='native-compiled-anchor-manifest-verification', verifier_sha256=before,
                  firmware_verified=False, firmware_revocation_verified=False, cases=rows)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.verifier, args.fixtures)
    print(json.dumps(report, indent=2))
    if report['result'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
