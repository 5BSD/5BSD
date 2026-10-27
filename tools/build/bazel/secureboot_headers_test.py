# SPDX-License-Identifier: BSD-2-Clause
"""Host reference checks for trust framing, rejection and deterministic headers."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import secureboot_headers as generator


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--awk', type=Path, required=True)
    parser.add_argument('--file2c', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads((args.source / 'lib/libsecureboot/tests/headers-policy.json').read_text())
    checks = 0
    with tempfile.TemporaryDirectory() as directory:
        p = Path(directory) / 'certificate.pem'
        valid = b'-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n'
        # AQID exercises framing only; it is not a decodable trust certificate.
        samples = [b'', valid, valid.replace(b'\n', b'\r\n'), valid + valid,
                   valid.replace(b'CERTIFICATE', b'PRIVATE KEY'),
                   b'-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n',
                   valid.replace(b'AQID', b'invalid!'), valid.split(b'-----END')[0],
                   b'prefix\n' + valid, valid + b'-----BEGIN PRIVATE KEY-----\n']
        for data in samples:
            p.write_bytes(data)
            for required in (False, True):
                reference = subprocess.run([str(args.awk), '-v', 'required=' + ('yes' if required else 'no'),
                    '-f', str(args.source / 'lib/libsecureboot/public-trust.awk'), str(p), '/dev/null'],
                    capture_output=True).returncode == 0
                try:
                    generator.public_pem([p], required)
                    accepted = True
                except ValueError:
                    accepted = False
                assert accepted == reference, (data, required)
                checks += 1
        for data in [b'\0', valid + b'\0', bytes(range(256))]:
            reference = subprocess.check_output([str(args.file2c), '-sx',
                'static const char ta_PEM[] = {', '};'], input=data).decode()
            assert generator.c_array('ta_PEM', data) == reference
            checks += 1
        p.write_bytes(valid)
        first = generator.generate(policy, [p], [])
        assert first == generator.generate(policy, [p], [])
        checks += 1
        rotated = copy.deepcopy(policy)
        rotated['build_utc'] += 1
        assert first['ta.h'] != generator.generate(rotated, [p], [])['ta.h']
        p.write_bytes(valid.replace(b'AQID', b'BAUG'))
        assert first['ta.h'] != generator.generate(policy, [p], [])['ta.h']
        checks += 2
        for key, value in [('build_utc', True), ('build_utc', -1),
                           ('hashes', ['INVALID']), ('signatures', ['OPENPGP']),
                           ('signature_extensions', ['sig";']), ('hash_kat', 'bad\0value'),
                           ('compiled_trust_only', True), ('self_tests', 'yes')]:
            bad = copy.deepcopy(policy)
            bad[key] = value
            try:
                generator.generate(bad, [], [])
            except ValueError:
                checks += 1
            else:
                raise AssertionError((key, value))
        # A certificate cannot be completed across input-file boundaries.
        p.write_bytes(b'-----BEGIN CERTIFICATE-----\nAQID\n')
        q = Path(directory) / 'tail.pem'
        q.write_bytes(b'-----END CERTIFICATE-----\n')
        try:
            generator.public_pem([p, q], True)
        except ValueError:
            checks += 1
        else:
            raise AssertionError('cross-file certificate accepted')
    print(f'PASS: {checks} framing, reference, policy and deterministic-output checks')


if __name__ == '__main__':
    main()
