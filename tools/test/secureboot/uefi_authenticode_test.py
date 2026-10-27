# SPDX-License-Identifier: BSD-2-Clause
"""Independent Authenticode qualification; no firmware or revocation claims."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('verifier', 'signer', 'loader', 'openssl', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    for path in vars(args).values():
        if not path.is_absolute():
            parser.error('all paths must be absolute')
    os.umask(0o077)
    args.work.mkdir(parents=True, exist_ok=False)
    env = dict(PATH='/sbin:/bin:/usr/sbin:/usr/bin', LC_ALL='C',
               OPENSSL_CONF='/dev/null')

    def run(argv, **kwargs):
        return subprocess.run(list(map(str, argv)), env=env,
                              capture_output=True, timeout=60, **kwargs)

    certificates = []
    for role in ('selected', 'other'):
        key = args.work / (role + '.key')
        certificate = args.work / (role + '.pem')
        signed = args.work / (role + '.efi')
        run([args.openssl, 'req', '-new', '-x509', '-newkey', 'rsa:2048',
             '-noenc', '-sha256', '-days', '2', '-keyout', key,
             '-out', certificate, '-subj', '/CN=5BSD DISPOSABLE ' + role,
             '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,digitalSignature,keyCertSign',
             '-addext', 'extendedKeyUsage=codeSigning'], check=True)
        run([args.signer, '-k', key, '-c', certificate, '-o', signed,
             args.loader], check=True)
        certificates.append(certificate)
    der = run([args.openssl, 'x509', '-in', certificates[0],
               '-outform', 'DER'], check=True).stdout
    pin = hashlib.sha256(der).hexdigest()
    bundle = args.work / 'anchors.pem'
    bundle.write_bytes(b''.join(cert.read_bytes() for cert in certificates))

    # Corrupt actual executable bytes without damaging the signature envelope.
    data = bytearray((args.work / 'selected.efi').read_bytes())
    pe = struct.unpack_from('<I', data, 60)[0]
    if data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('input is not PE')
    count = struct.unpack_from('<H', data, pe + 6)[0]
    table = pe + 24 + struct.unpack_from('<H', data, pe + 20)[0]
    for index in range(count):
        size, offset = struct.unpack_from('<II', data, table + 40 * index + 16)
        if size:
            if offset + size > len(data):
                raise ValueError('raw section out of bounds')
            data[offset] ^= 1
            break
    else:
        raise ValueError('no raw section to corrupt')
    tampered = args.work / 'tampered.efi'
    tampered.write_bytes(data)
    selected = args.work / 'selected.efi'
    cases = [
        ('selected', selected, bundle, pin, True, 'Signature verification: ok'),
        ('other-leaf', args.work / 'other.efi', bundle, pin, False,
         'Leaf hash match: failed'),
        ('wrong-pin', selected, bundle, '0' * 64, False, 'Leaf hash match: failed'),
        ('wrong-ca', selected, certificates[1], pin, False, 'PKCS7_verify error'),
        ('unsigned', args.loader, bundle, pin, False, 'No signature found'),
        ('tampered', tampered, bundle, pin, False, 'MISMATCH!!!'),
    ]
    rows = []
    for name, source, ca, leaf, accepted, reason in cases:
        argv = [args.verifier, 'verify', '-in', source, '-CAfile', ca,
                '-require-leaf-hash', 'sha256:' + leaf,
                '-ignore-timestamp', '-ignore-crl']
        result = run(argv)
        matched = reason.encode() in result.stdout + result.stderr
        rows.append(dict(case=name, argv=list(map(str, argv)),
                         expected_accept=accepted, actual=result.returncode,
                         reason_matched=matched,
                         passed=(result.returncode == 0) == accepted and matched,
                         stdout=result.stdout.decode(errors='replace'),
                         stderr=result.stderr.decode(errors='replace')))
    passed = all(row['passed'] for row in rows)
    report = dict(result='PASS' if passed else 'FAIL',
                  scope='artifact signatures only; no firmware/revocation proof',
                  hashes={str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (args.verifier, args.signer, args.loader,
                                       args.openssl, Path(__file__))}, cases=rows)
    (args.work / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(report['result'])
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
