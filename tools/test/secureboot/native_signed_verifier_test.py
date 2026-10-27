# SPDX-License-Identifier: BSD-2-Clause
"""Native signed-file integration; no firmware or release authority claim."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', type=Path, required=True)
    parser.add_argument('--openssl', type=Path, required=True)
    args = parser.parse_args()
    program = args.program.resolve(strict=True)
    openssl = args.openssl.resolve(strict=True)
    spec = importlib.util.spec_from_file_location(
        'generation_boot', ROOT / 'tools/build/capimage/generation_boot.py')
    boot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boot)
    count = 0
    with tempfile.TemporaryDirectory(prefix='bip-tvo-') as directory:
        root = Path(directory)
        key, cert = root / 'private.key', root / 'public.crt'
        subprocess.run([str(openssl), 'req', '-new', '-x509', '-newkey',
                        'rsa:2048', '-noenc', '-sha256', '-days', '1',
                        '-keyout', str(key), '-out', str(cert), '-subj',
                        '/CN=DISPOSABLE native verifier test', '-addext',
                        'basicConstraints=critical,CA:TRUE'],
                       check=True, capture_output=True, timeout=60)
        key.chmod(0o600)
        payload = root / 'payload'
        manifest = root / 'manifest'

        def run(arguments, trust=True):
            command = [str(program)]
            if trust:
                command += ['-T', str(cert)]
            return subprocess.run(command + arguments, check=True,
                                  capture_output=True, text=True, timeout=30)

        def loader(expected, trust=True, required=False):
            result = run((['-R'] if required else []) + ['-V', str(payload)], trust)
            match = re.search(r'^verify_file\(' + re.escape(str(payload)) +
                              r'\) = (-?\d+)$', result.stdout, re.MULTILINE)
            # VE_VERIFIED is 1; nonnegative unverified states are not success.
            if match is None or (int(match[1]) == 1) != expected:
                raise AssertionError((expected, result.stdout, result.stderr))
            if required and not expected and 'Secure Boot: verification failed:' not in result.stderr:
                raise AssertionError(('missing required-policy rejection', result.stderr))

        for size in (0, 1, 4095, 4096, 4097, 65537):
            data = bytes(i % 251 for i in range(size))
            payload.write_bytes(data)
            content = ('payload sha256=' + hashlib.sha256(data).hexdigest() + '\n').encode()
            artifacts, _ = boot.sign_loader_manifest(content, {
                'key': str(key), 'certificate': str(cert), 'openssl': str(openssl)}, root)
            for name, value in artifacts.items():
                (root / name).write_bytes(value)
            loader(True)
            loader(True, required=True)
            result = run(['-p', str(root), str(root / 'manifest.sig'), str(payload)])
            if ('vectx_close: Verified: ' + str(payload) + '\n') not in result.stdout:
                raise AssertionError((size, result.stdout, result.stderr))
            loader(False, trust=False)
            loader(False, trust=False, required=True)
            payload.write_bytes(data + b'x')
            loader(False)
            loader(False, required=True)
            payload.write_bytes(data)
            manifest.write_bytes(content + b'tampered\n')
            loader(False)
            loader(False, required=True)
            count += 9
        for entry in (b'payload no_hash\n', b'payload no_hash_extra\n',
                      b'payload unsupported=abc\n', b'other sha256=' + b'a' * 64 + b'\n'):
            artifacts, _ = boot.sign_loader_manifest(entry, {
                'key': str(key), 'certificate': str(cert), 'openssl': str(openssl)}, root)
            for name, value in artifacts.items():
                (root / name).write_bytes(value)
            loader(False, required=True)
            count += 1
    print(f'PASS: {count} native signed-file checks; firmware and release authority not qualified')


if __name__ == '__main__':
    main()
