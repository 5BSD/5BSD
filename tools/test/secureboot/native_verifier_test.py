#!/usr/bin/env python3
"""Real-file digest checks using an explicitly supplied native tvo binary.

Raw manifests are intentional: this does not qualify manifest authentication,
streaming verification, firmware, or BIP enforcement.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', type=Path, required=True)
    args = parser.parse_args()
    program = args.program.resolve(strict=True)
    count = 0
    with tempfile.TemporaryDirectory(prefix='bip-tvo-') as directory:
        root = Path(directory)
        payload = root / 'payload'
        manifest = root / 'manifest'
        for size in (0, 1, 4095, 4096, 4097, 65537):
            data = bytes(i % 251 for i in range(size))
            digest = hashlib.sha256(data).hexdigest()
            for case, content, token, expected in (
                ('valid', data, digest, True),
                ('changed', data + b'x', digest, False),
                ('extended-token', data, digest + 'a', False),
                ('short-token', data, digest[:-1], False),
            ):
                payload.write_bytes(content)
                manifest.write_text('payload sha256=' + token + '\n')
                result = subprocess.run(
                    [str(program), '-p', str(root), str(manifest), str(payload)],
                    capture_output=True, text=True, timeout=30, check=True)
                match = re.search(r'^verify_open\(' + re.escape(str(payload)) +
                                  r'\) = (-?\d+) ', result.stdout, re.MULTILINE)
                if match is None or (int(match[1]) >= 0) != expected:
                    raise AssertionError((size, case, result.stdout, result.stderr))
                count += 1
    print(f'PASS: {count} direct real-file digest checks; '
          'manifest authentication and streaming not qualified')


if __name__ == '__main__':
    main()
