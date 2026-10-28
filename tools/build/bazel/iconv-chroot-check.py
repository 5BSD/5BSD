#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run native iconv qualification in a prepared root, dropping test privileges."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--gid', type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        parser.error('root is required for chroot; test uid/gid must be nonzero')
    root = args.root.resolve(strict=True)
    if root == Path('/'):
        parser.error('a private prepared root is required')
    inventory = json.loads(args.manifest.read_text())
    for name, digest in inventory['files'].items():
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('fixture content mismatch: ' + name)
    prefix = ['/usr/sbin/chroot', '-u', str(args.uid), '-g', str(args.gid),
              '-G', str(args.gid), str(root)]
    results = []

    def run(name, command, data=b'', expected=None, failure=False):
        result = subprocess.run(prefix + command, input=data, capture_output=True,
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=30)
        passed = (result.returncode != 0 if failure else result.returncode == 0)
        if expected is not None:
            passed = passed and result.stdout == expected
        results.append({'name': name, 'passed': passed, 'status': result.returncode,
                        'stderr': result.stderr.decode(errors='replace')})
        return result

    run('iconvctl_trivialp_test', ['/tests/iconvctl_test', '-r', '/tmp/iconvctl.result',
                                 'iconvctl_trivialp_test'])
    result_file = root / 'tmp/iconvctl.result'
    results[-1]['passed'] = results[-1]['passed'] and result_file.exists() and result_file.read_text().strip() == 'passed'
    samples = [('ISO-8859-1', 'latin1', 'caf\u00e9'),
               ('ISO-8859-15', 'iso8859_15', '\u20ac'),
               ('KOI8-R', 'koi8_r', '\u041f\u0440\u0438\u0432\u0435\u0442'),
               ('SHIFT_JIS', 'shift_jis', '\u65e5\u672c\u8a9e'),
               ('BIG5', 'big5', '\u4e2d\u6587'),
               ('UTF-16LE', 'utf-16-le', 'A\u20ac\U00010000'),
               ('UTF-32BE', 'utf-32-be', 'A\u20ac\U00010000'),
               ('CP037', 'cp037', 'ABC')]
    for encoding, codec, text in samples:
        utf8, encoded = text.encode('utf8'), text.encode(codec)
        run('UTF-8 to ' + encoding, ['/usr/bin/iconv', '-f', 'UTF-8', '-t', encoding], utf8, encoded)
        run(encoding + ' to UTF-8', ['/usr/bin/iconv', '-f', encoding, '-t', 'UTF-8'], encoded, utf8)
    run('invalid UTF-8 rejected', ['/usr/bin/iconv', '-f', 'UTF-8', '-t', 'ASCII'], b'\xff', failure=True)
    run('unknown encoding rejected', ['/usr/bin/iconv', '-f', 'NO_SUCH_ENCODING', '-t', 'UTF-8'], failure=True)
    result = run('encoding listing', ['/usr/bin/iconv', '-l'])
    results[-1]['passed'] = results[-1]['passed'] and b'UTF-8' in result.stdout.upper()
    report = {'passed': all(item['passed'] for item in results), 'checks': results,
              'limitations': ['host kernel and loader', 'selected conversion cases, not every encoding']}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(results), 'report': str(args.output)}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
