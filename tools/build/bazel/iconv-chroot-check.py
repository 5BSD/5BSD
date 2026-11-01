#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run native iconv qualification in a prepared root, dropping test privileges."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--gid', type=int, required=True)
    parser.add_argument('--fstyp-tests', action='store_true',
                        help='run the sixteen maintained fstyp cases without makefs or device access')
    parser.add_argument('--fstyp-complete', action='store_true',
                        help='also run makefs cases and the original root-only md/newfs case in a disposable guest')
    args = parser.parse_args()
    if args.fstyp_complete and not args.fstyp_tests:
        parser.error('--fstyp-complete requires --fstyp-tests')
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        parser.error('root is required for chroot; test uid/gid must be nonzero')
    root = args.root.resolve(strict=True)
    if root == Path('/'):
        parser.error('a private prepared root is required')
    inventory = json.loads(args.manifest.read_text())
    for name, digest in inventory['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name:
            raise ValueError('invalid fixture inventory path: ' + name)
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('fixture content mismatch: ' + name)
    prefix = ['/usr/sbin/chroot', '-u', str(args.uid), '-g', str(args.gid),
              '-G', str(args.gid), str(root)]
    results = []

    def run(name, command, data=b'', expected=None, failure=False, directory=None, privileged=False):
        if directory is not None:
            command = ['/bin/sh', '-c', 'cd "$1" && shift && exec "$@"',
                       'iconv-runtime', directory] + command
        try:
            active_prefix = (['/usr/sbin/chroot', '-u', '0', '-g', '0', '-G', '0', str(root)]
                             if privileged else prefix)
            result = subprocess.run(active_prefix + command, input=data, capture_output=True,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=30)
        except subprocess.TimeoutExpired as error:
            result = subprocess.CompletedProcess(prefix + command, 124,
                                                 error.stdout or b'', error.stderr or b'timeout')
        except OSError as error:
            result = subprocess.CompletedProcess(prefix + command, 125, b'', str(error).encode())
        passed = (result.returncode == 1 if failure else result.returncode == 0)
        if expected is not None:
            passed = passed and result.stdout == expected
        results.append({'name': name, 'passed': passed, 'status': result.returncode,
                        'stderr': result.stderr.decode(errors='replace')})
        return result

    if args.fstyp_tests:
        run('child uid', ['/usr/bin/id', '-u'], expected=f'{args.uid}\n'.encode())
        run('child gid', ['/usr/bin/id', '-g'], expected=f'{args.gid}\n'.encode())
        run('child supplementary groups', ['/usr/bin/id', '-G'], expected=f'{args.gid}\n'.encode())
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
    if args.fstyp_tests:
        cases = ['befs', 'dir', 'empty', 'exfat', 'exfat_label', 'ext2', 'ext3', 'ext4',
                 'ext4_label', 'fat12', 'fat16', 'fat32', 'fat32_label', 'ntfs', 'ntfs_with_label', 'zeros']
        if args.fstyp_complete:
            cases += ['cd9660', 'cd9660_label', 'ufs1', 'ufs2', 'ufs2_label']
        for case in cases:
            work = root / 'tmp' / ('fstyp-' + case)
            work.mkdir(mode=0o700)
            os.chown(work, args.uid, args.gid)
            result = run('fstyp:' + case,
                         ['/usr/tests/usr.sbin/fstyp/fstyp_test', '-s', '/usr/tests/usr.sbin/fstyp',
                          '-r', 'atf.result', case], directory='/tmp/' + work.name)
            result_file = work / 'atf.result'
            results[-1]['passed'] = (results[-1]['passed'] and result_file.exists()
                                      and result_file.read_text().strip() == 'passed')
            results[-1]['stdout'] = result.stdout.decode(errors='replace')
            results[-1]['atf_result'] = result_file.read_text() if result_file.exists() else None
            # Match Kyua's work-directory cleanup; bound live image storage to one case.
            if results[-1]['passed']:
                shutil.rmtree(work)
        if args.fstyp_complete:
            # Keep the maintained root requirement and cleanup body intact.
            # Only this explicit device case runs as guest root.
            before = run('md devices before fstyp', ['/sbin/mdconfig', '-l'], privileged=True)
            work = root / 'tmp/fstyp-ufs_on_device'
            work.mkdir(mode=0o700)
            command = ['/usr/tests/usr.sbin/fstyp/fstyp_test', '-s', '/usr/tests/usr.sbin/fstyp']
            try:
                body = run('fstyp:ufs_on_device', command + ['-r', 'atf.result', 'ufs_on_device'],
                           directory='/tmp/' + work.name, privileged=True)
                result_file = work / 'atf.result'
                results[-1]['passed'] = (results[-1]['passed'] and result_file.exists()
                                         and result_file.read_text().strip() == 'passed')
                results[-1]['stdout'] = body.stdout.decode(errors='replace')
                results[-1]['atf_result'] = result_file.read_text() if result_file.exists() else None
            finally:
                cleanup = run('fstyp:ufs_on_device cleanup',
                              command + ['-r', 'cleanup.result', 'ufs_on_device:cleanup'],
                              directory='/tmp/' + work.name, privileged=True)
                results[-1]['stdout'] = cleanup.stdout.decode(errors='replace')
                run('md devices restored after fstyp', ['/sbin/mdconfig', '-l'],
                    expected=before.stdout, privileged=True)
    report = {'passed': all(item['passed'] for item in results), 'checks': results,
              'limitations': ['kernel and loader supplied by the execution harness', 'selected conversion cases, not every encoding']}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(results), 'report': str(args.output)}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
