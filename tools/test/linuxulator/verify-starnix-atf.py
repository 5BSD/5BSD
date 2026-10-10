#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Verify selected Starnix ATF serial evidence against explicit case/hash inputs."""
import argparse
import json
from pathlib import Path
import re


def verify(console, hashes, cases, qemu_exit):
    text = console.replace('\r\n', '\n')
    errors, rows = [], {}
    expected = {f'{program}:{case}' for program, names in cases.items()
                for case in names}
    if not expected or len(expected) != sum(map(len, cases.values())):
        errors.append('Empty or duplicate expected case list')
    if not hashes:
        errors.append('Empty artifact manifest')
    if qemu_exit != 0:
        errors.append(f'QEMU exit {qemu_exit}')
    for marker in ('STARNIX_ATF_BEGIN', 'STARNIX_ATF_DONE', 'STARNIX_ATF_EXIT 0'):
        if text.splitlines().count(marker) != 1:
            errors.append(f'Missing or duplicate marker: {marker}')
    for path, digest in hashes.items():
        path = '/' + path.lstrip('/')
        if text.splitlines().count(f'SHA256 ({path}) = {digest}') != 1:
            errors.append(f'Artifact hash mismatch/missing: {path}')
    for fs, tmpdir in (('zfs', '/tmp'), ('tmpfs', '/tmp/starnix-atf-tmpfs')):
        begin = f'STARNIX_ATF_FS_BEGIN {fs}'
        exits = re.findall(r'^STARNIX_ATF_FS_END ' + fs + r' (\d+)$', text, re.M)
        if text.splitlines().count(begin) != 1 or len(exits) != 1:
            errors.append(f'{fs}: missing or duplicate phase')
            continue
        end = f'STARNIX_ATF_FS_END {fs} {exits[0]}'
        if exits[0] != '0':
            errors.append(f'{fs}: phase exit {exits[0]}')
        if text.index(end) < text.index(begin):
            errors.append(f'{fs}: phase ends before it begins')
            continue
        section = text.split(begin + '\n', 1)[1].split(end + '\n', 1)[0]
        results = re.findall(r'^===> (\w+:\w+)\nResult: +([^\n]+)$', section, re.M)
        names = [name for name, _ in results]
        rows[fs] = dict(results)
        if len(names) != len(expected) or set(names) != expected:
            errors.append(f'{fs}: missing, duplicate or unexpected cases')
        if any(result != 'passed' for _, result in results):
            errors.append(f'{fs}: non-passing case result')
        if re.findall(r'^\s+TMPDIR=([^\n]+)$', section, re.M) != [tmpdir]:
            errors.append(f'{fs}: wrong execution TMPDIR')
    if not re.search(r'^linuxgate\s+/\s+zfs\s', text, re.M):
        errors.append('ZFS root mount not recorded')
    if not re.search(r'^tmpfs\s+/tmp/starnix-atf-tmpfs\s+tmpfs\s', text, re.M):
        errors.append('tmpfs work mount not recorded')
    for marker in ('all pools are healthy', 'All buffers synced.',
                   'acpi0: Powering system off...'):
        if marker not in text:
            errors.append(f'Missing shutdown evidence: {marker}')
    if re.search(r'panic:|Fatal trap|lock order reversal|sleeping thread.*owns.*non-sleepable',
                 text, re.I):
        errors.append('Kernel diagnostic present')
    return {'passed': not errors, 'errors': errors, 'rows': rows,
            'expected_count': 2 * len(expected),
            'passed_count': sum(result == 'passed' for phase in rows.values()
                                for result in phase.values()),
            'qemu_exit': qemu_exit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('console', 'manifest', 'cases', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--qemu-exit', type=int, required=True,
                        help='Actual terminal QEMU process exit; never infer from a timeout')
    args = parser.parse_args()
    result = verify(args.console.read_text(), json.loads(args.manifest.read_text()),
                    json.loads(args.cases.read_text()), args.qemu_exit)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(f"Starnix ATF: {'PASS' if result['passed'] else 'FAIL'} "
          f"{result['passed_count']}/{result['expected_count']}")
    for error in result['errors']:
        print(error)
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
