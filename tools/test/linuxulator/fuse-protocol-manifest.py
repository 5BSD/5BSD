#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Record the exact native FUSE cases and artifacts to stage in a test VM."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def cases_from_listing(listing):
    active, disabled = [], []
    suite = None
    for line in listing.splitlines():
        name = line.split('#', 1)[0].strip()
        if not name:
            continue
        if not line.startswith(' ') and name.endswith('.'):
            suite = name[:-1]
        elif line.startswith('  ') and suite:
            case = suite + '.' + name
            target = disabled if any(part.startswith('DISABLED_')
                                     for part in case.replace('/', '.').split('.')) else active
            target.append(case)
        else:
            raise ValueError('Unexpected gtest listing line: ' + line)
    if not active or len(set(active + disabled)) != len(active + disabled):
        raise ValueError('Empty or duplicate test listing')
    return active, disabled


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tests', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--fusefs-module', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[3]
    names = subprocess.check_output(
        ['make', '-C', str(source / 'tests/sys/fs/fusefs'), '-V', 'GTESTS'],
        text=True).split()
    if not names or len(set(names)) != len(names):
        parser.error('Empty or duplicate GTESTS list')
    manifest = {'version': 1, 'artifacts': {
        'kernel': digest(args.kernel), 'fusefs': digest(args.fusefs_module)},
        'programs': {}}
    for name in names:
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
            parser.error('Unsafe test program name: ' + name)
        binary = args.tests / name
        listing = subprocess.check_output(
            [str(binary.resolve()), '--gtest_list_tests', '--gtest_filter=*'],
            text=True, timeout=30)
        active, disabled = cases_from_listing(listing)
        manifest['programs'][name] = {
            'sha256': digest(binary), 'cases': active, 'disabled': disabled}
    with args.output.open('x') as stream:
        json.dump(manifest, stream, indent=2)
        stream.write('\n')
    with args.output.with_suffix('.programs').open('x') as stream:
        stream.write('\n'.join(names) + '\n')
    print(f'{len(names)} programs, '
          f'{sum(len(p["cases"]) for p in manifest["programs"].values())} active cases')


if __name__ == '__main__':
    main()
