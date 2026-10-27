#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare every configured native syscall stub with a recorded Make generation."""
import argparse
import json
from pathlib import Path
from libmd_environment import digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'workspace', 'reference', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--component', required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    selected = [c for c in plan['components'] if c['component'] == args.component]
    if len(selected) != 1 or not selected[0].get('syscall_generation'):
        raise ValueError('one component with declared syscall generation required')
    component = selected[0]
    reference = json.loads((args.reference/'receipt.json').read_text())
    names = [v['name'] for v in component['syscall_generation']['outputs']]
    if reference['status'] != 'passed' or set(reference['sources']) != set(names):
        raise ValueError('Make/native generator inventories differ')
    hashes = {}
    for name in names:
        if Path(name).name != name:
            raise ValueError('syscall output must be a basename')
        actual = args.workspace/'bazel-bin/generated'/component['metadata']['LIB']/name
        expected = args.reference/'objects'/name
        sha = digest(expected)
        if sha != reference['sources'][name] or digest(actual) != sha:
            raise ValueError('generated syscall differs: ' + name)
        hashes[name] = sha
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to('/usr/obj') or output == Path('/usr/obj'):
        raise ValueError('fresh result directory below /usr/obj required')
    output.mkdir()
    (output/'receipt.json').write_text(json.dumps(dict(status='passed',
        scope='complete selected syscall generation byte parity; no compilation/runtime claim',
        plan_sha256=digest(args.plan), reference_receipt_sha256=digest(args.reference/'receipt.json'),
        driver_sha256=digest(Path(__file__)), sources=hashes), indent=2)+'\n')
    print('PASS:', len(hashes), 'native syscall outputs match recorded Make generation')


if __name__ == '__main__':
    main()
