#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run full construction in private disk-backed storage in a disposable VM."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    parser.add_argument('--filesystem', action='store_true', required=True)
    parser.add_argument('--settings', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('builder_storage', Path(__file__).with_name('builder_storage.py'))
    storage = importlib.util.module_from_spec(spec); spec.loader.exec_module(storage)
    settings = json.loads(args.settings.read_text())
    work = Path(settings['work'])
    setup = storage.prepare(work, '/sbin/mount', '/sbin/sysctl')
    (work / 'storage.json').write_text(json.dumps(setup, indent=2) + '\n')
    target = work / 'construction'
    subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B',
        str(Path(__file__).with_name('system_database.py')), '--disposable-vm',
        '--filesystem', '--work', str(target)], check=True)
    output = target / 'constructed'
    built = json.loads((output / 'construction.json').read_text())
    if built['result'] != 'PASS':
        raise ValueError('retained construction has no successful receipt')
    records = (output / 'construction.json', output / 'generated.json', output / 'database/receipt.json')
    if built.get('storage_layout') is not None:
        records += (output / 'storage-layout.json',)
    if built.get('installation_configuration') is not None:
        records += (output / 'installation-transport.json',)
    report = {'format': 1, 'scope': 'retained-trusted-builder-output', 'result': 'PASS',
              'candidate': str(target / 'candidate'), 'generation_authenticated': False,
              'normal_boot_qualified': False,
              'receipts_sha256': {str(p): storage.digest(p) for p in records}}
    with (work / 'retained-builder.json').open('x') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    print('RETAINED_CONSTRUCTION_PASS work=' + str(work), flush=True)


if __name__ == '__main__':
    main()
