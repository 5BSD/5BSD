#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify read-only artifact attachment, not filesystem or generation validity."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'objtop', 'fixture-objtop', 'work', 'qemu-data', 'disk'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('qemu', 'kernconf', 'sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if not work.is_relative_to('/usr/obj/usr/src') or work.exists():
        parser.error('work must be a new directory under /usr/obj/usr/src')
    if args.disk.is_symlink() or not args.disk.is_file() or digest(args.disk) != args.sha256:
        parser.error('input must be a regular disk matching the explicit SHA256')
    work.mkdir()
    report = {'result': 'RUNNING', 'scope': 'readonly-artifact-attachment',
              'generation_authenticated': False, 'filesystem_verified': False}
    try:
        disk = work / 'input, copy.img'
        shutil.copyfile(args.disk, disk)
        if digest(disk) != args.sha256 or digest(args.disk) != args.sha256:
            raise ValueError('disk changed while copying')
        command = [sys.executable, '-B', str(Path(__file__).with_name('run-vm.py'))]
        for option in ('root', 'objtop', 'fixture-objtop', 'qemu-data', 'qemu', 'kernconf'):
            command.extend(['--' + option, str(getattr(args, option.replace('-', '_')))])
        command.extend(['--atf-case', 'tools/test/daemon-runtime/runner_probe:readonly_input_disk',
                        '--input-disk', str(disk), '--timeout', '180'])
        rejected = work / 'wrong-hash'
        wrong_hash = ('1' if args.sha256[0] == '0' else '0') + args.sha256[1:]
        bad = subprocess.run([*command, '--work', str(rejected), '--input-disk-sha256', wrong_hash],
                             text=True, capture_output=True)
        (work / 'wrong-hash.log').write_text(bad.stdout + bad.stderr)
        if bad.returncode != 2 or 'input disk SHA256 differs' not in bad.stderr or rejected.exists():
            raise ValueError('wrong disk hash was not rejected before staging')
        target = work / 'vm'
        subprocess.run([*command, '--work', str(target), '--input-disk-sha256', args.sha256], check=True)
        result = json.loads((target / 'result.json').read_text())
        serial = (target / 'serial.log').read_text()
        if (result['result'] != 'PASS' or result['input_disk_final_sha256'] != args.sha256 or
                not result['input_disk_readonly'] or
                serial.splitlines().count('READONLY_INPUT_DISK_PASS: readable raw disk refused identical block write') != 1):
            raise ValueError('VM did not prove read-only input access')
        if digest(args.disk) != args.sha256 or digest(disk) != args.sha256:
            raise ValueError('source or private input disk changed')
        report.update(result='PASS', wrong_hash_refused_before_staging=True,
                      raw_disk_read_succeeded=True, raw_disk_write_refused=True,
                      source_sha256=args.sha256, serial_sha256=digest(target / 'serial.log'),
                      vm_result_sha256=digest(target / 'result.json'))
    except BaseException as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('READONLY_ARTIFACT_PASS: explicit hash, guest read/write refusal, unchanged input')


if __name__ == '__main__':
    main()
