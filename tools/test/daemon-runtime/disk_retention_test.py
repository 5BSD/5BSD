#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Prove private fixture disk retention and default discard across real VM boots."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from atf_metadata import cases_completed


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'objtop', 'fixture-objtop', 'work', 'qemu-data'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--kernconf', required=True)
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    work = args.work.resolve()
    if not work.is_relative_to('/usr/obj/usr/src') or work.exists():
        parser.error('work must be a new directory under /usr/obj/usr/src')
    if not 30 <= args.timeout <= 3600:
        parser.error('timeout must be between 30 and 3600 seconds')
    work.mkdir()
    runner = Path(__file__).with_name('run-vm.py')
    report = {'result': 'RUNNING', 'scope': 'private-fixture-disk-retention',
              'system_generation_qualified': False, 'cases': []}
    try:
        for retain in (False, True):
            target = work / ('retained' if retain else 'discarded')
            command = [sys.executable, '-B', str(runner)]
            for option in ('root', 'objtop', 'fixture-objtop', 'qemu-data', 'qemu', 'kernconf'):
                command.extend(['--' + option, str(getattr(args, option.replace('-', '_')))])
            command.extend(['--work', str(target), '--timeout', str(args.timeout),
                            '--atf-case', 'tools/test/daemon-runtime/runner_probe:disk_retention'])
            if retain:
                command.append('--retain-disk-writes')
            subprocess.run(command, check=True)
            first = json.loads((target / 'result.json').read_text())
            first_text = (target / 'serial.log').read_text()
            if first['result'] != 'PASS' or first_text.splitlines().count('RUNNER_DISK_FIRST_BOOT') != 1:
                raise ValueError('first boot did not create a fresh sentinel')
            before = digest(target / 'guest.img')
            if retain and before != first['retained_guest_disk_sha256']:
                raise ValueError('retained disk changed before second boot')
            command = list(first['command'])
            serial = target / 'second-boot.log'
            command[command.index('-serial') + 1] = 'file:' + str(serial)
            (target / 'second-command.json').write_text(json.dumps(command, indent=2) + '\n')
            result = subprocess.run(command, timeout=args.timeout)
            text = serial.read_text(errors='replace')
            expected = 'RUNNER_DISK_RETAINED_BOOT' if retain else 'RUNNER_DISK_FIRST_BOOT'
            unwanted = 'RUNNER_DISK_FIRST_BOOT' if retain else 'RUNNER_DISK_RETAINED_BOOT'
            if (result.returncode != 0 or text.splitlines().count(expected) != 1 or
                    unwanted in text or not cases_completed(text, first['case_metadata']) or
                    text.splitlines().count('RUNTIME_VM_PASS') != 1 or
                    'Powering system off' not in text or
                    any(marker in text for marker in ('panic:', 'Fatal trap', 'lock order reversal'))):
                raise ValueError('second boot did not satisfy the disk-retention contract')
            after = digest(target / 'guest.img')
            if not retain and after != before:
                raise ValueError('default snapshot mode modified its base disk')
            report['cases'].append({'retain': retain, 'result': 'PASS',
                'first_disk_sha256': before, 'second_disk_sha256': after,
                'first_serial_sha256': digest(target / 'serial.log'),
                'second_serial_sha256': digest(serial)})
        report['result'] = 'PASS'
    except BaseException as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('DISK_RETENTION_PASS: default discard and explicit retention across two boots')


if __name__ == '__main__':
    main()
