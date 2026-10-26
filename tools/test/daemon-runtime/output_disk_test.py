#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify a private output disk beside an unchanged read-only input disk."""
import argparse
import hashlib
import json
from pathlib import Path
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
    parser.add_argument('--output-mib', type=int, default=16)
    args = parser.parse_args()
    work = args.work.resolve()
    if not work.is_relative_to('/usr/obj/usr/src') or work.exists():
        parser.error('work must be new under /usr/obj/usr/src')
    if not 16 <= args.output_mib <= 16384:
        parser.error('output capacity must be 16..16384 MiB')
    if args.disk.is_symlink() or not args.disk.is_file() or digest(args.disk) != args.sha256:
        parser.error('explicit regular input disk hash mismatch')
    work.mkdir()
    report = dict(result='RUNNING', scope='private output-disk persistence and input isolation',
                  generation_authenticated=False, filesystem_verified=False)
    command = [sys.executable, '-B', str(Path(__file__).with_name('run-vm.py'))]
    for option in ('root', 'objtop', 'fixture-objtop', 'qemu-data', 'qemu', 'kernconf'):
        command.extend(['--' + option, str(getattr(args, option.replace('-', '_')))])
    try:
        rejected = work / 'no-input'
        bad = subprocess.run([*command, '--work', str(rejected), '--output-disk-mib', str(args.output_mib)],
                             capture_output=True, text=True)
        (work / 'no-input.log').write_text(bad.stdout + bad.stderr)
        if bad.returncode != 2 or 'output disk requires' not in bad.stderr or rejected.exists():
            raise ValueError('missing input was not refused before staging')
        target = work / 'vm'
        subprocess.run([*command, '--work', str(target), '--input-disk', str(args.disk),
            '--input-disk-sha256', args.sha256, '--output-disk-mib', str(args.output_mib),
            '--timeout', '180',
            '--atf-case', 'tools/test/daemon-runtime/runner_probe:readonly_input_disk',
            '--atf-case', 'tools/test/daemon-runtime/runner_probe:output_disk'], check=True)
        result = json.loads((target / 'result.json').read_text())
        block = b'5BSD-OUTPUT-DISK\n'.ljust(512, b'\0')
        expected = hashlib.sha256(block)
        remaining = args.output_mib * 1024 * 1024 - 1024
        zeros = bytes(1024 * 1024)
        while remaining:
            chunk = min(remaining, len(zeros)); expected.update(zeros[:chunk]); remaining -= chunk
        expected.update(block)
        if (result['result'] != 'PASS' or result['input_disk_final_sha256'] != args.sha256 or
                digest(args.disk) != args.sha256 or
                (target / 'output.img').stat().st_size != args.output_mib * 1024 * 1024 or
                (target / 'output.img').stat().st_mode & 0o777 != 0o600 or
                digest(target / 'output.img') != expected.hexdigest() or
                result['output_disk_sha256'] != expected.hexdigest()):
            raise ValueError('output bytes, input isolation or recorded hashes differ')
        report.update(result='PASS', missing_input_refused=True, input_unchanged=True,
                      output_sha256=expected.hexdigest(), output_bytes=args.output_mib * 1024 * 1024,
                      vm_result_sha256=digest(target / 'result.json'))
    except BaseException as error:
        report.update(result='FAIL', error=str(error)); raise
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
