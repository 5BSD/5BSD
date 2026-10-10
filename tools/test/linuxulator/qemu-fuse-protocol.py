#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run a staged FUSE VM and verify every case against its build manifest."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import time

FAILURES = re.compile(r'panic:|Fatal trap|lock order reversal|'
                      r'non-sleepable locks held|\[\s+FAILED\s+\]|\[\s+SKIPPED\s+\]')


def validate_manifest(manifest):
    if manifest.get('version') != 1 or not manifest.get('programs'):
        raise ValueError('Invalid or empty manifest')
    artifacts = set(manifest.get('artifacts', {}))
    required = {'kernel', 'fusefs'}
    linux = {'linux64', 'linux_common', 'linux_rename_probe'}
    if artifacts not in (required, required | linux):
        raise ValueError('Kernel and fusefs hashes are required')
    hashes = list(manifest['artifacts'].values())
    for name, spec in manifest['programs'].items():
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or name in artifacts:
            raise ValueError('Invalid program name')
        cases = spec.get('cases', [])
        if not cases or len(cases) != len(set(cases)):
            raise ValueError('Empty or duplicate case list')
        hashes.append(spec.get('sha256', ''))
    if any(not re.fullmatch(r'[0-9a-f]{64}', value) for value in hashes):
        raise ValueError('Invalid SHA256 digest')


def evaluate(console, manifest, returncode):
    validate_manifest(manifest)
    console = console.replace('\r', '')
    errors = []
    programs = manifest['programs']
    active = None
    begun, ended = Counter(), Counter()
    passed = {name: Counter() for name in programs}
    hashes = {}
    for line in console.splitlines():
        if line.startswith('FUSE_PROTOCOL_BEGIN '):
            name = line.split()[-1]
            if active is not None or name not in programs:
                errors.append('Unexpected program begin: ' + line)
            active = name
            begun[name] += 1
        elif line.startswith('FUSE_PROTOCOL_END '):
            fields = line.split()
            if len(fields) != 3 or fields[1] != active or fields[2] != '0':
                errors.append('Unsuccessful or mismatched end: ' + line)
            if len(fields) >= 2:
                ended[fields[1]] += 1
            active = None
        elif line.startswith('FUSE_PROTOCOL_ARTIFACT '):
            fields = line.split()
            if len(fields) != 3 or fields[1] in hashes:
                errors.append('Malformed or duplicate artifact: ' + line)
            else:
                hashes[fields[1]] = fields[2]
        else:
            match = re.match(r'^\[\s+OK\s+\] (\S+) \(', line)
            if match:
                if active not in passed:
                    errors.append('Case outside a known program: ' + line)
                else:
                    passed[active][match[1]] += 1
    wanted = Counter({name: 1 for name in programs})
    if active is not None or begun != wanted or ended != wanted:
        errors.append('Missing, duplicate or unfinished test programs')
    for name, spec in programs.items():
        expected = Counter({case: 1 for case in spec['cases']})
        if passed[name] != expected:
            errors.append(f'{name}: missing={list((expected - passed[name]).elements())}, '
                          f'extra={list((passed[name] - expected).elements())}')
    expected_hashes = dict(manifest['artifacts'])
    expected_hashes.update({name: spec['sha256'] for name, spec in programs.items()})
    if hashes != expected_hashes:
        errors.append('Guest artifact hashes do not match the build manifest')
    if returncode != 0:
        errors.append(f'QEMU exit status {returncode}')
    if FAILURES.search(console):
        errors.append('Guest failure, skip or kernel diagnostic')
    for marker in ('FUSE_PROTOCOL_DONE', 'FUSE_PROTOCOL_EXIT 0'):
        if console.splitlines().count(marker) != 1:
            errors.append('Missing or duplicate completion marker: ' + marker)
    for marker in ('Powering system off', 'all pools are healthy'):
        if marker not in console:
            errors.append('Missing completion marker: ' + marker)
    return {'passed': not errors, 'errors': errors,
            'passed_case_count': sum(sum(rows.values()) for rows in passed.values()),
            'exit_code': returncode}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--firmware-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cpus', type=int, default=2)
    parser.add_argument('--timeout', type=int, default=3600)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    try:
        validate_manifest(manifest)
    except ValueError as error:
        parser.error(str(error))
    if args.cpus < 1 or args.timeout < 1:
        parser.error('CPU count and timeout must be positive')
    args.output.mkdir(parents=True, exist_ok=False)
    log = args.output / 'console.log'
    command = [str(args.qemu.resolve()), '-L', str(args.firmware_dir.resolve()),
               '-accel', 'tcg,thread=multi', '-m', '1536', '-smp', str(args.cpus),
               '-nic', 'none', '-display', 'none', '-monitor', 'none',
               '-serial', 'stdio', '-no-reboot', '-machine', 'q35', '-cpu', 'max',
               '-drive', f'file={args.image.resolve()},format=raw,if=virtio,snapshot=on']
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    with log.open('wb') as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + args.timeout
        try:
            while process.poll() is None:
                console = log.read_text(errors='replace')
                if time.monotonic() > deadline or re.search(
                        r'panic:|Fatal trap|lock order reversal|non-sleepable locks held', console):
                    process.kill()
                    break
                time.sleep(2)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
    result = evaluate(log.read_text(errors='replace'), manifest, process.returncode)
    result['command'] = command
    (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print('FUSE protocol:', 'PASS' if result['passed'] else 'FAIL',
          result['passed_case_count'], 'active cases')
    for error in result['errors']:
        print(error)
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
