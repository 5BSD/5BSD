#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Collect reproducible coverage from explicitly listed offline HyperTrace suites.

This collector does not certify coverage thresholds. Missing original-source
attribution and uninstrumented production paths remain separate inventory gaps.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys

SUITES = ('native-port', 'native-daemon', 'migration-tls',
          'migration-receiver', 'migration-recovery-exchange')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=Path)
parser.add_argument('--suite', action='append', choices=SUITES, required=True)
args = parser.parse_args()
out = args.output.resolve()
if not out.is_relative_to('/usr/obj'):
    parser.error('Use an isolated directory under /usr/obj')
if out.exists():
    parser.error('Output must be new; mixing stale counters invalidates evidence')
if len(set(args.suite)) != len(args.suite):
    parser.error('Do not repeat suites')
root = Path(__file__).resolve().parents[3]
tests = Path(__file__).resolve().parent
out.mkdir(parents=True)
wrappers = out / 'bin'
wrappers.mkdir()
metadata = {'suites': args.suite, 'live_tests': False,
            'source_head': subprocess.check_output(
                ['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
            'source_identity_note': 'HEAD is not a dirty-tree digest; retain mapped source hashes when exporting.',
            'tools': {}, 'test_driver_sha256': {},
            'flags': ['-fprofile-instr-generate', '-fcoverage-mapping',
                      '-fprofile-update=atomic']}
for compiler in ('cc', 'c++', 'clang', 'clang++'):
    binary = Path('/usr/bin') / compiler
    metadata['tools'][compiler] = subprocess.check_output(
        [str(binary), '--version'], text=True).splitlines()[0]
    p = wrappers / compiler
    p.write_text('#!/bin/sh\nexec ' + str(binary) + ' ' +
                 ' '.join(metadata['flags']) + ' "$@"\n')
    p.chmod(0o755)
results = []
for suite in args.suite:
    driver = tests / (suite + '.py')
    metadata['test_driver_sha256'][suite] = hashlib.sha256(driver.read_bytes()).hexdigest()
    profiles = out / (suite + '-profiles')
    profiles.mkdir()
    env = os.environ.copy()
    env.update(PATH=str(wrappers) + os.pathsep + env.get('PATH', ''),
               LLVM_PROFILE_FILE=str(profiles / '%m-%p.profraw'),
               HYPERTRACE_COVERAGE_DIR=str(profiles))
    command = [sys.executable, str(driver), str(out / suite)]
    with (out / (suite + '.log')).open('w') as log:
        completed = subprocess.run(command, env=env, stdout=log,
                                   stderr=subprocess.STDOUT)
    raw = sorted(profiles.glob('*.profraw'))
    errors = []
    for log in [out / (suite + '.log'), *(out / suite).rglob('*.log')]:
        if 'LLVM Profile Error' in log.read_text(errors='replace'):
            errors.append(str(log))
    merge_status = None
    if raw:
        listing = out / (suite + '-profiles.txt')
        listing.write_text('\n'.join(map(str, raw)) + '\n')
        with (out / (suite + '-merge.log')).open('w') as log:
            merge_status = subprocess.run(
                ['llvm-profdata', 'merge', '-sparse', '-f', str(listing),
                 '-o', str(out / (suite + '.profdata'))],
                stdout=log, stderr=subprocess.STDOUT).returncode
    result = {'suite': suite, 'command': command,
              'test_status': completed.returncode, 'profiles': len(raw),
              'merge_status': merge_status, 'profile_error_logs': errors,
              'passed': completed.returncode == 0 and bool(raw) and
                        merge_status == 0 and not errors}
    results.append(result)
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    (out / 'provenance.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    if not result['passed']:
        raise SystemExit(1)
