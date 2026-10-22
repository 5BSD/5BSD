#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Test a built snapshot bhyvectl against local IPC; never open a VM."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: migration-cli-ipc.py /usr/obj/<output> /path/to/snapshot-bhyvectl')
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
binary = Path(sys.argv[2]).resolve(strict=True)
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
# Bind evidence to the binary actually exercised, not the installed command.
digest = hashlib.sha256(binary.read_bytes()).hexdigest()
commands = [
    ['cc', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
     '-I' + str(root / 'usr.sbin/bhyve'),
     str(Path(__file__).with_suffix('.c')), '-lnv', '-o', str(out / 'ipc-test')],
    [str(out / 'ipc-test'), str(binary)],
]
results = []
for name, command in zip(('build', 'run'), commands):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (out / (name + '.log')).write_text(result.stdout + result.stderr)
    results.append({'phase': name, 'status': result.returncode})
    if result.returncode:
        break
unchanged = hashlib.sha256(binary.read_bytes()).hexdigest() == digest
passed = len(results) == 2 and all(r['status'] == 0 for r in results) and unchanged
(out / 'results.json').write_text(json.dumps({
    'binary': str(binary), 'sha256': digest, 'binary_unchanged': unchanged,
    'results': results, 'passed': passed, 'live_vm': False,
    'scope': 'Compiled frontend and libnv IPC with a mock source controller; not migration qualification',
}, indent=2) + '\n')
if not passed:
    raise SystemExit('FAIL: see build.log, run.log and results.json')
print('PASS: compiled migration initiation/recovery/repair frontend, 26 IPC cases')
