#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check DTrace object identity across roots, distinct paths and invalid aliases.

The object must contain a probe site for the supplied provider. No live tracing
or complete toolchain reproducibility is established by this bounded check.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

p = argparse.ArgumentParser(description=__doc__)
for name in ('dtrace', 'cpp', 'linker', 'objcopy', 'drti-dir', 'provider', 'object', 'output'):
    p.add_argument('--' + name, type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
if out.exists() or not out.is_relative_to('/usr/obj') or out == Path('/usr/obj'):
    p.error('fresh output below /usr/obj required')
paths = {name: getattr(a, name.replace('-', '_')).resolve(strict=True)
         for name in ('dtrace', 'cpp', 'linker', 'objcopy', 'drti-dir', 'provider', 'object')}
if any(path.is_relative_to(out) for path in paths.values()):
    p.error('inputs must be outside output')
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
inputs = {str(path): digest(path) for path in paths.values() if path.is_file()}
inputs[str(paths['drti-dir'] / 'drti.o')] = digest(paths['drti-dir'] / 'drti.o')
out.mkdir()
records = []
def run(name, mode, spelling='library/probe.o'):
    root = out / name
    (root / 'library').mkdir(parents=True)
    (root / 'other').mkdir()
    shutil.copyfile(paths['object'], root / 'library/probe.o')
    shutil.copyfile(paths['object'], root / 'other/probe.o')
    shutil.copyfile(paths['provider'], root / 'provider.d')
    if spelling == 'ABSOLUTE':
        spelling = str(root / 'library/probe.o')
    command = [str(paths['dtrace']), '-C', '-x', 'nolibs',
               '-x', 'cpppath=' + str(paths['cpp']),
               '-x', 'ldpath=' + str(paths['linker']),
               '-x', 'objcopypath=' + str(paths['objcopy']),
               '-x', 'syslibdir=' + str(paths['drti-dir'])]
    if mode is not None:
        command += ['-x', 'linkpath=' + mode]
    command += ['-G', '-o', 'provider.o', '-s', 'provider.d', spelling]
    result = subprocess.run(command, cwd=root, env={'PATH': '/bin:/usr/bin', 'LC_ALL': 'C'},
                            capture_output=True, text=True)
    (root / 'stdout').write_text(result.stdout)
    (root / 'stderr').write_text(result.stderr)
    record = dict(name=name, argv=command, exit_status=result.returncode)
    if result.returncode == 0:
        record['object_sha256'] = digest(root / spelling)
        record['provider_sha256'] = digest(root / 'provider.o')
    records.append(record)
    (out / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
    return record

first = run('relative-first', 'relative')
second = run('relative-second', 'relative')
assert first['exit_status'] == second['exit_status'] == 0
for key in ('object_sha256', 'provider_sha256'):
    assert first[key] == second[key], 'relative identity changed across roots: ' + key
other = run('relative-other-object', 'relative', 'other/probe.o')
assert other['exit_status'] == 0
assert other['object_sha256'] != first['object_sha256'], 'distinct object paths lost identity'
# Both default and explicit absolute modes remain available and root-dependent.
for mode in (None, 'absolute'):
    name = mode or 'default'
    left, right = run(name + '-first', mode), run(name + '-second', mode)
    assert left['exit_status'] == right['exit_status'] == 0
    assert left['object_sha256'] != right['object_sha256']
for index, spelling in enumerate(('ABSOLUTE', './library/probe.o', 'library/../library/probe.o', 'library//probe.o')):
    failure = run('invalid-path-' + str(index), 'relative', spelling)
    assert failure['exit_status'] != 0
    assert 'failed to generate unique key' in (out / failure['name'] / 'stderr').read_text()
assert run('invalid-mode', 'unsupported')['exit_status'] != 0
for path, expected in inputs.items():
    assert digest(Path(path)) == expected, 'input changed: ' + path
(out / 'receipt.json').write_text(json.dumps(dict(status='passed',
    scope='relative DTrace identity across roots; distinct paths; default behavior; invalid aliases',
    inputs=inputs, records=records,
    limitations=['No active tracing.', 'No complete Bazel SDK or cross-library link qualification.']), indent=2) + '\n')
print('PASS: stable relative identity; distinct paths; default absolute behavior; invalid paths/modes rejected')
