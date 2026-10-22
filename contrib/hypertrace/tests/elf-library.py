#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify matched built libraries offline; never open a DTrace device."""
from pathlib import Path
import concurrent.futures, json, os, subprocess, sys
if len(sys.argv) != 3:
    raise SystemExit('usage: elf-library.py /usr/obj/results /usr/obj/.../amd64.amd64')
out, world = (Path(arg).resolve() for arg in sys.argv[1:])
if not all(path.is_relative_to('/usr/obj') for path in (out, world)):
    raise SystemExit('Use /usr/obj for build and test artifacts')
out.mkdir(parents=True, exist_ok=True)
tests = Path(__file__).resolve().parent
library = world / 'cddl/lib/libdtrace/libdtrace.so.2'
source = tests.parent.parent.parent
inspector = out / 'elf-format-inspect.so'
subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
    '-Wno-unknown-pragmas',
    '-I', str(source / 'sys/cddl/compat/opensolaris'),
    '-I', str(source / 'cddl/compat/opensolaris/include'),
    '-I', str(source / 'sys/cddl/contrib/opensolaris/uts/common'),
    '-I', str(source / 'sys'),
    '-I', str(source / 'cddl/contrib/opensolaris/lib/libdtrace/common'),
    '-I', str(source / 'cddl/contrib/opensolaris/lib/libctf/common'),
    str(tests / 'elf-format-inspect.c'), '-o', str(inspector)], check=True)
env = os.environ.copy()
env.pop('LD_PRELOAD', None)
env['LD_LIBRARY_PATH'] = ':'.join(str(world / p) for p in
    ('cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
def run(name, command, environment=env):
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=90)
    (out / (name + '.log')).write_text(result.stdout + result.stderr)
    return {'case': name, 'status': result.returncode}
results = []
for name in ('elf-parser-boundary', 'elf-roundtrip', 'program-identity',
             'compiler-offline', 'options-offline', 'pragma-offline'):
    command = [sys.executable, str(tests / (name + '.py'))]
    if name != 'program-identity': command.append(str(out / name))
    command.append(str(library))
    if name == 'elf-roundtrip': command.append(str(inspector))
    results.append(run(name, command))
    if results[-1]['status']:
        raise SystemExit(f'{name} failed; inspect {out}')
subprocess.run(['cc', '-fPIC', '-Wall', '-Wextra', '-Werror', '-c',
    str(tests / 'elf-allocation.c'), '-o', str(out / 'elf-allocation.o')], check=True)
subprocess.run(['c++', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
    str(tests / 'elf-new-allocation.cc'), str(out / 'elf-allocation.o'),
    '-o', str(out / 'elf-allocation.so')], check=True)
injected = env.copy(); injected['LD_PRELOAD'] = str(out / 'elf-allocation.so')
fixtures = sorted((out / 'elf-roundtrip').glob('program-*.elf'))
def allocation(fixture):
    return run('allocation-' + fixture.stem, [sys.executable, str(tests / 'elf-allocation.py'),
               str(library), str(fixture)], injected)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    results += list(pool.map(allocation, fixtures))
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
for result in results: print(result)
if any(result['status'] for result in results): raise SystemExit(1)
print('PASS: actual built ELF library round trips, malformed input and C/C++ allocation failures; no live tracing')
