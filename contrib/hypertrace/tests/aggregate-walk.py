#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Aggregation snapshot, merge, sort and walk cases through actual libdtrace.

aggregate-walk.c reuses the modeled dtrace(4) vector of consume-ingestion.c
with dtrace_vopen(); expected values come from D aggregation semantics and
the documented sort rules.  A second, unsanitized build injects allocation
and sysctl failures.  No tracing device, kernel module, guest or daemon.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: aggregate-walk.py /usr/obj/results /usr/obj/.../amd64.amd64')
root = Path(__file__).resolve().parents[3]
out, obj = (Path(arg).resolve() for arg in sys.argv[1:])
if not all(path.is_relative_to('/usr/obj') for path in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output directory and an existing object tree')
out.mkdir(parents=True)
lib = obj / 'cddl/lib/libdtrace'
library = lib / 'libdtrace.so.2'
if not library.exists():
    raise SystemExit('Build libdtrace first')
tests = root / 'contrib/hypertrace/tests'
source = tests / 'aggregate-walk.c'
model = tests / 'consume-ingestion.c'
common = root / 'cddl/contrib/opensolaris/lib/libdtrace/common'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)]) if 'usr' in obj.parts[3:] else obj
includes = [prefix / 'source-includes'] if (prefix / 'source-includes').exists() else []
flags = [
    '-std=gnu17', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
    *('-I' + str(p) for p in includes),
    '-I' + str(tests),
    '-I' + str(root / 'sys'),
    '-I' + str(common),
    '-I' + str(root / 'cddl/contrib/opensolaris/lib/libctf/common'),
    '-I' + str(root / 'cddl/contrib/opensolaris/head'),
    '-I' + str(root / 'sys/cddl/compat/opensolaris'),
    '-I' + str(root / 'cddl/compat/opensolaris/include'),
    '-I' + str(root / 'sys/cddl/contrib/opensolaris/uts/common'),
]
link = ['-L' + str(lib), '-Wl,-rpath,' + str(lib), '-ldtrace', '-lelf', '-lxo']
builds = {
    'aggregate-walk': ['-O1', '-fsanitize=address,undefined',
                       '-fno-sanitize-recover=undefined'],
    'aggregate-walk-fault': ['-O0', '-DAGG_FAULT', '-rdynamic', '-lproc',
                             '-lutil'],
}
log = []
for name, extra in builds.items():
    srcs = [str(source)] + ([str(tests / 'aggregate-walk-vm.c')]
                            if '-DAGG_FAULT' in extra else [])
    command = ['cc', *extra, *flags, *srcs, *link, '-o', str(out / name)]
    build = subprocess.run(command, capture_output=True, text=True)
    log.append(' '.join(command) + '\n' + build.stdout + build.stderr)
    if build.returncode:
        (out / 'build.log').write_text('\n'.join(log))
        raise SystemExit('harness compilation failed; inspect build.log')
(out / 'build.log').write_text('\n'.join(log))
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
passed, failed, rcs = [], [], {}
text = ''
for name in builds:
    test = subprocess.run([str(out / name)], env=env, cwd=out,
        capture_output=True, text=True, timeout=600)
    rcs[name] = test.returncode
    text += f'== {name} rc {test.returncode}\n' + test.stdout + test.stderr
    passed += [f'{name}:' + l.split()[1] for l in test.stdout.splitlines()
               if l.startswith('PASS ')]
    failed += [f'{name}:' + l.split()[1].rstrip(':')
               for l in test.stdout.splitlines() if l.startswith('FAIL ')]
(out / 'run.log').write_text(text)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p)
    for p in (library, source, model, tests / 'aggregate-walk-vm.c',
              Path(__file__).resolve())},
    'scope': 'dtrace_vopen with the consume-ingestion dtrace(4) model; '
    'scripted aggregation firings; allocation/sysctl fault injection in an '
    'unsanitized build; no device, kernel, guest or daemon'}, indent=2) + '\n')
(out / 'results.json').write_text(json.dumps({'returncodes': rcs,
    'passed': passed, 'failed': failed}, indent=2) + '\n')
if any(rcs.values()) or failed or not passed:
    print(text[-6000:])
    raise SystemExit('aggregate walk failed; inspect run.log')
print('PASS:', len(passed), 'aggregation walk cases')
