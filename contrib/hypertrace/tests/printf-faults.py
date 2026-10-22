#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exhaustive allocation-failure injection for libdtrace's printf/print paths.

Builds printf-faults.c (no ASan: it interposes malloc, calloc and strdup)
with libdtrace's compile flags and runs every scenario; see the C file for
the oracle.  Each injected failure runs in its own child.  NODEV|NOSYS; no
device, kernel or daemon.

usage: printf-faults.py /usr/obj/new-output /usr/obj/.../amd64.amd64
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit(__doc__.strip().splitlines()[-1])
root = Path(__file__).resolve().parents[3]
out, obj = (Path(a).resolve() for a in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output directory and an existing object tree')
out.mkdir(parents=True)
lib = obj / 'cddl/lib/libdtrace'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)]) if 'usr' in obj.parts[3:] else obj
cflags = subprocess.run(
    ['make', '-C', str(root / 'cddl/lib/libdtrace'), '-m', str(root / 'share/mk'),
     'SRCTOP=' + str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null', '-V', 'CFLAGS'],
    env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)}, capture_output=True, text=True,
    check=True).stdout.split()
keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
includes = [prefix / 'source-includes'] if (prefix / 'source-includes').exists() else []
source = root / 'contrib/hypertrace/tests/printf-faults.c'
command = ['cc', *keep, *('-I' + str(p) for p in includes), '-g', '-O1', '-Wall',
           '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-sign-compare',
           '-Wno-unknown-pragmas', str(source), '-L' + str(lib),
           '-L' + str(obj / 'cddl/lib/libctf'), '-ldtrace', '-lctf', '-lelf', '-lxo',
           '-o', str(out / 'printf-faults')]
build = subprocess.run(command, capture_output=True, text=True)
(out / 'build.log').write_text(' '.join(command) + '\n' + build.stdout + build.stderr)
if build.returncode:
    raise SystemExit('harness compilation failed; inspect build.log')
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
scenarios = ['pfdict', 'printf-create', 'printf-dup', 'sprintf', 'escape',
             'print-text', 'print-structured', 'fprinta', 'print-value']
results = []
for sc in scenarios:
    r = subprocess.run([str(out / 'printf-faults'), sc], env=env, cwd=out,
                       capture_output=True, text=True, timeout=600)
    (out / (sc + '.log')).write_text(r.stdout + r.stderr)
    lines = r.stdout.splitlines()
    injected = sum(1 for l in lines if ' injected ok' in l)
    results.append({'scenario': sc, 'returncode': r.returncode,
                    'injected_failures': injected, 'last': lines[-1] if lines else '',
                    'passed': r.returncode == 0 and injected > 0})
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (lib / 'libdtrace.so.2', source, Path(__file__).resolve())},
    'scope': 'malloc/calloc/strdup failure injection in forked children; NODEV|NOSYS'},
    indent=2) + '\n')
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r))
if failed:
    raise SystemExit('allocation-failure injection failed')
print('PASS:', sum(r['injected_failures'] for r in results),
      'injected allocation failures across', len(results), 'scenarios')
