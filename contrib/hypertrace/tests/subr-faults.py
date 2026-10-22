#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Failure paths of libdtrace utilities, maps, buffered output and the
dtraced client under documented fault returns.

Builds subr-faults.c (with the consume-ingestion.c dtrace(4) model) using
libdtrace's own compile flags, without sanitizers because the preloaded
subr-faults-shim.c replaces malloc(3), and runs each group in its own
process and directory.  See subr-faults.c for the oracles.  No daemon,
device or VM.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: subr-faults.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
root = Path(__file__).resolve().parents[3]
out, obj = (Path(arg).resolve() for arg in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output and an existing object tree')
out.mkdir(parents=True)
lib = obj / 'cddl/lib/libdtrace'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])
cflags = subprocess.run(
    ['make', '-C', str(root / 'cddl/lib/libdtrace'), '-m', str(root / 'share/mk'),
     'SRCTOP=' + str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
     '-V', 'CFLAGS'], env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)},
    capture_output=True, text=True, check=True).stdout.split()
keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
tests = root / 'contrib/hypertrace/tests'
source = tests / 'subr-faults.c'
model = tests / 'consume-ingestion.c'
shim_src = tests / 'subr-faults-shim.c'
shim = out / 'subr-faults-shim.so'
steps = [
    ['cc', '-shared', '-fPIC', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
     '-I' + str(root / 'sys'), str(shim_src), '-o', str(shim)],
    ['cc', *keep, '-I' + str(tests), '-g', '-O1', '-Wall',
     '-Wno-unknown-pragmas', '-Wno-unused-function', str(source),
     '-L' + str(lib), '-Wl,-rpath,' + str(lib), '-ldtrace', '-lelf', '-lxo',
     '-lcrypto', '-lpthread', '-o', str(out / 'subr-faults')],
]
with (out / 'build.log').open('w') as log:
    for cmd in steps:
        log.write(' '.join(cmd) + '\n')
        r = subprocess.run(cmd, capture_output=True, text=True)
        log.write(r.stdout + r.stderr)
        if r.returncode:
            raise SystemExit('compilation failed; inspect build.log')
env = os.environ.copy()
env['LD_PRELOAD'] = str(shim)
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
groups = ['consume-sweeps', 'utilities', 'discard', 'transport', 'session',
          'send-elf', 'async-alloc', 'async-queue', 'async-failure',
          'async-closing']
results = []
for g in groups:
    work = out / g
    work.mkdir()
    r = subprocess.run([str(out / 'subr-faults'), g, 'async.err'], cwd=work,
                       env=env, capture_output=True, text=True, timeout=600)
    (work / 'run.log').write_text(r.stdout + r.stderr)
    results.append({'group': g, 'status': r.returncode,
                    'summary': (r.stdout.strip().splitlines() or [''])[-1]})
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (lib / 'libdtrace.so.2', source, model, shim_src, Path(__file__).resolve())},
    'scope': 'preloaded fault shim (documented failure returns of calls made '
    'by libdtrace); dtrace_vopen model; socketpair peers; no daemon, device '
    'or VM'}, indent=2) + '\n')
failed = [r for r in results if r['status'] != 0]
for r in failed:
    print(json.dumps(r), (out / r['group'] / 'run.log').read_text()[-3000:])
if failed:
    raise SystemExit(1)
checks = sum(int(r['summary'].split(':')[1].split()[0]) for r in results)
print('PASS:', len(results), 'groups,', checks, 'checks')
