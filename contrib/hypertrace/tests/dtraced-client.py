#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""libdtrace's dtraced client: framing, ELF delivery, async queue, handshake.

Builds dtraced-client.c with libdtrace's own compile flags (from the
maintained Makefile) and ASan/UBSan, links it against the library under
test, and runs each scenario in a separate process inside the output
directory.  See dtraced-client.c for the oracles.  No daemon, device or VM.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: dtraced-client.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
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
source = root / 'contrib/hypertrace/tests/dtraced-client.c'
command = ['cc', *keep, '-g', '-O1', '-fsanitize=address,undefined',
           '-fno-sanitize-recover=undefined', '-Wall', '-Wno-unknown-pragmas',
           str(source), '-L' + str(lib), '-Wl,-rpath,' + str(lib), '-ldtrace',
           '-lmd', '-lpthread', '-o', str(out / 'dtraced-client')]
build = subprocess.run(command, capture_output=True, text=True)
(out / 'build.log').write_text(' '.join(command) + '\n' + build.stdout + build.stderr)
if build.returncode:
    raise SystemExit('harness compilation failed; inspect build.log')
shim_src = root / 'contrib/hypertrace/tests/dtraced-client-shim.c'
shim = out / 'dtraced-client-shim.so'
r = subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
    '-I' + str(root / 'sys'), str(shim_src), '-o', str(shim)],
    capture_output=True, text=True)
(out / 'shim-build.log').write_text(r.stdout + r.stderr)
if r.returncode:
    raise SystemExit('shim compilation failed; inspect shim-build.log')
env = os.environ.copy()
env['LD_PRELOAD'] = str(shim)
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
env['ASAN_OPTIONS'] = 'detect_leaks=0'
results = []
for scenario in ('message', 'elf', 'envelope', 'async', 'discard', 'session'):
    work = out / scenario
    work.mkdir()
    r = subprocess.run([str(out / 'dtraced-client'), scenario], cwd=work, env=env,
                       capture_output=True, text=True, timeout=120)
    (work / 'run.log').write_text(r.stdout + r.stderr)
    results.append({'scenario': scenario, 'status': r.returncode,
                    'summary': (r.stdout.strip().splitlines() or [''])[-1]})
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (lib / 'libdtrace.so.2', source, shim_src, Path(__file__).resolve())},
    'scope': 'socketpair peers and a redirected test socket; preloaded '
    'birth-identity shim; no daemon or device'},
    indent=2) + '\n')
failed = [r for r in results if r['status'] != 0]
for r in failed:
    print(json.dumps(r), (out / r['scenario'] / 'run.log').read_text()[-1500:])
if failed:
    raise SystemExit(1)
print('PASS:', ', '.join(r['summary'] for r in results))
