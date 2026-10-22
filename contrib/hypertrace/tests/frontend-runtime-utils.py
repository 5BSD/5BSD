#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Property tests for dt_string, dt_list, dt_inttab and dt_strtab.

Builds frontend-runtime-utils.c twice against the library under test: once
with ASan/UBSan (property and differential checks), once without sanitizers
and with -DWITH_FAULTS (every allocation of each operation failed in turn).
The escape fixtures are C string literals compiled by cc, so the byte values
the decoder must produce come from the C compiler, not from libdtrace.
Offline: NODEV|NOSYS handle only.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: frontend-runtime-utils.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
root = Path(__file__).resolve().parents[3]
out, obj = (Path(a).resolve() for a in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output and an existing object tree')
out.mkdir(parents=True)
lib = obj / 'cddl/lib/libdtrace'
library = lib / 'libdtrace.so.2'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])
cflags = subprocess.run(
    ['make', '-C', str(root / 'cddl/lib/libdtrace'), '-m', str(root / 'share/mk'),
     'SRCTOP=' + str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null', '-V', 'CFLAGS'],
    env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)},
    capture_output=True, text=True, check=True).stdout.split()
keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
source = Path(__file__).with_suffix('.c')

# D/C escape sources whose decoded bytes the C compiler supplies.
FIXTURES = [r'abc', r'\n\t\r', r'\a\b\f\v', r'\\', r'\"', r'\0', r'\7', r'\12',
            r'\101', r'\1012', r'\377', r'\0400', r'\x41', r'\x7e', r'\xff',
            r'\x0g', r'A\x42z', r'\60\61', r'mixed\x20\101\n!', r'\08', r'\18', r'\2', r'\45', r'\56', r'\x4:', r'\x4!', r'\x4G', r"\'", r'\?', r"a\'b\?c"]
lines = ['struct fixture { const char *source; const char *bytes; size_t len; };',
         'static const struct fixture fixtures[] = {']
for f in FIXTURES:
    c_src = f.replace('\\', '\\\\').replace('"', '\\"')
    lines.append(f'\t{{ "{c_src}", "{f}", sizeof ("{f}") - 1 }},')
lines.append('};')
(out / 'escape-fixtures.h').write_text('\n'.join(lines) + '\n')

builds = {
    'asan': ['-g', '-O1', '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined'],
    'faults': ['-g', '-O0', '-DWITH_FAULTS'],
}
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
env['ASAN_OPTIONS'] = 'detect_leaks=0'
results = {}
for name, extra in builds.items():
    exe = out / ('frontend-runtime-utils-' + name)
    cmd = ['cc', *keep, '-I' + str(out), *extra, '-Wall', '-Wno-unknown-pragmas',
           str(source), '-L' + str(lib), '-Wl,-rpath,' + str(lib), '-ldtrace', '-o', str(exe)]
    b = subprocess.run(cmd, capture_output=True, text=True)
    (out / f'build-{name}.log').write_text(' '.join(cmd) + '\n' + b.stdout + b.stderr)
    if b.returncode:
        raise SystemExit(f'{name} build failed; inspect build-{name}.log')
    r = subprocess.run([str(exe)], cwd=out, env=env, capture_output=True, text=True, timeout=600)
    (out / f'run-{name}.log').write_text(r.stdout + r.stderr)
    last = (r.stdout.strip().splitlines() or [''])[-1]
    results[name] = {'returncode': r.returncode, 'summary': last,
                     'failures': [l for l in r.stdout.splitlines() if l.startswith('FAIL ')][:50]}
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (library, source, Path(__file__).resolve())},
    'scope': 'dt_string/dt_list/dt_inttab/dt_strtab via exported internals; NODEV|NOSYS'},
    indent=2) + '\n')
bad = [n for n, r in results.items() if r['returncode'] or not r['summary'].startswith('PASS')]
for n in bad:
    print(n, json.dumps(results[n], indent=1))
if bad:
    raise SystemExit(1)
print('PASS:', '; '.join(f"{n}: {r['summary']}" for n, r in results.items()))
