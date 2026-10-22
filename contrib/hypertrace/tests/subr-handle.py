#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""libdtrace utilities, errors, handlers, description maps and D sugar.

Builds subr-handle.c (which includes the dtrace(4) model of
consume-ingestion.c) with libdtrace's own compile flags and ASan/UBSan,
links it against the library under test, preloads dtraced-client-shim.c
for the process birth identity, and runs each case group in its own process
and directory.  See subr-handle.c for the oracles.  No daemon, device or VM.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: subr-handle.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
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
source = tests / 'subr-handle.c'
model = tests / 'consume-ingestion.c'
command = ['cc', *keep, '-I' + str(tests), '-g', '-O1',
           '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
           '-Wall', '-Wno-unknown-pragmas', '-Wno-unused-function', '-rdynamic',
           str(source), '-L' + str(lib), '-Wl,-rpath,' + str(lib), '-ldtrace',
           '-lelf', '-lxo', '-lctf', '-lcrypto', '-lpthread',
           '-L' + str(obj / 'cddl/lib/libctf'), '-o', str(out / 'subr-handle')]
build = subprocess.run(command, capture_output=True, text=True)
(out / 'build.log').write_text(' '.join(command) + '\n' + build.stdout + build.stderr)
if build.returncode:
    raise SystemExit('harness compilation failed; inspect build.log')
shim_src = tests / 'dtraced-client-shim.c'
shim = out / 'birth-shim.so'
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
env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
env.pop('DTRACE_DEBUG', None)
groups = ['errors', 'descriptions', 'attributes', 'versions', 'misc',
          'difo-dup', 'addr2str', 'registration', 'error-records',
          'setopt-handler', 'cpu-drops', 'status-drops', 'oformat-drops',
          'buffered', 'printf-overflow', 'maps', 'sugar', 'debug', 'uaddr',
          'progerr', 'freopen', 'identity', 'derived', 'oformat-style',
          'oformat-discard']
results = []
for g in groups:
    work = out / g
    work.mkdir()
    r = subprocess.run([str(out / 'subr-handle'), g], cwd=work, env=env,
                       capture_output=True, text=True, timeout=300)
    (work / 'run.log').write_text(r.stdout + r.stderr)
    results.append({'group': g, 'status': r.returncode,
                    'summary': (r.stdout.strip().splitlines() or [''])[-1]})


def drops_ok(path, want_dyn):
    """Drop objects in the structured output (parsed, not text-matched)."""
    doc = json.loads(path.read_text())
    probes = doc['dtrace']['probes']
    drops = [p for p in probes if 'kind' in p]
    principal = [d for d in drops if d['kind'] == 0]
    dynamic = [d for d in drops if d['kind'] == 2]
    ok = (len(principal) == 1 and principal[0]['count'] == 1 and
          principal[0]['msg'] == '1 drop on CPU 0\n' and
          principal[0]['cpu'] == 0)
    if want_dyn:
        ok = ok and len(dynamic) == 1 and dynamic[0]['count'] == 2 and \
            dynamic[0]['total'] == 2 and dynamic[0]['cpu'] == -1 and \
            dynamic[0]['msg'] == '2 dynamic variable drops\n'
    return ok


json_checks = {}
for name, want_dyn in (('drops.json', True), ('drops-nohandler.json', False),
                       ('drops-abort.json', False)):
    try:
        json_checks[name] = drops_ok(out / 'oformat-drops' / name, want_dyn)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as e:
        json_checks[name] = 'error: %s' % e
(out / 'results.json').write_text(json.dumps({'groups': results,
    'json': json_checks}, indent=2) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (lib / 'libdtrace.so.2', source, model, shim_src, Path(__file__).resolve())},
    'scope': 'dtrace_vopen with the consume-ingestion dtrace(4) model and a '
    'scripted wrapper; socket peers on a redirected test socket; preloaded '
    'birth-identity shim; no daemon, device or VM'}, indent=2) + '\n')
failed = [r for r in results if r['status'] != 0]
for r in failed:
    print(json.dumps(r), (out / r['group'] / 'run.log').read_text()[-3000:])
bad_json = {k: v for k, v in json_checks.items() if v is not True}
if bad_json:
    print('structured drop output:', bad_json)
if failed or bad_json:
    raise SystemExit(1)
checks = sum(int(r['summary'].split(':')[1].split()[0]) for r in results)
print('PASS:', len(results), 'groups,', checks, 'checks')
