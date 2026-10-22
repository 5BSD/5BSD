# SPDX-License-Identifier: BSD-2-Clause
"""Shared build/run helpers for the frontend-runtime-* suites.

Each suite compiles a C harness (and optionally a preloaded shim) against
the libdtrace object tree under test with libdtrace's own -I/-D/-std flags,
runs it, and records results.json and provenance.json.  A harness prints
"FAIL <text>" lines and a final "PASS/FAIL <n> checks, <m> failures" line.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parents[2]


def setup(name):
    if len(sys.argv) != 3:
        raise SystemExit(f'usage: {name}.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
    out, obj = (Path(a).resolve() for a in sys.argv[1:])
    if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
        raise SystemExit('Use a new /usr/obj output and an existing object tree')
    out.mkdir(parents=True)
    return out, obj


def cflags(obj):
    prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])
    flags = subprocess.run(
        ['make', '-C', str(ROOT / 'cddl/lib/libdtrace'), '-m', str(ROOT / 'share/mk'),
         'SRCTOP=' + str(ROOT), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null', '-V', 'CFLAGS'],
        env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)},
        capture_output=True, text=True, check=True).stdout.split()
    return [f for f in flags if f.startswith(('-I', '-D', '-std='))]


SANITIZE = ['-g', '-O1', '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined']
FAULTS = ['-g', '-O0', '-DWITH_FAULTS', '-lexecinfo']


def build(out, obj, source, exe, extra, shared=False, libs=('-ldtrace',)):
    lib = obj / 'cddl/lib/libdtrace'
    ctf = obj / 'cddl/lib/libctf'
    cmd = ['cc', *cflags(obj), '-I' + str(out), '-I' + str(TESTS), *extra, '-Wall',
           '-Wno-unknown-pragmas', *(['-shared', '-fPIC'] if shared else []), str(source),
           '-L' + str(lib), '-L' + str(ctf), '-Wl,-rpath,' + str(lib), *libs, '-o', str(exe)]
    b = subprocess.run(cmd, capture_output=True, text=True)
    log = out / ('build-' + Path(exe).name + '.log')
    log.write_text(' '.join(cmd) + '\n' + b.stdout + b.stderr)
    if b.returncode:
        raise SystemExit(f'build failed; inspect {log}')
    return exe


def env_for(obj, preload=None):
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
        ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
    env['ASAN_OPTIONS'] = 'detect_leaks=0'
    env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
    if preload:
        env['LD_PRELOAD'] = str(preload)
    return env


def run(out, exe, env, args=(), timeout=900):
    r = subprocess.run([str(exe), *map(str, args)], cwd=out, env=env,
                       capture_output=True, text=True, timeout=timeout)
    (out / ('run-' + Path(exe).name + '.log')).write_text(r.stdout + r.stderr)
    lines = r.stdout.strip().splitlines()
    return {'returncode': r.returncode, 'summary': lines[-1] if lines else '',
            'failures': [l for l in lines if l.startswith('FAIL ')][:80]}


def finish(out, obj, results, sources, scope):
    library = obj / 'cddl/lib/libdtrace/libdtrace.so.2'
    sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    files = [library, *sources, Path(sys.argv[0]).resolve(), Path(__file__).resolve()]
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    (out / 'provenance.json').write_text(json.dumps(
        {'sha256': {str(p): sha(p) for p in files}, 'scope': scope}, indent=2) + '\n')
    bad = [n for n, r in results.items()
           if r['returncode'] or not r['summary'].startswith('PASS')]
    for n in bad:
        print(n, json.dumps(results[n], indent=1))
    if bad:
        raise SystemExit(1)
    print('PASS:', '; '.join(f"{n}: {r['summary']}" for n, r in results.items()))
