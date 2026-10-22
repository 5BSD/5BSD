#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Identifier hash, register set and compile-ident list contracts.

Builds frontend-codegen-unit.c with libdtrace's CFLAGS and ASan/UBSan and
runs its direct checks (see the C file for the documented contracts).
"""
import json
import subprocess
import sys
from pathlib import Path
from frontend_codegen_common import check_args, build, env_for, finish

out, obj = check_args(sys.argv, 'world')
exe = build(out, obj, 'frontend-codegen-unit.c')
env = env_for(obj)
env.pop('DTRACE_DEBUG_REGSET')  # regset-assert-leak leaks on purpose
r = subprocess.run([str(exe)], env=env, capture_output=True, text=True,
                   timeout=300, cwd=out)
(out / 'run.log').write_text(r.stdout + r.stderr)
# Resolver checks: the identity interposer makes gethostname() and the
# kern.osrelease sysctl fail; libdtrace must report errors, not exit.
shim = out / 'frontend-codegen-resolver-shim.so'
b = subprocess.run(['cc', '-shared', '-fPIC', '-o', str(shim),
                    str(Path(__file__).with_name('frontend-codegen-resolver-shim.c'))],
                   capture_output=True, text=True)
(out / 'build-resolver-shim.log').write_text(b.stdout + b.stderr)
renv = env | {'LD_PRELOAD': str(shim), 'ASAN_OPTIONS': 'detect_leaks=0:verify_asan_link_order=0'}
r2 = subprocess.run([str(exe), 'resolver'], env=renv, capture_output=True, text=True,
                    timeout=300, cwd=out)
(out / 'run-resolver.log').write_text(r2.stdout + r2.stderr)
# Leak check: an uninstrumented build of the driver compiles one clause of
# N and 2N statements under the live-allocation shim; after dtrace_close()
# the live heap must not grow with the number of statements (regression: the
# per-DIFO type-name table leaked about 2.9 KB per statement).
plain = build(out / 'plain', obj, 'frontend-codegen-unit.c', sanitize=False) \
    if (out / 'plain').mkdir() is None else None
ashim = out / 'frontend-codegen-alloc-shim.so'
subprocess.run(['cc', '-shared', '-fPIC', '-O1', '-o', str(ashim),
                str(Path(__file__).with_name('frontend-codegen-alloc-shim.c'))], check=True)
lenv = env | {'LD_PRELOAD': str(ashim)}
live = {}
for n in (8, 16, 32):
    rl = subprocess.run([str(plain), 'compile', str(n)], env=lenv, capture_output=True,
                        text=True, timeout=300)
    (out / f'run-leak-{n}.log').write_text(rl.stdout + rl.stderr)
    line = [l for l in rl.stderr.splitlines() if l.startswith('LIVE ')]
    live[n] = tuple(map(int, line[-1].split()[1:])) if rl.returncode == 0 and line else None
leak_ok = all(live.values()) and live[16] == live[8] and live[32] == live[8]
ra = subprocess.run([str(exe), 'regset-abort'], env=env | {'DTRACE_DEBUG_REGSET': '1'},
                    capture_output=True, text=True, timeout=60, cwd=out)
(out / 'run-regset-abort.log').write_text(ra.stdout + ra.stderr)
extra = ra.stdout
for mode in ('regset-free-range', 'regset-free-negative', 'regset-free-twice'):
    rf = subprocess.run([str(exe), mode], env=env, capture_output=True, text=True,
                        timeout=60, cwd=out)
    (out / f'run-{mode}.log').write_text(rf.stdout + rf.stderr)
    extra += rf.stdout if rf.stdout.strip() else f'FAIL {mode}: rc {rf.returncode}\n'
r2 = subprocess.CompletedProcess(r2.args, r2.returncode, r2.stdout + extra, r2.stderr)
results = [{'check': 'compile-no-per-statement-leak', 'passed': leak_ok,
            'detail': json.dumps({str(k): v for k, v in live.items()})}]
if b.returncode or r2.returncode not in (0, 1) or 'failures' not in r2.stdout:
    results.append({'check': 'resolver-driver-exit', 'passed': False,
                    'detail': f'rc {r2.returncode} {r2.stderr[-500:]}'})
for line in (r.stdout + r2.stdout).splitlines():
    if line.startswith(('PASS ', 'FAIL ')):
        results.append({'check': line.split()[1].rstrip(':'), 'passed': line.startswith('PASS'),
                        'detail': line})
if r.returncode not in (0, 1) or not results:
    results.append({'check': 'driver-exit', 'passed': False, 'detail': r.stderr[-2000:]})
finish(out, results, [Path(__file__), Path(__file__).with_name('frontend-codegen-unit.c'),
                      Path(__file__).with_name('frontend-codegen-resolver-shim.c'),
                      Path(__file__).with_name('frontend-codegen-alloc-shim.c'),
                      Path(__file__).with_name('frontend_codegen_common.py'),
                      obj / 'cddl/lib/libdtrace/libdtrace.so.2'],
       'dt_idhash/dt_regset/dt_idkind_name/dtrace_compile_idents_set direct checks',
       'identifier hash and register set checks')
