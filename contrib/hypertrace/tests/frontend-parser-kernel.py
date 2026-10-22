#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Provider redeclaration against providers known to dtrace(4).

Uses the frontend-codegen.c driver, whose dtrace_vopen() vector models the
dtrace(4) provider and probe ioctls (provider "test" with argument-less
probes such as test:kernel:alpha:entry).  Oracle: dt_node_provider_cmp's
documented rules -- a redeclaration of a provider exported by dtrace(4) must
match its interface: the same probes, the same output arguments, and no
output prototype where the kernel probe has none.
"""
import json
import sys
from pathlib import Path
from frontend_codegen_common import check_args, build, compile_cases, finish, TESTS

out, obj = check_args(sys.argv, 'world')
exe = build(out, obj, 'frontend-codegen.c')
CASES = [
    ('impl-same', 'provider test { probe entry(); }; BEGIN { trace(1); }', None),
    ('impl-output-proto', 'provider test { probe entry(int x) : (); }; BEGIN { trace(1); }',
     'provider interface mismatch: test\n\t current: probe test:::entry has an output prototype'),
    ('impl-output-args', 'provider test { probe entry(int x) : (int x); }; BEGIN { trace(1); }',
     'probe test:::entry output prototype mismatch:\n\t current: 1 arg\n\tprevious: 0 args'),
    ('impl-new-probe', 'provider test { probe nosuch97(); }; BEGIN { trace(1); }',
     'provider interface mismatch: test\n\t current: probe test:::nosuch97 defined'),
]
got = compile_cases(exe, obj, out, [{'name': n, 'prog': p} for n, p, _ in CASES])
results = []
for name, prog, want in CASES:
    d = got[name]
    ok = ('stmts' in d) if want is None else (d.get('error', '').startswith(want))
    results.append({'case': name, 'program': prog, 'expected': want, 'got': d.get('error'), 'passed': ok})
finish(out, results, [Path(__file__), TESTS / 'frontend-codegen.c', TESTS / 'frontend_codegen_common.py',
                      obj / 'cddl/lib/libdtrace/libdtrace.so.2'],
       'provider redeclaration against modelled dtrace(4) providers', 'kernel-provider redeclaration cases')
