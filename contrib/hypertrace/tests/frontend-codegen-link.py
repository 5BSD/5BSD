#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Front end versus HyperTrace linker: integer result types.

Each expression is compiled offline (frontend-codegen.c) and linked with
hypertrace_link(); the driver dumps every statement before and after the
link.  For each trace() the suite records the front end's result width and
signedness-relevant DIF (before link), the linker's width (the return type
it assigns), the C compiler's sizeof and value for the same expression, and
the value recorded by the linked DIF (executed by the interpreter in
frontend_codegen_common.py) within the linker's width.

Pass/fail (coordinator decision: the front end is the source of truth for
D's types, which do not apply C's integer promotions): every case must
compile and link; the linker must give each result the front end's width;
and the value the linked DIF records must equal the D value, which is C's
arithmetic result taken at the front end's width (D computes in 64-bit
registers and records the front end's width).  Disagreements are also
written to agreement.json for diagnosis, classified as arithmetic/bitwise
with char/short operands, comparisons, unary/ternary, or folded constants.
"""
import itertools
import json
import subprocess
import sys
from pathlib import Path
from frontend_codegen_common import (check_args, build, compile_cases, finish, Machine,
                                     run_difo, DIFError, M64)

out, obj = check_args(sys.argv, 'world')
exe = build(out, obj)
TYPES = ['char', 'unsigned char', 'short', 'unsigned short', 'int', 'unsigned int',
         'long', 'unsigned long']
OPS = ['+', '-', '*', '&', '|', '^', '<<', '>>', '<', '==', '/', '%']
exprs = []
for t1, t2 in itertools.product(TYPES, TYPES):
    for op in OPS:
        if op in ('/', '%'):
            exprs.append(f'(({t1})arg0 {op} (({t2})arg1 | 1))')
        elif op in ('<<', '>>'):
            exprs.append(f'(({t1})arg0 {op} (({t2})arg1 & 7))')
        else:
            exprs.append(f'(({t1})arg0 {op} ({t2})arg1)')
for t in TYPES:
    exprs += [f'(-({t})arg0)', f'(~({t})arg0)', f'(+({t})arg0)', f'(!({t})arg0)',
              f'(arg2 ? ({t})arg0 : (char)arg1)', f'(({t})arg0)']
# Constant expressions folded by the front end.
exprs += ['((char)3 + (char)4)', '((unsigned char)200 * 2)', '((short)-1 >> 1)',
          '((unsigned short)65535 + 1)', '(+(unsigned char)255)', '(~(unsigned char)0)',
          '((char)-128 / (char)-1)', '(1 ? (unsigned char)200 : (short)1)']
VECTORS = [[-3 & M64, 7, 1, 0], [200, 300, 0, 0], [0x7fffffff, -129 & M64, 1, 0],
           [0x1234567890, 0xfff0, 0, 0]]

csrc = ['#include <stdint.h>', '#include <stdio.h>', 'int main(void) {',
        'int64_t arg0, arg1, arg2, arg3;',
        f'static const uint64_t V[{len(VECTORS)}][4] = {{' +
        ','.join('{' + ','.join(f'{x & M64}ULL' for x in v) + '}' for v in VECTORS) + '};',
        f'for (int v = 0; v < {len(VECTORS)}; v++) {{',
        'arg0 = (int64_t)V[v][0]; arg1 = (int64_t)V[v][1]; arg2 = (int64_t)V[v][2];',
        'arg3 = (int64_t)V[v][3]; (void)arg3;']
for i, e in enumerate(exprs):
    csrc.append(f'printf("%d %d %llu %d\\n", {i}, v, (unsigned long long){e}, '
                f'(int)sizeof ({e}));')
csrc += ['}', 'return 0; }']
(out / 'oracle.c').write_text('\n'.join(csrc) + '\n')
subprocess.run(['cc', '-fwrapv', '-w', '-o', str(out / 'oracle'), str(out / 'oracle.c')],
               check=True)
oracle = {}
for line in subprocess.run([str(out / 'oracle')], capture_output=True, text=True,
                           check=True).stdout.splitlines():
    i, v, r, size = map(int, line.split())
    oracle[(i, v)] = (r, size)

def klass(e):
    if 'arg' not in e:
        return 'folded-constant'
    if any(f' {op} ' in e for op in ('<', '==')) and '<<' not in e:
        return 'comparison'
    if e.startswith(('(-(', '(~(', '(+(', '(!(', '(arg2 ?')):
        return 'unary-ternary'
    return 'arithmetic'


PER = 16
cases = [{'name': f'link{c // PER}', 'opts': ['link'],
          'prog': 'BEGIN { ' + ' '.join(f'trace({e});' for e in exprs[c:c + PER]) + ' }'}
         for c in range(0, len(exprs), PER)]
got = compile_cases(exe, obj, out, cases)
results, agreement = [], []
for ci, c in enumerate(cases):
    g = got[c['name']]
    if 'error' in g or g.get('link') != 0:
        results.append({'case': c['name'], 'passed': False, 'error': g.get('error'),
                        'link': g.get('link'), 'linkmsg': g.get('linkmsg')})
        continue
    before = [st['actions'][0]['difo'] for st in g['stmts0']]
    after = [st['actions'][0]['difo'] for st in g['stmts']]
    for k, (d0, d1) in enumerate(zip(before, after)):
        i = ci * PER + k
        fe, lk = d0['rtype'][3], d1['rtype'][3]
        for v, vec in enumerate(VECTORS):
            r, csize = oracle[(i, v)]
            try:
                raw = run_difo(Machine({'args': vec}), d1)
            except DIFError as err:
                results.append({'expr': exprs[i], 'passed': False, 'note': str(err)})
                continue
            fmask = (1 << 8 * min(fe, 8)) - 1
            lmask = (1 << 8 * min(lk, 8)) - 1
            recorded = raw & lmask
            d_value = r & fmask          # C's arithmetic at D's (front-end) width
            ok_value = (recorded & fmask) == d_value
            ok_width = fe == lk
            if not (ok_width and ok_value):
                agreement.append({'expr': exprs[i], 'vector': v, 'class': klass(exprs[i]),
                                  'frontend_size': fe, 'linker_size': lk, 'c_size': csize,
                                  'recorded': recorded, 'd_value': d_value})
            if v == 0 or not (ok_width and ok_value):
                results.append({'expr': exprs[i], 'vector': v, 'class': klass(exprs[i]),
                                'passed': ok_width and ok_value, 'width_ok': ok_width,
                                'value_ok': ok_value, 'frontend_size': fe,
                                'linker_size': lk})
(out / 'agreement.json').write_text(json.dumps(agreement, indent=1) + '\n')
finish(out, results, [Path(__file__), Path(__file__).with_name('frontend-codegen.c'),
                      Path(__file__).with_name('frontend_codegen_common.py'),
                      obj / 'cddl/lib/libdtrace/libdtrace.so.2'],
       'Front end vs hypertrace_link() result types; linked DIF executed by the '
       'interpreter vs the C compiler; NOSYS dtrace_vopen model',
       'front-end/linker typing cases')
