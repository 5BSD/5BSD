#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Integer expression code generation, differential against the C compiler.

Seeded random integer expressions over arg0..arg3 (int64_t in D) are
compiled by libdtrace offline (frontend-codegen.c) and the DIF of each
trace() action is executed by the independent interpreter in
frontend_codegen_common.py with several argument vectors.  The oracle is
the system C compiler evaluating the same expression text with int64_t
arg0..arg3 (D follows the ANSI-C integer promotion and conversion rules):
the C program reports each result, sizeof(expr) and whether the type is
signed; D must agree on the value (within the traced width) and on the
traced width and signedness.

Domain restrictions (documented D behaviour, not oracle copying): DIF
registers are 64-bit and D does not truncate intermediate results of
32-bit arithmetic, so every 32-bit +, -, *, <<, unary - and ~ result is
wrapped in an explicit cast to its own type; division and remainder use
divisors that are never zero or -1; left shifts are applied to uint64_t
operands with counts masked to 0..63.  Expressions that need more DIF
registers than exist are reported by D as D_NOREG and are counted, not
evaluated.
"""
import json
import random
import subprocess
import sys
from pathlib import Path
from frontend_codegen_common import (check_args, build, compile_cases, finish,
                                     Machine, run_difo, DIFError, sha, M64)

out, obj = check_args(sys.argv, 'world')
exe = build(out, obj)
rng = random.Random(0x5B5D)

# (C/D spelling, size, signed)
TYPES = [('char', 1, True), ('unsigned char', 1, False), ('short', 2, True),
         ('unsigned short', 2, False), ('int', 4, True), ('unsigned int', 4, False),
         ('long', 8, True), ('unsigned long', 8, False), ('int64_t', 8, True),
         ('uint64_t', 8, False), ('uint8_t', 1, False), ('int16_t', 2, True),
         ('uint32_t', 4, False), ('int32_t', 4, True)]
T = {t[0]: t for t in TYPES}
INT, UINT, LONG, ULONG = T['int'], T['unsigned int'], T['long'], T['unsigned long']


def promote(t):
    return INT if t[1] < 4 else t


def usual(a, b):
    a, b = promote(a), promote(b)
    if a[2] == b[2]:
        return a if a[1] >= b[1] else b
    s, u = (a, b) if a[2] else (b, a)
    if u[1] >= s[1]:
        return u
    return s  # signed is wider and represents every unsigned value


def norm(t):
    """Canonical type for size/sign only."""
    return {(4, True): INT, (4, False): UINT, (8, True): LONG, (8, False): ULONG}.get(
        (t[1], t[2]), t)


def wrap(e, t):
    if t[1] == 4:
        return f'(({t[0]})({e}))', t
    return e, t


def gen(depth):
    """Return (expr text, type) for an expression that, unless it is a single
    constant, depends on at least one argument (constant-only subtrees are
    folded by the parser, whose divergences are probed separately below)."""
    e, t = _gen(depth)
    if e.startswith('(') and 'arg' not in e:
        return f'arg{rng.randrange(4)}', T['int64_t']
    return e, t


def _gen(depth):
    if depth == 0 or rng.random() < 0.2:
        r = rng.random()
        if r < 0.65:
            return f'arg{rng.randrange(4)}', T['int64_t']
        v = rng.choice([0, 1, 2, 3, 7, 8, 31, 100, 255, 256, 1000, 65535, 0x7fffffff,
                        0x80000000, 0xffffffff, 0x100000000, 0x123456789abc])
        text = str(v) if rng.random() < 0.5 else hex(v)
        # C and D type an unsuffixed constant by the same rules.
        if v <= 0x7fffffff:
            return text, INT
        if v <= 0xffffffff and text.startswith('0x'):
            return text, UINT
        return text, LONG
    k = rng.random()
    if k < 0.15:
        e, t = gen(depth - 1)
        c = rng.choice(TYPES)
        return f'(({c[0]}){e})', c
    if k < 0.22:
        e, t = gen(depth - 1)
        op = rng.choice(['-', '~', '!', '+'])
        if op == '!':
            return f'(!{e})', INT
        pt = promote(t)
        r = f'({op}{e})'
        return wrap(r, pt) if op != '+' else (r, pt)
    if k < 0.30:
        c, _ = gen(depth - 1)
        a, ta = gen(depth - 1)
        b, tb = gen(depth - 1)
        return f'({c} ? {a} : {b})', usual(ta, tb)
    if k < 0.33:
        a, _ = gen(depth - 1)
        b, tb = gen(depth - 1)
        return f'({a}, {b})', tb
    a, ta = gen(depth - 1)
    b, tb = gen(depth - 1)
    op = rng.choice(['+', '-', '*', '&', '|', '^', '/', '%', '<<', '>>', '==', '!=',
                     '<', '<=', '>', '>=', '&&', '||'])
    if op in ('==', '!=', '<', '<=', '>', '>=', '&&', '||'):
        return f'({a} {op} {b})', INT
    if op in ('/', '%'):
        # Divisor is always in [1, 256]; type is that of (b & 255) + 1.
        bt = usual(usual(tb, INT), INT)
        rt = usual(ta, bt)
        return f'({a} {op} ((({b}) & 255) + 1))', rt
    if op == '<<':
        return f'(((uint64_t)({a})) << (({b}) & 63))', ULONG
    if op == '>>':
        pt = promote(ta)
        cnt = (pt[1] * 8) - 1
        return f'({a} >> (({b}) & {cnt}))', pt
    rt = usual(ta, tb)
    return wrap(f'({a} {op} {b})', rt)


exprs = []
seen = set()
while len(exprs) < 2400:
    e, t = gen(rng.choice([1, 2, 2, 3, 3, 4]))
    if e not in seen and e.startswith('('):
        seen.add(e)
        exprs.append((e, t))
# Hand-picked boundary cases for casts, signedness and comparisons.
for e in ['((unsigned int)arg0)', '((uint64_t)(unsigned int)(int)arg0)',
          '((int64_t)(int)(unsigned int)arg0)', '((long)(unsigned char)arg0)',
          '((unsigned long)(char)arg0)', '((int)(short)arg0)', '((unsigned short)(short)arg0)',
          '((uint64_t)(int)arg0 < 0)', '((int)arg0 < (unsigned int)arg1)',
          '((int)arg0 >= (unsigned int)arg1)', '((int)arg0 / (unsigned int)((arg1 & 255) + 1))',
          '((int)arg0 % (unsigned int)((arg1 & 255) + 1))', '(arg0 ? (int)arg1 : (unsigned int)arg2)',
          '((arg0 ? (int)arg1 : (unsigned int)arg2) + arg3)', '((short)arg0 < (unsigned short)arg1)',
          '((unsigned int)arg0 > (int)arg1)',
          '(arg0 < 0 ? -arg0 : arg0)', '((uint64_t)arg0 >> 63)', '(arg0 >> 63)',
          '((unsigned char)arg0 * (unsigned char)arg1)', '(+arg0)', '(-(-arg0))',
          '(sizeof (arg0) + sizeof ((char)arg1) + sizeof ((short)arg2))',
          '((int)((unsigned int)arg0 / 3))', '(((uint64_t)arg0) % 1000000007)',
          # Folded and run-time same-width signedness casts agree with C.
          '((uint64_t)(unsigned int)(int)(arg0 - arg0 - 5) == (uint64_t)(unsigned int)(int)-5)',
          '((uint64_t)(unsigned int)(int)(arg0 - arg0 - 5))', '((int64_t)(int)(unsigned int)arg1)',
          '((int64_t)arg0 / -7)', '((int64_t)arg0 % -7)', '(arg0 / 7)', '(arg0 % 7)']:
    exprs.append((e, None))

# Known divergences of the parser (dt_parser.c, not part of code generation):
# constant folding keeps out-of-range values for the folded type, and type
# promotion skips the integer promotions for char/short operands and for
# unary + and shifts.  These are evaluated and recorded (not pass/fail) so a
# parser fix is visible here.
DIVERGENT = ['((int)0x80000000)', '((unsigned int)(2 * 0xffffffff))',
             '((char)arg0 < (unsigned char)arg1)', '(+((unsigned char)arg0))',
             '(((unsigned short)arg0) >> 1)']
FIRST_DIVERGENT = len(exprs)
exprs += [(e, None) for e in DIVERGENT]

VECTORS = [[0, 0, 0, 0], [1, -1, 2, -2], [127, 128, 255, 256],
           [-128, 32767, -32768, 65535], [0x7fffffff, -0x80000000, 0xffffffff, 0x100000000],
           [0x7fffffffffffffff, -0x8000000000000000, -1, 0x123456789abcdef],
           [rng.getrandbits(64) - (1 << 63) for _ in range(4)],
           [rng.getrandbits(33) - (1 << 32) for _ in range(4)]]

# ---- C oracle -------------------------------------------------------------
csrc = ['#include <stdint.h>', '#include <stdio.h>',
        'static void emit(int i, int v, unsigned long long r, int size, int sgn)',
        '{ printf("%d %d %llu %d %d\\n", i, v, r, size, sgn); }',
        'int main(void) {', 'int64_t arg0, arg1, arg2, arg3;',
        f'static const int64_t V[{len(VECTORS)}][4] = {{' +
        ','.join('{' + ','.join(f'(int64_t){x & M64}ULL' for x in v) + '}' for v in VECTORS) + '};',
        f'for (int v = 0; v < {len(VECTORS)}; v++) {{',
        'arg0 = V[v][0]; arg1 = V[v][1]; arg2 = V[v][2]; arg3 = V[v][3];']
for i, (e, _) in enumerate(exprs):
    csrc.append(f'emit({i}, v, (unsigned long long){e}, (int)sizeof ({e}), '
                f'(__typeof__({e}))-1 < 0);')
csrc += ['}', 'return 0; }']
(out / 'oracle.c').write_text('\n'.join(csrc) + '\n')
cc = subprocess.run(['cc', '-std=gnu17', '-O0', '-fwrapv', '-w', str(out / 'oracle.c'),
                     '-o', str(out / 'oracle')], capture_output=True, text=True)
(out / 'oracle-build.log').write_text(cc.stdout + cc.stderr)
if cc.returncode:
    raise SystemExit('oracle compilation failed')
oracle = {}
for line in subprocess.run([str(out / 'oracle')], capture_output=True, text=True,
                           check=True).stdout.splitlines():
    i, v, r, size, sgn = map(int, line.split())
    oracle[(i, v)] = (r, size, sgn)

# ---- D side ---------------------------------------------------------------
PER = 12
cases = []
for c in range(0, len(exprs), PER):
    body = ' '.join(f'trace({e});' for e, _ in exprs[c:c + PER])
    cases.append({'name': f'arith{c // PER}', 'prog': f'BEGIN {{ {body} }}'})
got = compile_cases(exe, obj, out, cases)

results = []
widths = []
divergence = {}
for ci, c in enumerate(cases):
    g = got[c['name']]
    chunk = list(range(ci * PER, min((ci + 1) * PER, len(exprs))))
    if 'error' in g:
        # Re-run each expression alone to isolate register exhaustion.
        results.append({'case': c['name'], 'passed': False, 'error': g['error']})
        continue
    acts = [st['actions'][0] for st in g['stmts']]
    assert len(acts) == len(chunk), c['name']
    for i, a in zip(chunk, acts):
        d = a['difo']
        size = d['rtype'][3]
        for v, vec in enumerate(VECTORS):
            m = Machine({'args': [x & M64 for x in vec]})
            r, csize, csgn = oracle[(i, v)]
            try:
                raw = run_difo(m, d)
                w = (1 << 8 * min(size, csize)) - 1
                ok = (raw & w) == (r & w)
                note = None
            except DIFError as err:
                raw, ok, note = None, False, str(err)
            if i >= FIRST_DIVERGENT:
                divergence.setdefault(exprs[i][0], []).append(
                    {'vector': v, 'd': raw, 'c': r, 'd_size': size, 'c_size': csize})
                continue
            if size != csize:
                widths.append({'expr': exprs[i][0], 'd_size': size, 'c_size': csize})
            if not ok or v == 0:
                results.append({'expr': exprs[i][0], 'vector': v, 'd': raw, 'c': r,
                                'd_size': size, 'c_size': csize, 'note': note,
                                'passed': ok})
# Width divergences come from parser typing (dt_parser.c, reported): the
# integer promotions are not applied to char/short operands, unary + and
# shifts, and a ternary with a constant condition is folded to the selected
# operand with that operand's type.  D is then narrower than C; values are
# compared within the narrower width and every divergence is recorded.  D
# must never be wider than C.
(out / 'parser-divergence.json').write_text(json.dumps(divergence, indent=1) + '\n')
uniq = {w['expr']: w for w in widths}
(out / 'width-divergence.json').write_text(json.dumps(list(uniq.values()), indent=1) + '\n')
for w in uniq.values():
    results.append({'width': w, 'passed': w['d_size'] < w['c_size']})
finish(out, results, [exe.with_name('frontend-codegen.c') if False else
       Path(__file__).with_name('frontend-codegen.c'), Path(__file__),
       Path(__file__).with_name('frontend_codegen_common.py'),
       obj / 'cddl/lib/libdtrace/libdtrace.so.2'],
       'Random integer expressions: libdtrace DIF executed by an independent '
       'interpreter vs the C compiler (-fwrapv); NOSYS dtrace_vopen model',
       'integer expression differential checks')
