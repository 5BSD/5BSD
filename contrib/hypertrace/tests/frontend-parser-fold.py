#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""D integer constant folding, typing and precedence against the C compiler.

Oracle: the system C compiler (LP64, same integer model as D on amd64)
evaluating the identical expression text.  The Dynamic Tracing Guide
specifies ANSI-C integer constant typing (C99 6.4.4.1 for long long), the
usual arithmetic conversions and C operator precedence for D.  Random
expressions over integer/character constants, casts, sizeof, unary, binary
and conditional operators are generated with a fixed seed and rendered
either fully parenthesised or with minimal parentheses (C precedence and
associativity), so the C parse is the precedence oracle as well.

Each D expression is compiled as BEGIN { trace(E); } through libdtrace
(NODEV|NOSYS, option tree=2).  The folded constant must be the whole action
(DIF: setx; ret), its value truncated to the traced size must equal the C
value, the traced size must equal sizeof(E), and the signedness reported by
the cooked parse tree must equal C's.

Scope (documented D semantics, not C): D keeps intermediate values in 64-bit
registers and does not apply C's integer promotions to char/short operands.
Expressions are therefore kept to cases where both languages are defined to
agree: sub-int types appear only directly beneath a widening cast, and a
non-root subexpression may not wrap or change value through an implicit
conversion (casts are folded exactly as C converts, including same-width
changes of signedness).  C types of every node are
obtained from the C compiler first (stage 1, unevaluated sizeof/typeof), the
filter applies C's conversion rules to those types, and the C compiler then
evaluates the kept expressions (stage 2).  Character constants >= 0x80 are
excluded (D stores the unsigned byte value).
"""
from pathlib import Path
import json
import random
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend_parser as fp

out, obj = fp.check_args(sys.argv, 'usage: frontend-parser-fold.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
SEED, COUNT = 20261021, 2400
rng = random.Random(SEED)

WIDE = ['int', 'unsigned int', 'long', 'unsigned long', 'long long', 'unsigned long long',
        'int32_t', 'uint32_t', 'int64_t', 'uint64_t']
NARROW = ['char', 'signed char', 'unsigned char', 'short', 'unsigned short',
          'int8_t', 'uint8_t', 'int16_t', 'uint16_t']
# C precedence (higher binds tighter); all binary operators are left-assoc.
BIN = {'*': 13, '/': 13, '%': 13, '+': 12, '-': 12, '<<': 11, '>>': 11,
       '<': 10, '<=': 10, '>': 10, '>=': 10, '==': 9, '!=': 9, '&': 8, '^': 7,
       '|': 6, '&&': 5, '||': 4}
UN = ['-', '+', '~', '!']


def literal():
    kind = rng.random()
    if kind < 0.12:
        c = rng.choice([("'a'", None), ("'\\n'", None), ("'\\t'", None), ("'\\\\'", None),
                        ("'\\x41'", None), ("'\\101'", None), ("'\\0'", None),
                        ("'\\a'", None), ("'\\b'", None), ("'\\f'", None), ("'\\r'", None),
                        ("'\\v'", None), ("'\\\"'", None), ("'\\7'", None), ("'\\x7f'", None),
                        ("'ab'", None), ("'abc'", None), ("'Zz1'", None), ("'ABCD'", None)])
        return {'op': 'lit', 'text': c[0]}
    mag = rng.choice([0, 1, 2, 3, 7, 10, 100, 255, 256, 65535, 65536, 0x7fffffff, 0x80000000,
                      0xffffffff, 0x100000000, 0x7fffffffffffffff, 0x8000000000000000,
                      0xffffffffffffffff, rng.randrange(1 << rng.choice([4, 8, 16, 31, 33, 62, 64]))])
    base = rng.choice(['d', 'x', 'X', 'o'])
    suffix = rng.choice(['', '', '', 'u', 'U', 'l', 'L', 'ul', 'UL', 'uL', 'll', 'LL', 'ull', 'ULL', 'uLL'])
    if base == 'd':
        if mag > 0x7fffffffffffffff and 'u' not in suffix.lower():
            mag &= 0x7fffffffffffffff  # unsuffixed decimals never become unsigned
        text = str(mag)
    elif base in 'xX':
        text = ('0x' if base == 'x' else '0X') + format(mag, 'x' if rng.random() < .5 else 'X')
    else:
        text = '0' + format(mag, 'o') if mag else '0'
    return {'op': 'lit', 'text': text + suffix}


def gen(depth):
    r = rng.random()
    if depth == 0 or r < 0.18:
        if rng.random() < 0.06:
            return {'op': 'sizeoft', 'type': rng.choice(WIDE + NARROW + ['void *', 'char *'])}
        return literal()
    if r < 0.30:
        return {'op': 'un', 'sym': rng.choice(UN), 'kids': [gen(depth - 1)]}
    if r < 0.40:
        if rng.random() < 0.4:
            return {'op': 'cast', 'type': rng.choice(WIDE),
                    'kids': [{'op': 'cast', 'type': rng.choice(NARROW), 'kids': [gen(depth - 1)]}]}
        return {'op': 'cast', 'type': rng.choice(WIDE), 'kids': [gen(depth - 1)]}
    if r < 0.45:
        return {'op': 'sizeofe', 'kids': [gen(depth - 1)]}
    if r < 0.52:
        return {'op': 'cond', 'kids': [gen(depth - 1), gen(depth - 1), gen(depth - 1)]}
    return {'op': 'bin', 'sym': rng.choice(list(BIN)), 'kids': [gen(depth - 1), gen(depth - 1)]}


def prec(n):
    return {'bin': lambda: BIN[n['sym']], 'cond': lambda: 3}.get(n['op'], lambda: 15)()


def render(n, minimal):
    """Fully parenthesised, or minimal parentheses by C precedence."""
    op = n['op']
    if op == 'lit':
        return n['text']
    if op == 'sizeoft':
        return f"sizeof ({n['type']})"
    k = n.get('kids', [])
    if op == 'un':
        inner = render(k[0], minimal)
        if not minimal or prec(k[0]) < 15 or inner[0] in '+-':
            inner = f'({inner})'
        return f"{n['sym']}{inner}"
    if op == 'cast':
        inner = render(k[0], minimal)
        return f"({n['type']})" + (inner if minimal and prec(k[0]) == 15 and inner[0] not in '+-' else f'({inner})')
    if op == 'sizeofe':
        return f'sizeof ({render(k[0], minimal)})'
    if op == 'cond':
        a, b, c = (render(x, minimal) for x in k)
        if not minimal:
            return f'(({a}) ? ({b}) : ({c}))'
        a = a if prec(k[0]) > 3 else f'({a})'
        b = b if prec(k[1]) > 3 else f'({b})'
        c = c if prec(k[2]) >= 3 else f'({c})'
        return f'{a} ? {b} : {c}'
    p = BIN[n['sym']]
    a, b = render(k[0], minimal), render(k[1], minimal)
    if not minimal:
        return f'(({a}) {n["sym"]} ({b}))'
    a = a if prec(k[0]) >= p else f'({a})'
    b = b if prec(k[1]) > p else f'({b})'
    return f'{a} {n["sym"]} {b}'


def nodes(n, acc):
    acc.append(n)
    for k in n.get('kids', []):
        nodes(k, acc)
    return acc


def run_cc(name, body):
    src = out / f'{name}.c'
    src.write_text('#include <stdio.h>\n#include <stdint.h>\n#include <stddef.h>\n' + body)
    exe = out / name
    b = subprocess.run(['cc', '-std=gnu17', '-fwrapv', '-w', '-Wno-parentheses', '-o', str(exe), str(src)],
                       capture_output=True, text=True)
    (out / f'{name}.log').write_text(b.stdout + b.stderr)
    if b.returncode:
        raise SystemExit(f'C oracle {name} failed to compile; see {name}.log')
    return subprocess.run([str(exe)], capture_output=True, text=True, check=True).stdout


exprs = [gen(rng.choice([1, 2, 3, 4])) for _ in range(COUNT)]
for i, e in enumerate(exprs):
    e['minimal'] = i % 2 == 1
# Stage 1: C type (size, signedness) of every node and, for binary
# operators, of the usual-arithmetic-conversion common type.
lines, index = [], []
for i, e in enumerate(exprs):
    for j, n in enumerate(nodes(e, [])):
        t = render(n, False)
        lines.append(f'{{sizeof({t}), (__typeof__({t}))-1 < 0}},')
        index.append((i, j, 'self'))
        if n['op'] == 'bin' and n['sym'] not in ('<<', '>>', '&&', '||'):
            a, b = (render(k, False) for k in n['kids'])
            lines.append(f'{{sizeof(({a}) + ({b})), (__typeof__(({a}) + ({b})))-1 < 0}},')
            index.append((i, j, 'common'))
        if n['op'] == 'cond':
            a, b = (render(k, False) for k in n['kids'][1:])
            lines.append(f'{{sizeof(1 ? ({a}) : ({b})), (__typeof__(1 ? ({a}) : ({b})))-1 < 0}},')
            index.append((i, j, 'common'))
stage1 = run_cc('types', 'static const struct { size_t size; int sign; } t[] = {\n' + '\n'.join(lines) +
                '\n};\nint main(void) { for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) '
                'printf("%zu %d\\n", t[i].size, t[i].sign); return 0; }\n').split('\n')
ctype = {}
for key, row in zip(index, stage1):
    size, sign = map(int, row.split())
    ctype[key] = (size * 8, bool(sign))


def conv(v, t):
    bits, signed = t
    v &= (1 << bits) - 1
    return v - (1 << bits) if signed and v >> (bits - 1) else v


def fits(v, t):
    return conv(v, t) == v


class Reject(Exception):
    pass


def charval(text):
    body = text[1:-1]
    esc = {'n': 10, 't': 9, '\\': 92, "'": 39, '"': 34, 'a': 7, 'b': 8, 'f': 12, 'r': 13, 'v': 11}
    out_bytes, i = [], 0
    while i < len(body):
        if body[i] == '\\':
            c = body[i + 1]
            if c == 'x':
                m = re.match(r'[0-9a-fA-F]+', body[i + 2:])
                out_bytes.append(int(m.group(0), 16)); i += 2 + len(m.group(0))
            elif c in '01234567':
                m = re.match(r'[0-7]{1,3}', body[i + 1:])
                out_bytes.append(int(m.group(0), 8)); i += 1 + len(m.group(0))
            else:
                out_bytes.append(esc[c]); i += 2
        else:
            out_bytes.append(ord(body[i])); i += 1
    v = 0
    for b in out_bytes:
        v = v * 256 + b
    return v


def value(e, n, j, root):
    """C value of node n under C rules, raising Reject where D's documented
    64-bit/no-promotion model may legitimately differ from C."""
    t = ctype[(e, j, 'self')]
    op = n['op']
    kids = n.get('kids', [])
    if op != 'cast' and t[0] < 32:
        raise Reject('sub-int node outside a cast chain')
    if op == 'lit':
        text = n['text']
        if text.startswith("'"):
            return charval(text)
        v = int(text.rstrip('uUlL'), 8 if re.match(r'0[0-7]', text) else 0)
        assert fits(v, t)
        return v
    if op == 'sizeofe':
        if not root:
            # D folds sizeof only for types and strings at parse time; an
            # expression operand is sized during cooking (not folded).
            raise Reject('sizeof expression below the root')
        value(e, kids[0], j + 1, False)  # operand must lie in the shared domain
        return ctype[(e, j + 1, 'self')][0] // 8
    if op == 'sizeoft':
        return SIZES[n['type']]
    # child indices in pre-order numbering
    idx, k = [], j + 1
    for kid in kids:
        idx.append(k)
        k += len(nodes(kid, []))
    vals = [value(e, kid, i2, False) for kid, i2 in zip(kids, idx)]
    if op == 'cast':
        src = ctype[(e, idx[0], 'self')]
        r = conv(vals[0], t)
        return r
    if op == 'un':
        a, s = vals[0], n['sym']
        if not fits(a, t):
            raise Reject('implicit conversion')
        if s == '-':
            exact = -a
            if not fits(exact, t) and t[1]:
                raise Reject('signed overflow')
            return conv(exact, t)
        if s == '+':
            return a
        if s == '~':
            if not t[1] and t[0] < 64 and not root:
                raise Reject('~ of a sub-64-bit unsigned value below the root')
            return conv(~a, t)
        return int(not a)
    if op == 'cond':
        common = ctype[(e, j, 'common')]
        chosen = vals[1] if vals[0] else vals[2]
        if not fits(chosen, common) and not root:
            raise Reject('conditional conversion changes value')
        return conv(chosen, common)
    s = n['sym']
    a, b = vals
    if s in ('&&', '||'):
        return int(bool(a) and bool(b)) if s == '&&' else int(bool(a) or bool(b))
    if s in ('<<', '>>'):
        if not fits(a, t) or b < 0 or b >= t[0]:
            raise Reject('shift operand or count')
        exact = a << b if s == '<<' else a >> b
        if not fits(exact, t) or (s == '<<' and a < 0):
            raise Reject('shift overflow')
        return exact
    common = ctype[(e, j, 'common')]
    if not fits(a, common) or not fits(b, common):
        raise Reject('implicit conversion changes value')
    if s in ('/', '%'):
        if b == 0:
            raise Reject('division by zero')
        q = abs(a) // abs(b) * (1 if (a >= 0) == (b >= 0) else -1)
        exact = q if s == '/' else a - q * b
    else:
        exact = {'*': a * b, '+': a + b, '-': a - b, '&': a & b, '^': a ^ b, '|': a | b,
                 '<': int(a < b), '<=': int(a <= b), '>': int(a > b), '>=': int(a >= b),
                 '==': int(a == b), '!=': int(a != b)}[s]
    if not fits(exact, t) and not root:
        raise Reject('arithmetic wraps below the root')
    if not fits(exact, t) and t[1]:
        raise Reject('signed overflow')
    return conv(exact, t)


# LP64 sizes of the named types (C99/LP64 data model).
SIZES = {'void *': 8, 'char *': 8, 'char': 1, 'signed char': 1, 'unsigned char': 1,
         'int8_t': 1, 'uint8_t': 1, 'short': 2, 'unsigned short': 2, 'int16_t': 2,
         'uint16_t': 2}
for name in WIDE:
    SIZES[name] = 4 if name in ('int', 'unsigned int', 'int32_t', 'uint32_t') else 8
kept, reasons = [], {}
for i, e in enumerate(exprs):
    try:
        e['pyvalue'] = value(i, e, 0, True)
        kept.append(i)
    except Reject as why:
        reasons[str(why)] = reasons.get(str(why), 0) + 1
# Stage 2: the C compiler evaluates every kept expression.
body = []
for i in kept:
    t = render(exprs[i], exprs[i]['minimal'])
    body.append(f'{{(unsigned long long)({t}), sizeof({t}), (__typeof__({t}))-1 < 0}},')
stage2 = run_cc('values', 'static const struct { unsigned long long v; size_t size; int sign; } t[] = {\n'
                + '\n'.join(body) + '\n};\nint main(void) { for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) '
                'printf("%llu %zu %d\\n", t[i].v, t[i].size, t[i].sign); return 0; }\n').split('\n')
h = fp.Harness(out, obj)
cases = [{'id': str(i), 'src': f'BEGIN {{ trace({render(exprs[i], exprs[i]["minimal"])}); }}',
          'opts': ['tree=2'], 'keep': True} for i in kept]
res = h.run(cases)
C = fp.dif_constants()
results, failed = [], []
for i, row in zip(kept, stage2):
    cv, size, sign = (int(x) for x in row.split())
    text = render(exprs[i], exprs[i]['minimal'])
    r = res[str(i)]
    rec = {'expr': text, 'c': {'value': cv, 'size': size, 'signed': bool(sign)}}
    ok = r['compiled'] and len(r['stmts']) == 1
    if ok:
        d = r['stmts'][0]['acts'][0]['difo']
        ins = d['insns']
        # A folded constant is setx then ret; HyperTrace typecast markers
        # (DIF_OP_TYPECAST, no value effect) may follow a folded cast.
        core = [x for x in ins if x >> 24 != C['DIF_OP_TYPECAST']]
        ok = (len(core) == 2 and core[0] >> 24 == C['DIF_OP_SETX'] and core[1] >> 24 == C['DIF_OP_RET'])
        ins = core
        m = re.search(r'\n      (?:INT 0x([0-9a-f]+)|OP1 sizeof) \(type=<([^>]*)> attr=\S+ flags=([A-Z,0]+)\)', r['output'])
        if ok and m:
            raw = int(d['ints'][ins[0] >> 8 & 0xffff])
            bits = d['rsize'] * 8
            dsigned = 'SIGN' in m.group(3).split(',')
            dv = raw & ((1 << bits) - 1)
            cvt = cv & ((1 << bits) - 1)
            rec['d'] = {'value': dv, 'size': d['rsize'], 'signed': dsigned, 'type': m.group(2)}
            ok = d['rsize'] == size and dsigned == bool(sign) and dv == cvt and (m.group(1) is None or int(m.group(1), 16) == raw)
            # The filter's own C-rule evaluation must agree with the compiler.
            if conv(exprs[i]['pyvalue'], (size * 8, bool(sign))) & ((1 << size * 8) - 1) != cv & ((1 << size * 8) - 1):
                rec['filter_mismatch'] = exprs[i]['pyvalue']
                ok = False
        else:
            ok = False
    if not ok:
        rec['error'] = r.get('error')
        rec['output'] = r.get('output')
        failed.append(rec)
    rec['passed'] = ok
    results.append(rec)
(out / 'results.json').write_text(json.dumps({'seed': SEED, 'generated': COUNT, 'kept': len(kept),
    'rejected_by_reason': reasons, 'cases': results}, indent=1) + '\n')
h.provenance([__file__], 'D constant folding/typing/precedence vs the system C compiler; NODEV|NOSYS')
for f in failed[:40]:
    print('FAIL', json.dumps(f)[:600])
if failed or len(kept) < COUNT // 3:
    raise SystemExit(f'{len(failed)} of {len(kept)} folded expressions differ from C')
print('PASS:', len(kept), 'folded constant expressions match the C compiler',
      f'({COUNT - len(kept)} outside the shared C/D domain)')
