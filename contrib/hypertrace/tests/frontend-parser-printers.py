#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Parse-tree printers: DTRACE_C_SUGAR source output and the tree dumps.

Oracle 1 (round trip): with DTRACE_C_SUGAR the compiler prints the clauses
of the program after the sugar transformation (dt_printd).  That text,
preceded by the program's declarations (which are not clauses and are not
printed), is D source for the same program, so compiling it again (without
SUGAR) must produce exactly the same statements: probe descriptions,
predicate and action DIF (opcodes and operands, integer and string tables,
variable tables, return types).  Programs using if/else are excluded from
the round trip: dt_sugar.c introduces the internal variables self->%error
and this->%condition_N, which are deliberately not valid D identifiers; for
those only the presence of the generated guard clauses is checked.

Oracle 2 (tree dump, option tree=N): DT_TREEDUMP_PASS(dtp, p) selects pass p
by bit p-1 (dt_impl.h).  Pass 1 dumps the parsed tree, pass 2 each cooked
clause, pass 3 the root at the end, pass 4 prints each clause as D source.
For programs written to contain one node of each kind, the dump must name
each node with the label and operands given by the node's construction
(e.g. OP2 + over VARIABLE x and INT 0x1), at increasing indentation.
"""
from pathlib import Path
import json
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend_parser as fp

out, obj = fp.check_args(sys.argv, 'usage: frontend-parser-printers.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
F = fp.ETAGS | fp.NOLIBS
NOLIBS = ['nolibs']
XL = ('struct xin { int a; }; struct xout { int b; }; '
      'translator struct xout < struct xin *p > { b = p->a; };\n')
ROUND = {
    'arith': 'BEGIN { x = 1; trace(x + 2 * 3 - x / 2 % 5); trace(x << 2 | x >> 1 & 7 ^ 9); }',
    'compare': 'BEGIN { x = 1; trace(x < 2 && x >= 0 || x != 3 ^^ x == 4); trace(x <= 9 > 0); }',
    'unary': 'BEGIN { x = 1; trace(-x); trace(+x); trace(~x); trace(!x); trace(x++); trace(x--);'
             ' trace(++x); trace(--x); }',
    'negative': 'BEGIN { trace(-5); trace(-5l); trace(0xffffffffu); trace(1ul); trace(-0x7fffffffffffffff); }',
    'cast': 'BEGIN { trace((char)arg0); trace((unsigned short)arg1); trace((int *)arg0); '
            'trace((userland int *)arg0); trace((string)arg0); }',
    'cond': 'BEGIN { trace(arg0 ? 1 : 2); trace(arg0 ? "a" : "b"); }',
    'strings': 'BEGIN { trace("tab\\there"); trace("quote\\"q"); trace("nl\\n"); trace(""); }',
    'assign': 'BEGIN { x = 1; x += 2; x -= 1; x *= 3; x /= 2; x %= 5; x &= 7; x |= 8; x ^= 1; '
              'x <<= 1; x >>= 1; }',
    'arrays': 'BEGIN { a[1, "k"] = 2; trace(a[1, "k"]); self->t[3] = 4; trace(self->t[3]); '
              'this->l = 5; trace(this->l); }',
    'members': 'struct s { int a; struct s *n; }; BEGIN { this->p = (struct s *)arg0; '
               'trace(this->p->a); trace(this->p->n->a); trace((*this->p).a); }',
    'deref-addr': 'struct s { int a; }; BEGIN { trace(*(int *)arg0); '
                  'trace((uintptr_t)&((struct s *)arg0)->a); }',
    'sizeof': 'BEGIN { x = 1; trace(sizeof (x)); trace(sizeof (int)); trace(stringof(arg0)); }',
    'funcs': 'BEGIN { trace(strlen("abc")); printf("%d %s\\n", 1, "x"); exit(0); }',
    'aggs': 'BEGIN { @a = count(); @b[1, "x"] = sum(2); @c[probefunc] = quantize(3); } '
            'END { printa(@a); trunc(@b, 1); }',
    'pred': 'BEGIN /arg0 > 1 && arg1/ { trace(1); }',
    'multi-pdesc': 'BEGIN, END { trace(1); }',
    'xlate': XL + 'BEGIN { trace(xlate <struct xout> ((struct xin *)arg0).b); '
                  'trace(xlate <struct xout *> ((struct xin *)arg0)->b); }',
    'target': 'othervmx:dtrace:::BEGIN { trace(1); }',
}
SUGARED = {
    'if-else': 'BEGIN { if (arg0 > 1) { trace(1); } else { trace(2); } trace(3); }',
    'if-nested': 'BEGIN { if (arg0) { if (arg1) { trace(1); } } else { trace(2); } }',
    'if-only': 'BEGIN /arg0/ { if (arg1) trace(1); }',
}


def decls(src):
    """The declarations preceding the first clause (not printed by dt_printd)."""
    cut = min(i for i in (src.find('BEGIN'), src.find('othervmx')) if i >= 0)
    return src[:cut]


cases = []
for name, src in list(ROUND.items()) + list(SUGARED.items()):
    cases.append({'id': 'first:' + name, 'src': src, 'flags': F | fp.SUGAR | fp.ZDEFS, 'opts': NOLIBS})
h = fp.Harness(out, obj)
first = h.run(cases)


def norm(stmts):
    """Statements as compared: everything the harness reports about them."""
    return json.dumps(stmts, sort_keys=True)


results, failed = [], []
second_cases = []
for name in ROUND:
    r = first['first:' + name]
    if not r['compiled']:
        failed.append((name, 'original failed: ' + str(r['error'])))
        continue
    second_cases.append({'id': 'second:' + name, 'src': decls(ROUND[name]) + r['output'],
                         'flags': F | fp.ZDEFS, 'opts': NOLIBS})
second = h.run(second_cases)
for name in ROUND:
    r1 = first['first:' + name]
    r2 = second.get('second:' + name)
    if r2 is None:
        continue
    ok = r2['compiled'] and norm(r1['stmts']) == norm(r2['stmts'])
    results.append({'id': name, 'source': ROUND[name], 'printed': r1['output'],
                    'recompiled': r2['compiled'], 'error': r2['error'], 'passed': ok})
    if not ok:
        failed.append((name, f"round trip differs: {r2['error']} :: {r1['output'][:400]!r}"))

# Sugared if/else: dt_sugar.c resets self->%error in dtrace:::ERROR and the
# probe clause, then guards each branch with this->%condition_N clauses.
for name in SUGARED:
    r = first['first:' + name]
    txt = r['output']
    ok = (r['compiled'] and txt.startswith('dtrace:::ERROR') and '(self->%error) = 0x1' in txt
          and '(this->%condition_1) =' in txt and txt.count(':::BEGIN') >= 3)
    results.append({'id': name, 'printed': txt, 'passed': ok})
    if not ok:
        failed.append((name, 'sugar output ' + repr(txt[:300])))

# Tree dumps.
DUMP_SRC = (XL + 'provider pdx { probe ev(int); };\ninline uint64_t il = timestamp;\n'
            'enum ex { EXA = 2 };\n'
            'BEGIN /arg0/ { x = 1; trace(x + 1); trace("s"); this->l = 2; self->t[1] = 3; '
            '@a[1] = count(); trace(arg0 ? 1 : 2); trace((int)arg1); trace(il); trace(-x); '
            'trace(xlate <struct xout> ((struct xin *)arg0).b); a[1, 2] = 4; trace(a[1, 2]); '
            'if (x) { trace(1); } else { trace(2); } }')
# Expected lines (label, operand) with the depth each must appear at, from
# the construction of the tree: CLAUSE > PDESC; D EXPRESSION > FUNC trace >
# OP2 + > VARIABLE x / INT 0x1 ...
EXPECT_PASS2 = [
    r'^CLAUSE attr=', r'^  PDESC :::BEGIN \[0\]', r'^CTXATTR ', r'^  D EXPRESSION attr=',
    r'^    FUNC trace \(type=<void>', r'^      OP2 \+ \(type=<int>', r'^        VARIABLE x \(type=<int>',
    r'^        INT 0x1 \(type=<int>', r'^      STRING "s" \(type=<string>',
    r'^    OP2 = \(', r'^      VARIABLE this->l \(', r'^      VARIABLE self->t \(', r'^      \[',
    r'^    AGGREGATE @a attr=', r'^      OP3 \(type=<int>', r'^      ?\?', r'^        INT 0x2',
    r'^      VARIABLE il \(type=<uint64_t>', r'^      OP1 - \(type=<int>', r'^      OP2 \( \(type=<int>',
    r'^        TYPE \(type=<int>', r'^  PREDICATE /', r'VARIABLE arg0 \(', r'^  /',
    r'^      VARIABLE a \(', r'xlate',
]
P4_SRC = (XL + 'BEGIN /arg0/ { x = 1; trace(x + 1); trace("s"); this->l = 2; self->t[1] = 3; '
          '@a[1] = count(); trace(arg0 ? 1 : 2); trace((int)arg1); trace(-x); '
          'trace(xlate <struct xout> ((struct xin *)arg0).b); a[1, 2] = 4; trace(a[1, 2]); }')
dump_cases = [{'id': 'dump', 'src': DUMP_SRC, 'flags': F, 'opts': ['tree=15'] + NOLIBS},
              {'id': 'dump-pass1', 'src': DUMP_SRC, 'flags': F, 'opts': ['tree=1'] + NOLIBS},
              {'id': 'dump-pass3', 'src': DUMP_SRC, 'flags': F, 'opts': ['tree=4'] + NOLIBS},
              {'id': 'dump-pass4', 'src': P4_SRC, 'flags': F, 'opts': ['tree=8'] + NOLIBS},
              {'id': 'dump-error', 'src': 'BEGIN { trace(1 +); }', 'flags': F, 'opts': ['tree=4'] + NOLIBS},
              {'id': 'dump-cook-error', 'src': 'BEGIN { trace(nosuchvar97); }', 'flags': F,
               'opts': ['tree=4'] + NOLIBS}]
d = h.run(dump_cases)
r = d['dump']
lines = r['output'].splitlines()
missing = [p for p in EXPECT_PASS2 if not any(re.search(p, l) for l in lines)]
dump_ok = r['compiled'] and not missing
results.append({'id': 'tree-dump', 'missing': missing, 'passed': dump_ok})
if not dump_ok:
    failed.append(('tree-dump', f'missing {missing}; error {r["error"]}'))
# Pass 1 (parsed tree) and pass 3 (final root) both start with PROGRAM and
# contain the translator, provider and inline definitions.
for cid in ('dump-pass1', 'dump-pass3'):
    rr = d[cid]
    out_lines = rr['output'].splitlines()
    want = ['PROGRAM attr=', 'XLATOR (', ' from <struct xin *>', ' to <struct xout>', 'MEMBER b',
            'PROVIDER pdx (decl)', 'PROBE ::ev', 'INLINE il (type=<uint64_t>', 'CLAUSE attr=']
    if cid == 'dump-pass1':
        want = ['PROGRAM attr=', 'XLATOR (', 'PROVIDER pdx (decl)', 'PROBE ::ev', 'CLAUSE attr=',
                'IF attr=', 'IF BODY:', 'IF ELSE:', 'IDENT x', 'INT 0x1']
    miss = [w for w in want if w not in rr['output']]
    ok = rr['compiled'] and out_lines and out_lines[0].startswith('PROGRAM') and not miss
    results.append({'id': cid, 'missing': miss, 'passed': bool(ok)})
    if not ok:
        failed.append((cid, f'missing {miss}'))
# Pass 4 prints each clause as D source after sugar: it must recompile.
p4 = d['dump-pass4']
src4 = XL + p4['output']
again = h.run([{'id': 'p4', 'src': src4, 'flags': F | fp.ZDEFS, 'opts': NOLIBS}])['p4']
ok = p4['compiled'] and again['compiled']
results.append({'id': 'dump-pass4', 'passed': ok, 'error': again['error']})
if not ok:
    failed.append(('dump-pass4', f'{again["error"]} :: {p4["output"][:300]!r}'))
# A compile that fails before the final pass prints nothing for pass 3.
e = d['dump-error']
ok = not e['compiled'] and fp.tag(e) == 'D_SYNTAX' and 'PROGRAM' not in e['output']
results.append({'id': 'dump-error', 'passed': ok})
if not ok:
    failed.append(('dump-error', e['output'][:200]))
# A cooking error after parsing still reaches the final pass, which dumps
# the (partially cooked) program root.
e = d['dump-cook-error']
ok = (not e['compiled'] and fp.tag(e) == 'D_IDENT_UNDEF' and e['output'].startswith('PROGRAM')
      and 'IDENT nosuchvar97' in e['output'])
results.append({'id': 'dump-cook-error', 'passed': ok})
if not ok:
    failed.append(('dump-cook-error', e['output'][:300]))
(out / 'results.json').write_text(json.dumps(results, indent=1) + '\n')
h.provenance([__file__], 'dt_printd round trip and dt_node_printr tree dumps; NODEV|NOSYS, nolibs')
for f in failed:
    print('FAIL', *f)
if failed:
    raise SystemExit(f'{len(failed)} printer checks failed')
print('PASS:', len(results), 'printer checks (round trip and tree dumps)')
