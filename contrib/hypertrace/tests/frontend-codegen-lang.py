#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""D language code generation checked by execution.

Each case is a D program compiled offline (frontend-codegen.c, NOSYS
dtrace_vopen model with typed probes) whose statements are executed in
order, as an ECB executes its actions, by the independent DIF interpreter
in frontend_codegen_common.py.  Predicates gate their statement.  The values
returned by every action DIFO (trace arguments, printf arguments,
aggregation keys, values and variable ids) are compared with values derived
by hand from the D language semantics (Dynamic Tracing Guide: variables and
scopes, compound assignment, ++/--, short-circuit && || ^^, pointer
arithmetic scaled by the referenced type, bit-fields, inlines, translators,
associative arrays, strings and the documented subroutines).  Bit-field and
structure layouts are cross-checked against the C compiler.
"""
import json
import struct
import subprocess
import sys
from pathlib import Path
from frontend_codegen_common import (check_args, build, compile_cases, finish,
                                     Machine, run_difo, retval, DIFError, M64,
                                     disasm)

out, obj = check_args(sys.argv, 'world')
exe = build(out, obj)

ENV = {'args': [5, 7, -3 & M64, 0x1234], 'probefunc': 'fn', 'probename': 'nm',
       'probemod': 'mod', 'probeprov': 'prov', 'execname': 'cmd', 'pid': 42,
       'tid': 43, 'ppid': 1, 'uid': 1001, 'gid': 5, 'timestamp': 1000,
       'walltimestamp': 2000, 'epid': 9, 'id': 4, 'curthread': 0xdead0000,
       'errno': 0, 'regs': [11, 12, 13], 'uregs': [21, 22, 23]}

# ---- Structure layouts -----------------------------------------------------
# Types declared in D are laid out by libctf (ctf_add_member): each member
# starts at the next byte boundary after the previous member's end, rounded
# up to the new member's alignment, bit-fields included (no bit packing), and
# the structure size is the end of its last member (no tail padding).  Member
# offsets of the ordinary structure are cross-checked with the C compiler,
# which agrees for every member; only the tail padding differs.
csrc = r'''
#include <stddef.h>
#include <stdio.h>
struct kst { char c; short s; int i; long l; unsigned char uc; };
int main(void) {
	printf("%zu %zu %zu %zu %zu\n", offsetof(struct kst, c), offsetof(struct kst, s),
	    offsetof(struct kst, i), offsetof(struct kst, l), offsetof(struct kst, uc));
	return 0;
}
'''
(out / 'layout.c').write_text(csrc)
subprocess.run(['cc', '-o', str(out / 'layout'), str(out / 'layout.c')], check=True)
offs = list(map(int, subprocess.run([str(out / 'layout')], capture_output=True, text=True,
                                    check=True).stdout.split()))
assert offs == [0, 2, 4, 8, 16], offs
KST_SIZE = offs[-1] + 1
kdata = bytearray(KST_SIZE)
struct.pack_into('<b', kdata, offs[0], -5)
struct.pack_into('<h', kdata, offs[1], -300)
struct.pack_into('<i', kdata, offs[2], -70000)
struct.pack_into('<q', kdata, offs[3], -1)
struct.pack_into('<B', kdata, offs[4], 200)
layout = {'kst': bytes(kdata)}
# struct bf { unsigned a : 3; int b : 5; unsigned c : 12; int d : 4; } in D:
# a at byte 0 (1-byte unit), b at byte 1, c at byte 2 (2-byte unit), d at
# byte 4; size 5.  a = 5, b = -7, c = 0xabc, d = -3.
layout['bf'] = bytes([5, (-7) & 0x1f, 0xbc, 0x0a, (-3) & 0xf])


def kst(m):
    return m.kobj(layout['kst'])


def bf(m):
    return m.kobj(layout['bf'])


def kstr(s):
    return lambda m: m.kobj(s.encode() + b'\0' * (m.strsize - len(s)))


def xin(m):
    s = m.kobj(b'str' + b'\0' * 253)
    return m.kobj(struct.pack('<i4xQ', 21, s))


def xin2(m):
    s = m.kobj(b'str' + b'\0' * 253)
    return m.kobj(struct.pack('<i4xQii', 21, s, 7, -8))


# struct xw under the libctf layout rule: c@0 (1), h@2 (2), i@4 (4), t@8
# (string, 256 bytes), arr@264 (2 x int), untr@272 (long); size 280.  The
# untranslated member is not compared (scratch memory is not zeroed).
class Bytes:
    def __init__(self, fields):
        self.fields = fields   # [(offset, bytes)]


XW_EXPECTED = Bytes([(0, struct.pack('<b', 21)), (2, struct.pack('<h', 42)),
                     (4, struct.pack('<i', 63)), (8, b'str' + b'\0' * 253),
                     (264, struct.pack('<ii', 7, -8))])
# struct xout: b@0 (int), c@8 (long); size 16.
XOUT_EXPECTED = Bytes([(0, struct.pack('<i', 42)), (8, struct.pack('<q', 5))])

NONZERO = object()
CASES = [
    ('vars-compound', 'BEGIN { self->x = 3; this->y = 4; trace(self->x + this->y); '
     'g = 10; g += 5; trace(g); g -= 3; trace(g); g *= 2; trace(g); g /= 5; trace(g); '
     'g %= 3; trace(g); g <<= 4; trace(g); g >>= 1; trace(g); g |= 1; trace(g); '
     'g &= 0x7; trace(g); g ^= 0xf; trace(g); }', {},
     [7, 15, 12, 24, 4, 1, 16, 8, 9, 1, 14]),
    ('incdec-vars', 'BEGIN { i = 5; trace(i++); trace(i); trace(++i); trace(i--); '
     'trace(--i); trace(i); self->t = 1; trace(self->t++); trace(++self->t); '
     'this->l = 10; trace(this->l--); trace(--this->l); }', {},
     [5, 6, 7, 7, 5, 5, 1, 3, 10, 8]),
    ('incdec-memory', 'struct s { int a; long b; }; struct s g; BEGIN { g.a = 1; '
     'trace(g.a++); trace(++g.a); trace(g.a--); trace(--g.a); g.b = 100; g.b += 23; '
     'trace(g.b); g.b <<= 2; trace(g.b); }', {}, [1, 3, 3, 1, 123, 492]),
    ('pointer-arith', 'struct s { int a; long b; }; struct s g; BEGIN { '
     'this->p = &g.a; this->q = this->p; this->p++; '
     'trace((long)this->p - (long)this->q); ++this->p; trace(this->p - this->q); '
     'this->p--; trace(this->p - this->q); trace((long)(this->p + 3) - (long)this->q); '
     'this->lp = &g.b; trace((long)(this->lp + 2) - (long)this->lp); '
     'trace((long)(2 + this->lp) - (long)this->lp); }', {}, [4, 2, 1, 16, 16, 16]),
    ('string-compare', 'BEGIN { s = "abc"; t = "abd"; trace(s < t); trace(s == t); '
     'trace(s != t); trace(s >= "abc"); trace(s > t); trace(s <= t); '
     'trace(s == "abc" ? "yes" : "no"); }', {}, [1, 0, 1, 1, 0, 1, 'yes']),
    ('subroutines', 'BEGIN { trace(strlen("hello")); trace(strjoin("ab", "cd")); '
     'trace(substr("hello", 1, 3)); trace(substr("hello", -2)); trace(index("hello", "l")); '
     'trace(rindex("hello", "l")); trace(strchr("hello", \'l\')); trace(strrchr("hello", \'l\')); '
     'trace(strstr("hello", "ll")); trace(toupper("abC")); trace(tolower("ABc")); '
     'trace(lltostr(-42)); trace(htons(0x1234)); trace(htonl(0x12345678)); '
     'trace(htonll(0x0102030405060708)); trace(ntohs(0x3412)); }', {},
     [5, 'abcd', 'ell', 'lo', 2, 3, 'llo', 'lo', 'llo', 'ABC', 'abc', '-42', 0x3412,
      0x78563412, 0x0807060504030201, 0x1234]),
    ('logical-shortcircuit', 'BEGIN { x = 0; y = (arg0 > 3 || (x = 1)); trace(x); '
     'trace(y); z = (arg0 < 3 && (x = 2)); trace(x); trace(z); trace(arg0 ^^ arg1); '
     'trace(arg0 ^^ 0); trace(!arg0); trace(arg0 ? arg1 : arg2); '
     'w = (arg0 < 3 || (x = 3)); trace(x); trace(w); v = (arg0 > 3 && arg1 > 6); '
     'trace(v); trace(0 ^^ arg2); }', {}, [0, 1, 0, 0, 0, 1, 0, 7, 3, 1, 1, 1]),
    ('kernel-struct', 'struct kst { char c; short s; int i; long l; unsigned char uc; }; '
     'BEGIN { this->k = (struct kst *)arg0; trace(this->k->c); trace(this->k->s); '
     'trace(this->k->i); trace(this->k->l); trace(this->k->uc); '
     'trace(*(int *)(arg0 + 4)); trace(((char *)arg0)[2]); '
     'trace(((unsigned char *)arg0)[0]); trace(&this->k->l - &this->k->l); '
     'trace((char *)&this->k->uc - (char *)this->k); trace((*this->k).s); '
     'trace(sizeof (*this->k)); }', {'args': [kst]},
     [-5, -300, -70000, -1, 200, -70000, -44, 251, 0, 16, -300, KST_SIZE]),
    ('userland-load', 'struct kst { char c; short s; int i; long l; unsigned char uc; }; '
     'BEGIN { this->u = (userland struct kst *)arg0; trace(this->u->s); '
     'trace(this->u->uc); trace(*(userland int *)(arg0 + 4)); '
     'trace(*(int *)copyin(arg0 + 4, 4)); }', {'args': [kst]},
     [-300, 200, -70000, -70000]),
    ('bitfield-read', 'struct bf { unsigned a : 3; int b : 5; unsigned c : 12; int d : 4; }; '
     'BEGIN { this->p = (struct bf *)arg0; trace(this->p->a); trace(this->p->b); '
     'trace(this->p->c); trace(this->p->d); }', {'args': [bf]}, [5, -7, 0xabc, -3]),
    ('bitfield-write', 'struct s2 { int a : 3; unsigned b : 5; short c; }; struct s2 g; '
     'BEGIN { g.a = -2; g.b = 9; g.c = 7; trace(g.a); trace(g.b); trace(g.c); g.b = 40; '
     'trace(g.b); trace(g.a); }', {}, [-2, 9, 7, 8, -2]),
    ('inlines', 'inline int K = 3; inline string S = "xy"; inline int sq[int x] = x * x; '
     'inline int add[int a, int b] = a + b; inline unsigned char UC = arg0 + 0x1fa; '
     'BEGIN { trace(K + 1); trace(S); trace(sq[arg0]); trace(add[arg0, arg1]); '
     'trace(sq[add[1, 2]]); trace(UC); }', {}, [4, 'xy', 25, 12, 9, 0xff]),
    ('sizeof-stringof-comma', 'BEGIN { trace(sizeof (arg0)); trace(sizeof ((char)arg0)); '
     'trace(stringof((char *)arg3)); trace((arg0, arg1)); trace(+arg2); '
     'trace(stringof(probefunc)); }', {'args': [5, 7, -3 & M64, kstr('kstr')]},
     [8, 1, 'kstr', 7, -3, 'fn']),
    ('builtins', 'BEGIN { trace(probefunc); trace(probename); trace(probemod); '
     'trace(probeprov); trace(execname); trace(pid); trace(tid); trace(ppid); '
     'trace(uid); trace(gid); trace(timestamp); trace(walltimestamp); trace(epid); '
     'trace(id); trace(curthread); trace(arg1); trace(arg9); trace(regs[1]); '
     'trace(uregs[2]); }', {},
     ['fn', 'nm', 'mod', 'prov', 'cmd', 42, 43, 1, 1001, 5, 1000, 2000, 9, 4,
      0xdead0000, 7, 0, 12, 23]),
    ('typed-args', 'typed:kernel:fn:t { trace(args[0]); trace(args[2]); trace(args[3]); '
     'trace(stringof(args[1])); trace(args[0] < 0); }',
     {'args': [-2 & M64, kstr('hello'), 0x1ff, 0x18000]}, [-2, 0xff, -32768, 'hello', 1]),
    ('translators', 'struct xin { int a; char *s; }; struct xout { int b; string t; long c; }; '
     'translator struct xout < struct xin *p > { b = p->a * 2; t = stringof(p->s); c = 7; }; '
     'BEGIN { trace(xlate <struct xout> ((struct xin *)arg0).b); '
     'trace(xlate <struct xout> ((struct xin *)arg0).t); '
     'trace(xlate <struct xout *> ((struct xin *)arg0)->c); }', {'args': [xin]},
     [42, 'str', 7]),
    ('translator-assign', 'struct xin { int a; char *s; }; struct xout { int b; long c; }; '
     'translator struct xout < struct xin *p > { b = p->a + 1; c = p->a * 3; }; '
     'struct xout go; BEGIN { go = xlate <struct xout> ((struct xin *)arg0); '
     'trace(go.b); trace(go.c); }', {'args': [xin]}, [22, 63]),
    ('assoc-byref', 'struct pt { int x; int y; }; struct pt pa[int]; BEGIN { '
     'pa[1].x = 3; pa[1].y = 4; trace(pa[1].x + pa[1].y); self->sa["k"] = "v"; '
     'trace(self->sa["k"]); self->n[arg0, "z"] = 9; trace(self->n[5, "z"]); '
     'trace(self->n[6, "z"]); }', {}, [7, 'v', 9, 0]),
    ('predicates', 'BEGIN /arg0 > 3/ { trace(1); } BEGIN /arg0 > 10/ { trace(2); } '
     'BEGIN /probefunc == "fn"/ { trace(3); } BEGIN /!(arg1 & 1)/ { trace(4); }', {},
     [1, 3]),
    ('global-array', 'int ga[5]; BEGIN { ga[2] = 9; ga[arg0 - 4] = 3; '
     'trace(ga[2] + ga[1]); trace(ga[0]); }', {}, [12, 0]),
    ('local-strings', 'BEGIN { this->s = strjoin("a", "b"); trace(this->s); '
     'self->s = "zz"; trace(self->s); gs = this->s; trace(strlen(gs)); }', {},
     ['ab', 'zz', 2]),
    ('speculation', 'BEGIN { self->spec = speculation(); trace(self->spec != 0); }', {},
     [1]),
    ('aggregations', 'BEGIN { @a[1, "x"] = sum(arg0 * 2); @b = lquantize(arg1, 0, 10, 2); '
     '@c[probefunc] = count(); @d = max(arg2); @e[arg0] = avg(arg1); '
     '@f[strlen(probefunc)] = count(); }', {},
     [1, 'x', 10, 7, 'fn', -3, 5, 7, 2]),
    ('bitfield-store-ptr', 'struct s2 { int x; int a : 3; unsigned b : 5; }; struct s2 g; '
     'BEGIN { this->p = (struct s2 *)&g.x; this->p->b = 21; this->p->a = 3; trace(g.b); trace(g.a); '
     'trace(this->p->b); }', {}, [21, 3, 21]),
    ('struct-member-copy', 'struct s { int a; long b; }; struct o { struct s in; int z; }; '
     'struct s gb; struct o go; BEGIN { gb.a = 3; gb.b = 9; go.in = gb; go.z = 1; '
     'trace(go.in.a); trace(go.in.b); trace(go.z); }', {}, [3, 9, 1]),
    ('pointer-compare', 'struct s { int a; long b; }; struct s g; BEGIN { this->p = &g.a; '
     'this->q = (int *)&g.b; trace(this->p < this->q); trace(this->p == this->p); '
     'trace(this->q <= this->p); }', {}, [1, 1, 0]),
    ('translator-whole', 'struct xin2 { int a; char *s; int arr[2]; }; '
     'struct xw { char c; short h; int i; string t; int arr[2]; long untr; }; '
     'translator struct xw < struct xin2 *p > { c = (char)p->a; h = (short)(p->a * 2); i = p->a * 3; '
     't = stringof(p->s); arr = p->arr; }; '
     'BEGIN { trace(xlate <struct xw> ((struct xin2 *)arg0)); }', {'args': [xin2]},
     [XW_EXPECTED]),
    ('typed-translated', 'struct xin { int a; char *s; }; struct xout { int b; long c; }; '
     'translator struct xout < struct xin *p > { b = p->a * 2; c = 5; }; '
     'typed:kernel:fn:t { trace(args[4].b); trace(args[5]->c); trace(*args[5]); }',
     {'args': [0, 0, 0, 0, xin]}, [42, 5, XOUT_EXPECTED]),
    # An inline whose value is a variable names that variable: assignments
    # and increments through it update the variable (dt_ident_resolve()).
    ('inline-alias', 'int gv; inline int K = gv; inline int L = K; BEGIN { K = 3; '
     'trace(gv); K++; trace(gv); ++L; trace(K); trace(L + 1); }', {}, [3, 4, 5, 6]),
    # Regression: an inline array used inside its own (or another inline
    # array's) argument rebinds the parameters; the outer binding must be
    # restored (crash / wrong register before).  f(x) = x + 1, g(y) = 2 f(y).
    ('inline-nested', 'inline int f[int x] = x + 1; inline int g[int y] = f[y] * 2; '
     'BEGIN { trace(f[g[arg1]]); trace(f[f[arg0]]); trace(g[f[g[arg0]]]); '
     'trace(f[arg0] + f[arg1]); }', {}, [17, 7, 2 * (2 * 6 + 1 + 1), 14]),
    # Compound assignment on an unsigned int: unsigned division, remainder
    # and logical shift.  (unsigned int)-3 = 4294967293; / 2 = 2147483646;
    # % 1000 = 646; >> 1 = 323.
    ('compound-unsigned', 'BEGIN { self->u = (unsigned int)arg2; self->u /= 2; trace(self->u); '
     'self->u %= 1000; trace(self->u); self->u >>= 1; trace(self->u); }', {},
     [2147483646, 646, 323]),
    ('printf-args', 'BEGIN { printf("%d %s %c\\n", arg0, "q", \'z\'); }', {},
     [5, 'q', ord('z')]),
]

cases = [{'name': n, 'prog': p} for n, p, _, _ in CASES]
got = compile_cases(exe, obj, out, cases)


def expect_ok(exp, val, d):
    if exp is NONZERO:
        return val not in (0, None)
    if isinstance(exp, Bytes):
        return isinstance(val, bytes) and all(val[o:o + len(b)] == b for o, b in exp.fields)
    if isinstance(exp, str):
        return val == exp
    if isinstance(val, int):
        size = d['rtype'][3] or 8
        mask = (1 << 8 * min(size, 8)) - 1
        return (val & mask) == (exp & mask)
    return False


results = []
for name, prog, env, expected in CASES:
    g = got[name]
    if 'error' in g:
        results.append({'case': name, 'error': g['error'], 'passed': False})
        continue
    m = Machine(dict(ENV))
    m.env.update({k: v for k, v in env.items() if k != 'args'})
    if 'args' in env:
        m.env['args'] = [a(m) if callable(a) else a for a in env['args']]
    values, note = [], None
    try:
        for st in g['stmts']:
            if st['pred'] is not None and run_difo(m, st['pred']) == 0:
                continue
            for a in st['actions']:
                d = a['difo']
                if d is None or (a['kind'] == 1 and not a['return']):
                    if d is not None:
                        run_difo(m, d)
                    continue
                values.append((retval(m, d, run_difo(m, d)), d))
    except DIFError as err:
        note = str(err)
    ok = note is None and len(values) == len(expected) and all(
        expect_ok(e, v, d) for e, (v, d) in zip(expected, values))
    results.append({'case': name, 'expected': [e if not isinstance(e, (Bytes, object.__class__))
                                               and e is not NONZERO else str(e)
                                               for e in expected],
                    'got': [v if not isinstance(v, bytes) else v.hex() for v, _ in values],
                    'note': note, 'passed': ok})

finish(out, results, [Path(__file__), Path(__file__).with_name('frontend-codegen.c'),
                      Path(__file__).with_name('frontend_codegen_common.py'),
                      obj / 'cddl/lib/libdtrace/libdtrace.so.2'],
       'D language constructs: libdtrace DIF executed by an independent interpreter, '
       'hand-derived expectations, C layout oracle; NOSYS dtrace_vopen model',
       'D code generation execution cases')
