#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Scoped symbol references (`sym, mod`sym, ``sym) against modelled modules.

A small C file is compiled with -g, converted to CTF (ctfconvert/ctfmerge)
and linked into LP64 and ILP32 shared objects.  The harness registers them
as loaded modules (frontend-parser.c @elfmod): "fakek" primary kernel,
"fakel" kernel, "fakeu" user, "fake32" a 32-bit kernel module.  Oracles:
symbol sizes from nm -S (sizeof applied to a symbol is its symbol-table size,
dt_node_sizeof); object types from the C declarations (trace size); the D
scoping rules of the Dynamic Tracing Guide (` = kernel, `` = user modules,
mixed use is D_SYM_BADREF); a module of another data model is D_SYM_MODEL;
a symbol without CTF type is D_SYM_NOTYPES unless its address is taken.
"""
from pathlib import Path
import json
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend_parser as fp

out, obj = fp.check_args(sys.argv, 'usage: frontend-parser-symbols.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
SRC = '''struct fs { int a; long b; };
int fake_var = 1;
long fake_long[4];
struct fs fake_struct;
int fake_func(int x) { return x + fake_var; }
static char fake_local[3];
char *fake_ptr = fake_local;
enum fe { FE_A = 3, FE_B = 7, timestamp = 9 };
enum fe fake_enum = FE_B;
struct opaque;
struct opaque *fake_op;
#ifdef __LP64__
__int128 fake_wide;
#endif
'''
(out / 'm.c').write_text(SRC)


def sh(*cmd):
    subprocess.run(cmd, check=True, cwd=out, capture_output=True)


sh('cc', '-g', '-O0', '-fPIC', '-c', '-o', 'm.o', 'm.c')
sh('ctfconvert', '-L', 'fake', 'm.o')
sh('cc', '-shared', '-o', 'm.so', 'm.o')
sh('ctfmerge', '-L', 'fake', '-o', 'm.so', 'm.o')
sh('cc', '-m32', '-g', '-O0', '-fPIC', '-c', '-o', 'm32.o', 'm.c')
sh('ctfconvert', '-L', 'fake', 'm32.o')
sh('ld', '-m', 'elf_i386_fbsd', '-shared', '-o', 'm32.so', 'm32.o')
sh('ctfmerge', '-L', 'fake', '-o', 'm32.so', 'm32.o')
sizes = {}
for line in subprocess.run(['nm', '-S', str(out / 'm.so')], capture_output=True, text=True,
                           check=True).stdout.splitlines():
    f = line.split()
    if len(f) == 4:
        sizes[f[3]] = int(f[1], 16)
MODS = [f'fakek kp {out}/m.so', f'fakel k {out}/m.so', f'fakeu u {out}/m.so',
        f'fake32 k3 {out}/m32.so']
B = 'BEGIN '
F = fp.ETAGS | fp.NOLIBS


def last(r):
    return r['stmts'][-1]['acts'][-1]['difo']


def const(v):
    # SETX, optionally the link-time TYPECAST (84) the front end now emits to
    # give the constant its D type (sizeof is size_t), then RET.
    def check(r):
        ops = [i >> 24 for i in last(r)['insns']]
        return (ops[-2:] == [37, 35] or ops[-3:] == [37, 84, 35]) and \
            int(last(r)['ints'][0]) == v
    return check


K = fp.dif_constants()
CASES = [
    ('kernel-scope', B + '{ trace(fakek`fake_var); }', 'ok', lambda r: last(r)['rsize'] == 4),
    ('kmods-scope', B + '{ trace(`fake_var); }', 'ok', lambda r: last(r)['rsize'] == 4),
    ('loadable-scope', B + '{ trace(fakel`fake_var + 1); }', 'ok', None),
    ('member', B + '{ trace(fakek`fake_struct.b); }', 'ok', lambda r: last(r)['rsize'] == 8),
    ('array-index', B + '{ trace(fakek`fake_long[2]); }', 'ok', lambda r: last(r)['rsize'] == 8),
    ('sizeof-object', B + '{ trace(sizeof (fakek`fake_long)); }', 'ok', const(sizes['fake_long'])),
    ('sizeof-struct', B + '{ trace(sizeof (fakek`fake_struct)); }', 'ok', const(sizes['fake_struct'])),
    ('sizeof-func', B + '{ trace(sizeof (fakek`fake_func)); }', 'ok', const(sizes['fake_func'])),
    ('addr-func', B + '{ trace((uintptr_t)&fakek`fake_func); }', 'ok', None),
    ('deref-ptr', B + '{ trace(*fakek`fake_ptr); }', 'ok', lambda r: last(r)['rsize'] == 1),
    ('user-scope', B + '{ trace(``fake_var); }', 'ok', None),
    ('user-mod-scope', B + '{ trace(fakeu``fake_var); }', 'ok', None),
    ('user-as-kernel', B + '{ trace(fakeu`fake_var); }', ('D_SYM_BADREF', "user module 'fakeu'"), None),
    ('kernel-as-user', B + '{ trace(fakek``fake_var); }', ('D_SYM_BADREF', "kernel module 'fakek'"), None),
    ('model-mismatch', B + '{ trace(fake32`fake_var); }', ('D_SYM_MODEL', 'fake32`fake_var'), None),
    ('no-symbol', B + '{ trace(fakek`no_such_sym97); }', ('D_IDENT_UNDEF', 'fakek`no_such_sym97'), None),
    ('assign-symbol', B + '{ fakek`fake_var = 2; }', ('D_OP_WRITE', None), None),
    ('inline-symbol', 'inline int fv = fakek`fake_var; ' + B + '{ trace(fv); }', 'ok', None),
    ('pragma-module-ctf', '#pragma D depends_on module fakek\n' + B + '{ trace(1); }', 'ok', None),
    ('pragma-module-noctf', '#pragma D depends_on module fake32\n' + B + '{ trace(1); }',
     ('D_PRAGMA_DEPEND', 'module fake32'), None),
    # A module's enum tags are not D identifiers: on the right of a
    # comparison with that enum type they denote the tag's value.
    ('enum-tag-compare', B + '{ trace(fakek`fake_enum == FE_B); }', 'ok', None),
    ('enum-tag-ambiguous', B + '{ trace(fakek`fake_enum != timestamp); }',
     ('D_IDENT_AMBIG', 'timestamp is both a enum fe enum tag'), None),
    # A pointer to a module's forward tag is compatible with a pointer to
    # the D struct of the same name (dt_node_is_ptrcompat forward rule).
    ('forward-ptr-compat', 'struct opaque { int a; }; ' + B +
     '{ trace(fakek`fake_op == (struct opaque *)arg0); }', 'ok', None),
    ('forward-ptr-compat-rev', 'struct opaque { int a; }; ' + B +
     '{ trace((struct opaque *)arg0 != fakek`fake_op); }', 'ok', None),
    ('forward-ptr-cond', 'struct opaque { int a; }; ' + B +
     '{ trace((timestamp ? fakek`fake_op : (struct opaque *)arg0)->a); }', 'ok', None),
    # -> through a pointer to a forward tag finds the definition elsewhere.
    ('forward-ptr-member', 'struct opaque { int a; long b; }; ' + B + '{ trace(fakek`fake_op->b); }', 'ok',
     lambda r: last(r)['rsize'] == 8),
    # Round 4: a function symbol as a cast operand, an associative-array
    # key, and an assignment target; a typedef of a module type; integers
    # wider than 64 bits are not DIF scalars (dt_node_type_assign: BITF).
    ('cast-func-symbol', B + '{ trace((uintptr_t)fakek`fake_func); }', 'ok', None),
    ('key-func-symbol', B + '{ a[fakek`fake_func] = 1; trace(a[fakek`fake_func]); }', 'ok', None),
    # A function symbol's D type is "function pointer" (dtrace_symbol_type).
    ('assign-func-symbol', B + '{ fakek`fake_func = 1; }', ('D_OP_INCOMPAT', '"function pointer" = "int"'), None),
    ('typedef-module-type', 'typedef fakek`struct fs fst97; ' + B + '{ trace(sizeof (fst97)); }', 'ok', const(16)),
    ('wide-int-symbol', B + '{ trace(sizeof (fakek`fake_wide)); }', ('D_SIZEOF_BITFIELD', None), None),
    ('tree-symbol', B + '{ trace(fakek`fake_var); }', 'ok',
     lambda r: 'SYMBOL fakek`fake_var' in r['output'] or 'SYMBOL m.so`fake_var' in r['output']),
    ('scoped-type', B + '{ trace(sizeof (fakek`struct fs)); }', 'ok', const(16)),
    # '[' after a name in a clause makes it an identifier (D lexer rule), so
    # the array type is written behind a pointer declarator.
    ('scoped-type-array', B + '{ trace(sizeof (fakek`struct fs *[3])); }', 'ok', const(24)),
    ('scoped-type-cast', B + '{ trace(((fakek`struct fs *)arg0)->b); }', 'ok',
     lambda r: last(r)['rsize'] == 8),
]
ATTR = [('attr-min-symbol', B + '{ trace(fakek`fake_var); }', ('D_ATTR_MIN', 'symbol fakek`fake_var'))]
h = fp.Harness(out, obj)
# User symbols stay unresolved (relocated at run time): DTRACE_C_UNODEF.
res = h.run([{'id': c[0], 'src': c[1], 'flags': F | (fp.UNODEF if 'user' in c[0] else 0),
              'elfmods': MODS, 'opts': ['tree=2'] if c[0].startswith('tree-') else []} for c in CASES])
# An array of a module's type is created in the D container from a copy of
# the element type (dt_decl_type copies types from other containers).
TYPES = [('array-of-module-type', 'struct sm97 { fakek`struct fs a[3]; }; ' + B + '{ trace(sizeof (struct sm97)); }', 48)]
tres = h.run([{'id': t[0], 'src': t[1], 'flags': F, 'elfmods': MODS} for t in TYPES])
for tid, tsrc, tsize in TYPES:
    res[tid] = tres[tid]
    CASES.append((tid, tsrc, 'ok', const(tsize)))
res.update(h.run([{'id': c[0], 'src': c[1], 'flags': F | fp.EATTR, 'elfmods': MODS,
                    'opts': ['amin=Unstable/Unstable/Common', 'nolibs']} for c in ATTR]))
CASES += [(c[0], c[1], c[2], None) for c in ATTR]
results, failed = [], []
for cid, src, exp, check in CASES:
    r = res[cid]
    if exp == 'ok':
        ok = r['compiled'] and (check is None or check(r))
    else:
        tag, sub = exp
        ok = not r['compiled'] and (tag == '*' or fp.tag(r) == tag) and (sub is None or sub in r['error'])
    results.append({'id': cid, 'src': src, 'error': r.get('error'), 'passed': bool(ok)})
    if not ok:
        failed.append((cid, r.get('error')))
(out / 'results.json').write_text(json.dumps({'nm_sizes': sizes, 'cases': results}, indent=1) + '\n')
h.provenance([__file__], 'scoped symbols against CTF-bearing modelled modules; NODEV|NOSYS')
for f in failed:
    print('FAIL', *f)
if failed:
    raise SystemExit(f'{len(failed)} of {len(results)} symbol cases failed')
print('PASS:', len(results), 'scoped symbol cases')
