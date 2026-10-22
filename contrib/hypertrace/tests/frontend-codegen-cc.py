#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compiler driver (dt_cc.c), assembler (dt_as.c) and register allocator
(dt_regset.c) behaviour, offline.

Programs are compiled by frontend-codegen.c (NOSYS dtrace_vopen model;
optional offline symbol modules backed by a small ELF object).  Expected
values are derived from the public definitions and documented behaviour:
action kinds and argument encodings from sys/dtrace.h (DTRACEACT_*,
DTRACE_USTACK_ARG, DTRACE_LQUANTIZE_*/DTRACE_LLQUANTIZE_* shifts) and the
DT_ACT_* numbering in dt_impl.h; stack-frame defaults from the documented
options; relocation policy from the link-mode table documented in dt_as()
(kernel: kernel static, user dynamic; primary: primary-kernel static;
dynamic: all relocated; static: none) with symbol addresses taken from nm(1);
the CTF cache file header from ctf.h (CTF_MAGIC); cpp(1) handling from
dt_preproc() (#! line skipped; exit status 126/127/other mapped to
EDT_CPPEXEC/EDT_CPPENT/EDT_CPPERR); D library dependency rules from the
Dynamic Tracing Guide (depends_on, cycles rejected); diagnostics by tag.
DIF results are executed with the interpreter in frontend_codegen_common.py.
"""
import os
import struct
import sys
from pathlib import Path
from frontend_codegen_common import (check_args, build, build_fakemod, compile_cases,
                                     finish, Machine, run_difo, retval, disasm, ACT, AGG,
                                     OP, M64)

out, obj = check_args(sys.argv, 'world')
exe = build(out, obj)
syms = build_fakemod(out)
ETAGS = 0x100
DT_ACT_BASE = 55 + 1          # DIF_SUBR_MAX + 1
DT_ACT_FTRUNCATE = DT_ACT_BASE + 21
DT_ACT_CLEAR, DT_ACT_NORMALIZE, DT_ACT_DENORMALIZE, DT_ACT_TRUNC = (
    DT_ACT_BASE + 15, DT_ACT_BASE + 16, DT_ACT_BASE + 17, DT_ACT_BASE + 18)
DT_ACT_SETOPT = DT_ACT_BASE + 28


def ustack_arg(nframes, strsize):
    return (strsize << 32) | (nframes & 0xffffffff)


def acts(g):
    return [a for st in g.get('stmts', []) for a in st['actions']]


def kinds(g):
    return [a['kind'] for a in acts(g)]


def val(a, env=None):
    m = Machine(env or {'args': [5, 7, 0, 0]})
    return retval(m, a['difo'], run_difo(m, a['difo']))


def tagged(tag):
    return lambda g: g.get('error', '').startswith(f'[{tag}]')


def ok(g):
    return 'stmts' in g


# ---- library directories ----------------------------------------------------
libs = out / 'libs'
for d in ('good', 'cyc', 'bad', 'syntax', 'empty', 'dup1', 'dup2', 'unread', 'notlib', 'xlver',
          'inl', 'malformed'):
    (libs / d).mkdir(parents=True)
(libs / 'good/a.d').write_text('#pragma D depends_on library b.d\ninline int LIBA = LIBB + 1;\n')
(libs / 'good/b.d').write_text('inline int LIBB = 40;\n')
(libs / 'good/notes.txt').write_text('not a D library\n')
(libs / 'cyc/c.d').write_text('#pragma D depends_on library d.d\ninline int C = 1;\n')
(libs / 'cyc/d.d').write_text('#pragma D depends_on library c.d\ninline int D = 2;\n')
(libs / 'bad/e.d').write_text('#pragma D depends_on library nonexistent_lib.d\ninline int E = 3;\n')
(libs / 'notlib/i.d').write_text('#pragma D depends_on library notes.txt\ninline int I = 1;\n')
(libs / 'notlib/notes.txt').write_text('not a D library\n')
(libs / 'good/README').write_text('no extension\n')
(libs / 'xlver/v.d').write_text(
    'struct vin { int a; }; struct vout { int b; }; struct vout2 { int c; }; struct vout3 { int d; };\n'
    '#pragma D binding "1.0" translator\n'
    'translator struct vout3 < struct vin *p > { d = p->a; };\n'
    '#pragma D binding "1.10" translator\n'
    'translator struct vout < struct vin *p > { b = p->a; };\n'
    'translator struct vout2 < struct vin *p > { c = p->a + 1; };\n')
(libs / 'inl/i.d').write_text('inline int f[int x] = x + 1;\ninline int g[int y] = f[y] * 2;\n')
(libs / 'malformed/m.d').write_text('#pragma D depends_on library\ninline int M = 1;\n')
(libs / 'syntax/f.d').write_text('inline int F = ;\n')
(libs / 'dup1/g.d').write_text('inline int G1 = 7;\n')
(libs / 'dup2/g.d').write_text('inline int G2 = 8;\n')
(libs / 'unread/h.d').write_text('inline int H = 9;\n')
(libs / 'unread/h.d').chmod(0)
LIBS = ['libs', 'syslibdir=' + str(libs / 'empty')]

ctypes = out / 'ctypes.ctf'
dtypes = out / 'dtypes.ctf'
X = ('struct xin { int a; char *s; }; struct xout { int b; long c; }; '
     'translator struct xout < struct xin *p > { b = p->a * 2; c = 5; }; ')
N = 'struct nosuch_xlate { int q; long r; }; '


FILL_NAMES = [f't{i:04d}' + 'z' * 100 for i in range(570)]
FILL_DECLS = ''.join(f'struct {n} {{ int a; }}; ' for n in FILL_NAMES)
FILL_SUM = '(' + ' + '.join(f'(long)(struct {n} *)arg0' for n in FILL_NAMES) + ')'


def balanced(terms, op='||'):
    """A balanced expression tree, so code generation depth stays small."""
    if len(terms) == 1:
        return f'({terms[0]})'
    mid = len(terms) // 2
    return f'({balanced(terms[:mid], op)} {op} {balanced(terms[mid:], op)})'


def reloc(g, i, ktab, utab, name):
    """Action i has exactly the given kernel/user relocation counts, each a
    DOF_RELO_SETX (1) against string 'name' at the offset of its SETX's
    integer-table slot, and SETX's integer is the nm(1) address."""
    a = acts(g)[i]['difo']
    rels = a['krel'] + a['urel']
    if len(a['krel']) != ktab or len(a['urel']) != utab:
        return False
    strtab = a['str'].encode('latin-1')
    setx = [ins for ins in a['buf'] if ins >> 24 == OP['SETX']]
    for r in rels:
        nm = strtab[r[0]:].split(b'\0')[0].decode()
        if nm != name or r[1] != 1 or r[2] != ((setx[0] >> 8) & 0xffff) * 8:
            return False
    return int(a['int'][(setx[0] >> 8) & 0xffff]) == syms[name][0]


CASES = [
    # --- actions -----------------------------------------------------------
    ('act-destructive', 0, [], 'BEGIN { breakpoint(); panic(); stop(); }',
     lambda g: kinds(g) == [ACT['BREAKPOINT'], ACT['PANIC'], ACT['STOP']]),
    ('act-raise-chill-exit', 0, [], 'BEGIN { raise(9); chill(100); exit(3); }',
     lambda g: kinds(g) == [ACT['RAISE'], ACT['CHILL'], ACT['EXIT']] and
     [val(a) & 0xffffffff for a in acts(g)] == [9, 100, 3]),
    ('act-system', 0, [], 'BEGIN { system("echo %d %s", 3, "x"); }',
     lambda g: kinds(g) == [ACT['SYSTEM']] * 2 and [val(a) for a in acts(g)] == [3, 'x']),
    ('act-freopen', 0, [], 'BEGIN { freopen("/tmp/out.%d", 1); freopen(""); }',
     lambda g: kinds(g) == [ACT['FREOPEN']] * 2 and val(acts(g)[0]) == 1 and
     disasm(acts(g)[1]['difo']) == [('RET', 0, 0, 0)]),
    ('act-freopen-sentinel', ETAGS, [], 'BEGIN { freopen("."); }',
     tagged('D_FREOPEN_INVALID')),
    ('act-ftruncate', 0, [], 'BEGIN { ftruncate(); }',
     lambda g: kinds(g) == [ACT['LIBACT']] and acts(g)[0]['arg'] == str(DT_ACT_FTRUNCATE)),
    ('act-speculation', 0, [], 'BEGIN { self->s = speculation(); } '
     'BEGIN { speculate(self->s); trace(1); } END { commit(self->s); } '
     'END { discard(self->s); }',
     lambda g: kinds(g) == [ACT['DIFEXPR'], ACT['SPECULATE'], ACT['DIFEXPR'],
                            ACT['COMMIT'], ACT['DISCARD']]),
    ('act-jstack-default', 0, [], 'BEGIN { jstack(); }',
     lambda g: kinds(g) == [ACT['JSTACK']] and acts(g)[0]['arg'] == '0'),
    ('act-jstack-options', 0, ['jstackframes=7', 'jstackstrsize=300'], 'BEGIN { jstack(); }',
     lambda g: acts(g)[0]['arg'] == str(ustack_arg(7, 300))),
    ('act-jstack-args', 0, ['jstackframes=7'], 'BEGIN { jstack(3, 100); }',
     lambda g: acts(g)[0]['arg'] == str(ustack_arg(3, 100))),
    ('act-ustack-options', 0, ['ustackframes=9'], 'BEGIN { ustack(); ustack(4, 64); }',
     lambda g: kinds(g) == [ACT['USTACK']] * 2 and
     [a['arg'] for a in acts(g)] == [str(ustack_arg(9, 0)), str(ustack_arg(4, 64))]),
    ('act-stack-options', 0, ['stackframes=11'], 'BEGIN { stack(); stack(5); immstack(); }',
     lambda g: kinds(g) == [ACT['STACK'], ACT['STACK'], ACT['IMMSTACK']] and
     [a['arg'] for a in acts(g)][:2] == ['11', '5']),
    ('agg-key-actions', 0, ['ustackframes=6'],
     'BEGIN { @a[ustack(5)] = count(); @b[usym(arg0)] = count(); @c[uaddr(arg0)] = count(); '
     '@d[umod(arg0)] = count(); @e[stack()] = count(); @f[sym(arg0)] = count(); '
     '@g[mod(arg0)] = count(); @h[jstack()] = count(); @i[ufunc(arg0)] = count(); '
     '@j[func(arg0)] = count(); @k[ustack()] = count(); }',
     lambda g: [a['kind'] for a in acts(g) if a['kind'] not in
                (ACT['DIFEXPR'], AGG['COUNT'])] ==
     [ACT['USTACK'], ACT['USYM'], ACT['UADDR'], ACT['UMOD'], ACT['STACK'], ACT['SYM'],
      ACT['MOD'], ACT['JSTACK'], ACT['USYM'], ACT['SYM'], ACT['USTACK']] and
     [a['arg'] for a in acts(g) if a['kind'] == ACT['USTACK']] ==
     [str(ustack_arg(5, 0)), str(ustack_arg(6, 0))]),
    ('agg-encodings', 0, [],
     'BEGIN { @a = llquantize(arg0, 10, 0, 6, 20); @b = lquantize(arg0, -10, 10, 5); '
     '@c = lquantize(arg0, 0, 10, 1, arg1); @d = quantize(arg0, 3); '
     '@e = llquantize(arg0, 10, 0, 6, 20, arg1); }',
     lambda g: [a['arg'] for a in acts(g) if a['kind'] in (AGG['LQUANTIZE'], AGG['LLQUANTIZE'])]
     == [str((10 << 48) | (0 << 32) | (6 << 16) | 20),
         str((5 << 48) | (4 << 32) | ((-10) & 0xffffffff)),
         str((1 << 48) | (10 << 32)), str((10 << 48) | (6 << 16) | 20)] and
     len([a for a in acts(g) if a['kind'] == ACT['DIFEXPR']]) >= 3),
    ('agg-llquantize-match', ETAGS, [],
     'BEGIN { @a = llquantize(arg0, 10, 0, 6, 20); @a = llquantize(arg0, 10, 0, 6, 10); }',
     tagged('D_LLQUANT_NSTEPMATCH')),
    ('agg-llquantize-factor', ETAGS, [],
     'BEGIN { @a = llquantize(arg0, 10, 0, 6, 20); @a = llquantize(arg0, 20, 0, 6, 20); }',
     tagged('D_LLQUANT_FACTORMATCH')),
    ('agg-llquantize-low', ETAGS, [],
     'BEGIN { @a = llquantize(arg0, 10, 0, 6, 20); @a = llquantize(arg0, 10, 1, 6, 20); }',
     tagged('D_LLQUANT_LOWMATCH')),
    ('agg-llquantize-high', ETAGS, [],
     'BEGIN { @a = llquantize(arg0, 10, 0, 6, 20); @a = llquantize(arg0, 10, 0, 7, 20); }',
     tagged('D_LLQUANT_HIGHMATCH')),
    ('agg-quantize-len', ETAGS, [], 'BEGIN { @a = quantize(arg0, 1, 2); }',
     tagged('D_PROTO_LEN')),
    ('agg-lquantize-len', ETAGS, [], 'BEGIN { @a = lquantize(arg0, 0, 10, 1, 1, 2); }',
     tagged('D_PROTO_LEN')),
    ('agg-incr-scalar', ETAGS, [], 'struct s { int a; }; struct s g; '
     'BEGIN { @a = quantize(arg0, g); }', tagged('D_PROTO_ARG')),
    # An aggregation name is only created by an assignment (which marks it
    # modified), so naming an unassigned one fails to resolve; the
    # *_AGGBAD diagnostics are unreachable (recorded as gaps).
    ('agg-undefined-name', ETAGS, [], 'END { printa(@nosuch); }', tagged('D_IDENT_UNDEF')),
    ('agg-libacts', 0, [], 'BEGIN { @a = count(); } END { clear(@a); normalize(@a, 4); '
     'denormalize(@a); trunc(@a, 2); trunc(@a); setopt("quiet"); setopt("bufsize", "4m"); }',
     lambda g: [a['arg'] for a in acts(g) if a['kind'] == ACT['LIBACT']][:5] ==
     [str(DT_ACT_CLEAR), str(DT_ACT_NORMALIZE), str(DT_ACT_NORMALIZE),
      str(DT_ACT_DENORMALIZE), str(DT_ACT_TRUNC)]),
    ('trace-dyn', ETAGS, [], X + 'BEGIN { trace(xlate <struct xout *> ((struct xin *)arg0)); }',
     tagged('D_TRACE_DYN')),
    ('print-dyn', ETAGS, [], X + 'BEGIN { print(xlate <struct xout *> ((struct xin *)arg0)); }',
     tagged('D_PRINT_DYN')),
    ('print-type', 0, [], 'struct s { int a; }; struct s g; BEGIN { print(g); print(arg0); }',
     # print() records "module`type-id" of its argument's type; struct s
     # and int64_t are both D-container types.
     lambda g: [st['strdata'].split('`')[0] for st in g['stmts']] == ['D', 'D'] and
     all(st['strdata'].split('`')[1].isdigit() for st in g['stmts'])),
    ('printf-noargs', 0, [], 'BEGIN { printf("hello\\n"); }',
     lambda g: disasm(acts(g)[0]['difo']) == [('RET', 0, 0, 0)]),
    # --- probe descriptions ------------------------------------------------
    ('pdesc-zero', ETAGS, [], 'test:::nosuch { trace(1); }', tagged('D_PDESC_ZERO')),
    ('pdesc-zero-allowed', 0x4, [], 'test:::nosuch { trace(1); }', ok),
    ('pdesc-unstable-args', ETAGS, [], 'unstable:kernel::u { trace(args[0]); }',
     tagged('D_ARGS_MULTI')),
    # --- translators and dynamic translation -------------------------------
    ('xlate-dynamic-extern', 0, ['late=dynamic'],
     N + 'typed:kernel:fn:nox { trace(args[0].q); trace(args[0].r + 1); trace(args[0]); }',
     lambda g: all(any(ins >> 24 == OP['XLARG'] for ins in a['difo']['buf'])
                   for a in acts(g)) and
     [x['member'] for x in acts(g)[0]['difo']['xl']] == ['q'] and
     [x['member'] for x in acts(g)[1]['difo']['xl']] == ['r'] and
     # The whole-structure translation fills each member from its XLARG.
     sorted(x['member'] for x in acts(g)[2]['difo']['xl']) == ['q', 'r'] and
     all((ins >> 8) & 0xffff < len(a['difo']['xl'])
         for a in acts(g) for ins in a['difo']['buf'] if ins >> 24 == OP['XLARG'])),
    ('xlate-dynamic-ptr', 0, ['late=dynamic'],
     N + 'typed:kernel:fn:noxp { trace(args[0]->q); trace(*args[0]); }',
     lambda g: all(any(ins >> 24 == OP['XLARG'] for ins in a['difo']['buf'])
                   for a in acts(g))),
    ('xlate-static-missing', ETAGS, [], N + 'typed:kernel:fn:nox { trace(args[0].q); }',
     tagged('D_ARGS_XLATOR')),
    ('xlate-dynamic-program', 0, ['late=dynamic'],
     X + 'BEGIN { trace(xlate <struct xout> ((struct xin *)arg0).b); }', ok),
    # --- symbol relocations (dt_as) ----------------------------------------
    ('reloc-dynamic', 0x60, ['fakemods', 'linkmode=dynamic'],
     'BEGIN { trace(&`fake_var); trace(&fakel`fake_long); trace(&fakeu``fake_var); }',
     lambda g: reloc(g, 0, 1, 0, 'fake_var') and reloc(g, 1, 1, 0, 'fake_long') and
     reloc(g, 2, 0, 1, 'fake_var')),
    ('reloc-primary', 0x60, ['fakemods', 'linkmode=primary'],
     'BEGIN { trace(&`fake_var); trace(&fakel`fake_long); trace(&fakeu``fake_var); }',
     lambda g: reloc(g, 0, 0, 0, 'fake_var') and reloc(g, 1, 1, 0, 'fake_long') and
     reloc(g, 2, 0, 1, 'fake_var')),
    ('reloc-kernel', 0x60, ['fakemods', 'linkmode=kernel'],
     'BEGIN { trace(&`fake_var); trace(&fakel`fake_long); trace(&fakeu``fake_var); }',
     lambda g: reloc(g, 0, 0, 0, 'fake_var') and reloc(g, 1, 0, 0, 'fake_long') and
     reloc(g, 2, 0, 1, 'fake_var')),
    ('reloc-static', 0x60, ['fakemods', 'linkmode=static'],
     'BEGIN { trace(&`fake_var); trace(&fakeu``fake_var); }',
     lambda g: reloc(g, 0, 0, 0, 'fake_var') and reloc(g, 1, 0, 0, 'fake_var')),
    ('reloc-undef-primary', ETAGS, ['fakemods', 'linkmode=dynamic'],
     'BEGIN { trace(&`fake_var); }', tagged('D_ASRELO')),
    ('reloc-undef-loadable', ETAGS, ['fakemods', 'linkmode=dynamic'],
     'BEGIN { trace(&fakel`fake_long); }', tagged('D_ASRELO')),
    ('reloc-undef-user', ETAGS | 0x20, ['fakemods', 'linkmode=dynamic'],
     'BEGIN { trace(&fakeu``fake_var); }', tagged('D_ASRELO')),
    ('reloc-load-symbol', 0x60, ['fakemods', 'linkmode=static'],
     'BEGIN { trace(*(int *)&`fake_var); }',
     lambda g: int(acts(g)[0]['difo']['int'][0]) == syms['fake_var'][0]),
    # --- compiler modes and options ----------------------------------------
    ('cpp-define', 0x10, ['file', 'define=Y=5'], '#define X 4\nBEGIN { trace(X + Y); }\n',
     lambda g: val(acts(g)[0]) == 9),
    ('cpp-shebang', 0x10, ['file'], '#!/usr/sbin/dtrace -s\n#define X 6\nBEGIN { trace(X); }\n',
     lambda g: val(acts(g)[0]) == 6),
    ('cpp-incdir', 0x10, ['file', 'incdir=' + str(out)],
     '#include "inc.h"\nBEGIN { trace(INCVAL); }\n', lambda g: val(acts(g)[0]) == 77),
    ('cpp-version-macro', 0x10, ['file'],
     '#if __SUNW_D_VERSION >= 0x01000000\nBEGIN { trace(1); }\n#else\nBEGIN { trace(2); }\n'
     '#endif\n', lambda g: val(acts(g)[0]) == 1),
    ('cpp-error', 0x10, ['file'], '#error stop\nBEGIN { trace(1); }\n',
     lambda g: 'error' in g and 'Preprocessor failed' in g['error']),
    ('cpp-noent', 0x10, ['file', 'cpppath=/nonexistent/cpp'], 'BEGIN { trace(1); }\n',
     lambda g: 'error' in g and 'Preprocessor not found' in g['error']),
    ('cpp-noexec', 0x10, ['file', 'cpppath=' + str(out / 'notexec.sh')], 'BEGIN { trace(1); }\n',
     lambda g: 'error' in g and 'exec' in g['error']),
    ('fcompile-plain', 0, ['file'], '#!/usr/sbin/dtrace -s\nBEGIN { trace(arg1); }\n',
     lambda g: val(acts(g)[0]) == 7),
    ('typefile', 0, ['typefile'], 'unsigned short', lambda g: g.get('size') == 2),
    ('version-reduce', ETAGS, ['version=1.0'], 'BEGIN { print(1); }',
     tagged('D_FUNC_UNDEF')),
    ('version-raise', 0, ['version=1.0'], 'BEGIN { trace(1); }\n@@then version=1.1\nBEGIN { trace(2); }',
     lambda g: 'conflicts with earlier' in (g.get('setopt_error') or '')),
    ('version-same', 0, [], 'BEGIN { trace(1); }\n@@then version=' + '1.13' + '\nBEGIN { trace(2); }',
     lambda g: ok(g)),
    ('tree-dump', 0, ['tree=15'], 'BEGIN /arg0/ { trace(arg0 + 1); }', ok),
    ('verbose-dis', 0x1, [], 'BEGIN { trace(arg0 * 2); }', ok),
    ('sugar-dump', 0x400, [], 'BEGIN { if (arg0) { trace(1); } }', ok),
    ('ctf-cache', 0, ['ctypes=' + str(ctypes), 'dtypes=' + str(dtypes)],
     'struct cached { int z; }; BEGIN { trace(sizeof (struct cached)); }',
     lambda g: ok(g) and ctypes.read_bytes()[:2] == b'\xf1\xcf' and
     dtypes.read_bytes()[:2] == b'\xf1\xcf'),
    # Control-directive-only compilation yields no program and no error
    # (regression: it returned an uninitialized program pointer).
    ('ctl-only', 0x2000, [], '#pragma D option quiet\nBEGIN { trace(1); }',
     lambda g: g.get('errno') == 0 and 'stmts' not in g),
    ('empty-flag', 0x2, [], '', lambda g: ok(g) and g['stmts'] == []),
    ('macro-args', 0, ['argv=prog|21|word'], 'BEGIN { trace($1 * 2); trace($$2); }',
     lambda g: [val(a) for a in acts(g)] == [42, 'word']),
    # --- D libraries ---------------------------------------------------------
    ('lib-depends', 0, LIBS + ['libdir=' + str(libs / 'good')], 'BEGIN { trace(LIBA); }',
     lambda g: val(acts(g)[0]) == 41),
    ('lib-cycle', 0, LIBS + ['libdir=' + str(libs / 'cyc')], 'BEGIN { trace(1); }',
     lambda g: 'Cyclic dependency' in g.get('error', '')),
    # Dependency failures skip the library silently (documented in
    # dt_load_libs_sort()); its inline is then undefined.
    ('lib-baddep', 0, LIBS + ['libdir=' + str(libs / 'bad')], 'BEGIN { trace(E); }',
     lambda g: 'failed to resolve E' in g.get('error', '')),
    ('lib-baddep-other', 0, LIBS + ['libdir=' + str(libs / 'bad')], 'BEGIN { trace(1); }', ok),
    ('lib-notlib-dep', 0, LIBS + ['libdir=' + str(libs / 'notlib')], 'BEGIN { trace(1); }',
     lambda g: 'Invalid library dependency' in g.get('error', '')),
    ('lib-syntax', 0, LIBS + ['libdir=' + str(libs / 'syntax')], 'BEGIN { trace(1); }',
     lambda g: 'error' in g),
    ('lib-missing-dir', 0, LIBS + ['libdir=' + str(libs / 'nonexistent')], 'BEGIN { trace(1); }',
     ok),
    ('lib-duplicate', 0, LIBS + ['libdir=' + str(libs / 'dup1'), 'libdir=' + str(libs / 'dup2')],
     'BEGIN { trace(G2); }', lambda g: tagged('D_IDENT_UNDEF')(g) or 'G2' in g.get('error', '')),
    ('lib-duplicate-first', 0, LIBS + ['libdir=' + str(libs / 'dup1'), 'libdir=' + str(libs / 'dup2')],
     'BEGIN { trace(G1); }', lambda g: val(acts(g)[0]) == 7),
    ('lib-unreadable', 0, LIBS + ['libdir=' + str(libs / 'unread')], 'BEGIN { trace(1); }',
     ok if os.geteuid() != 0 else (lambda g: True)),
    # --- registers -----------------------------------------------------------
    ('regs-exhausted', ETAGS, ['iregs=3'],
     'BEGIN { trace((arg0 + arg1) * (arg2 + arg3)); }', tagged('D_NOREG')),
    ('regs-enough', 0, ['iregs=4'], 'BEGIN { trace((arg0 + arg1) * (arg2 + arg3)); }',
     lambda g: val(acts(g)[0], {'args': [1, 2, 3, 4]}) == 21),
    ('regs-deep', ETAGS, [], 'BEGIN { trace(' + '+'.join(f'(arg{i % 4} * {i + 2}' for i in range(9))
     + ')' * 9 + '); }', tagged('D_NOREG')),
    ('tupregs-exhausted', 0, ['tregs=2'], 'BEGIN { a[1, 2, 3] = 4; }',
     lambda g: 'tuple' in g.get('error', '').lower()),
    ('tupregs-conf', 0, ['conf_tupregs=2'], 'BEGIN { trace(substr("abc", 1, 1)); }',
     lambda g: 'tuple' in g.get('error', '').lower()),
    ('regs-multiword', 0, ['iregs=100'],
     'BEGIN { trace(' + '+'.join(f'(arg{i % 4}' for i in range(70)) + ')' * 70 + '); }',
     lambda g: ok(g) and max(max((ins >> 16) & 0xff, (ins >> 8) & 0xff, ins & 0xff)
                             for ins in acts(g)[0]['difo']['buf']) >= 64),
    # --- identifiers: args[], uregs[], prototypes ---------------------------
    ('args-len', ETAGS, [], 'typed:kernel:fn:t { trace(args[0, 1]); }', tagged('D_PROTO_LEN')),
    ('args-nonconst', ETAGS, [], 'typed:kernel:fn:t { trace(args[arg0]); }',
     tagged('D_PROTO_ARG')),
    ('args-range', ETAGS, [], 'typed:kernel:fn:t { trace(args[9]); }', tagged('D_ARGS_IDX')),
    ('args-native-type', ETAGS, [], 'typed:kernel:fn:badn { trace(args[0]); }',
     tagged('D_ARGS_TYPE')),
    ('args-xlate-type', ETAGS, [], 'typed:kernel:fn:bad { trace(args[0]); }',
     tagged('D_ARGS_TYPE')),
    ('uregs-len', ETAGS, [], 'BEGIN { trace(uregs[0, 1]); }', tagged('D_PROTO_LEN')),
    ('uregs-nonconst', ETAGS, [], 'BEGIN { trace(uregs[arg0]); }', tagged('D_PROTO_ARG')),
    ('assoc-key-type', ETAGS, [], 'BEGIN { a[1] = 1; a["x"] = 2; }', tagged('D_PROTO_ARG')),
    ('func-arg-type', ETAGS, [], 'BEGIN { trace(strlen(1)); }', tagged('D_PROTO_ARG')),
    ('func-ret-type', ETAGS, [], 'BEGIN { trace(getmajor(0)); }', tagged('D_UNKNOWN')),
    # hostid_t is not a base type in this (kernel-less) configuration.
    ('var-type-unresolved', ETAGS, [], 'BEGIN { trace(hostid); }',
     lambda g: ok(g) or g.get('error', '').startswith('[D_UNKNOWN] in action list: '
                                                    'failed to resolve type hostid_t')),
    ('pdesc-argdesc-error', ETAGS, [], 'typed:kernel:fn:argfail { trace(1); }',
     tagged('D_PDESC_INVAL')),
    ('agg-key-function', 0, [], 'BEGIN { @a[strlen(probefunc), probefunc] = count(); }',
     lambda g: [a['kind'] for a in acts(g)][-1] == AGG['COUNT']),
    # --- more compiler modes -------------------------------------------------
    ('cpp-shebang-only', 0x12, ['file'], '#!/usr/sbin/dtrace -s', lambda g: ok(g) and g['stmts'] == []),
    # Regression: a foreign-target variable of bottom type has no object
    # name; dt_copyvar() passed NULL to strncpy() (crash).
    ('zdefs-foreign-bottom', 0x4, [], 'nosuchvmx:fbt::foo:entry { x = args[0]; trace(x + 1); }',
     lambda g: ok(g) and acts(g)[0]['difo']['var'][1][3] == 0),
    ('ctf-cache-unwritable', 0, ['ctypes=/dev/null', 'dtypes=/dev/null'],
     'BEGIN { trace(1); }', ok),
    ('type-unresolved', 0, ['type'], 'short double',
     lambda g: 'failed to resolve type short double' in g.get('error', '')),
    ('type-forward', 0, ['type'], 'struct nosuch_incomplete_t',
     lambda g: g.get('type') == 'struct nosuch_incomplete_t'),
    ('reloc-mixed-labels', 0x60, ['fakemods', 'linkmode=primary'],
     'BEGIN { trace(arg0 ? (uintptr_t)&`fake_var : (uintptr_t)&fakeu``fake_var); }',
     lambda g: len(acts(g)[0]['difo']['krel']) == 0 and len(acts(g)[0]['difo']['urel']) == 1 and
     any(ins >> 24 == OP['BA'] for ins in acts(g)[0]['difo']['buf'])),
    # --- table limits ---------------------------------------------------------
    ('limit-strtab', ETAGS, [], 'BEGIN { trace(' + balanced(
        [f'probefunc == "{i:04d}' + 'x' * 100 + '"' for i in range(700)]) + '); }',
     lambda g: 'String constant table limit exceeded' in g.get('error', '')),
    ('limit-inttab', ETAGS, [], 'BEGIN { trace(' + balanced(
        [f'arg0 == {100000 + i}' for i in range(65600)]) + '); }',
     lambda g: 'Integer constant table limit exceeded' in g.get('error', '')),
    ('limit-vartab', ETAGS, [], ''.join(f'self int v{i:04d}' + 'y' * 100 + '; '
                                        for i in range(700)) + 'BEGIN { trace(' + balanced(
        [f'self->v{i:04d}' + 'y' * 100 for i in range(700)]) + '); }',
     lambda g: 'String constant table limit exceeded' in g.get('error', '')),
    ('limit-symtab', ETAGS, [], ''.join(f'struct t{i:04d}' + 'z' * 100 + ' { int a; }; '
                                        for i in range(700)) + 'BEGIN { trace(' + balanced(
        [f'(struct t{i:04d}' + 'z' * 100 + ' *)arg0 != 0' for i in range(700)]) + '); }',
     lambda g: 'String constant table limit exceeded' in g.get('error', '')),
    # --- second pass: remaining reachable outcomes --------------------------
    ('destructive-difexpr', 0, [], 'BEGIN { copyout((void *)arg0, arg1, 4); }',
     lambda g: acts(g)[0]['difo']['destructive'] == 1),
    ('trunc-too-many', ETAGS, [], 'BEGIN { @a = count(); } END { trunc(@a, 1, 2); }',
     tagged('D_TRUNC_PROTO')),
    ('trace-agg', ETAGS, [], 'BEGIN { @a = count(); } END { trace(@a); }',
     tagged('D_TRACE_AGG')),
    ('tracemem-pointer', 0, [], 'BEGIN { tracemem((char *)arg0, 16); }',
     lambda g: kinds(g) == [ACT['TRACEMEM']]),
    ('immstack-proto', ETAGS, [], 'BEGIN { immstack(1, 2); }', tagged('D_STACK_PROTO')),
    ('immstack-size', ETAGS, [], 'BEGIN { immstack(arg0); }', tagged('D_STACK_SIZE')),
    ('ustack-strsize-negative', ETAGS, [], 'BEGIN { ustack(1, -1); }',
     tagged('D_USTACK_STRSIZE')),
    ('agg-immstack-key', 0, ['immstackframes=3'], 'BEGIN { @a[immstack()] = count(); }',
     lambda g: ACT['IMMSTACK'] in kinds(g)),
    ('llquantize-power', ETAGS, [], 'BEGIN { @a = llquantize(arg0, 4, 0, 6, 12); }',
     tagged('D_LLQUANT_FACTOREVEN')),
    ('pdesc-zero-target', ETAGS, [], 'nosuchvm:test:::nosuch { trace(1); }',
     lambda g: g.get('error', '').startswith('[D_PDESC_ZERO]') and
     'nosuchvm:test' in g['error']),
    ('version-xlator', 0, LIBS + ['libdir=' + str(libs / 'xlver')],
     'BEGIN { trace(xlate <struct vout> ((struct vin *)arg0).b); }\n@@then version=1.5\n'
     'BEGIN { trace(xlate <struct vout2> ((struct vin *)arg0).c); '
     'trace(xlate <struct vout> ((struct vin *)arg0).b); }',
     lambda g: 'stmts' in g['phase0'] and
     'cannot translate' in g.get('error', '') and 'vout"' in g['error']),
    ('version-xlator-kept', 0, LIBS + ['libdir=' + str(libs / 'xlver')],
     'BEGIN { trace(1); }\n@@then version=1.5\n'
     'BEGIN { trace(xlate <struct vout2> ((struct vin *)arg0).c); '
     'trace(xlate <struct vout3> ((struct vin *)arg0).d); }', ok),
    ('lib-ctl-error', 0, LIBS + ['libdir=' + str(libs / 'malformed')], 'BEGIN { trace(1); }',
     lambda g: 'malformed' in g.get('error', '')),
    # Library inline arrays used by two compilations on one handle; values
    # are f(x) = x + 1 and g(y) = 2 f(y) with arg1 = 7.
    ('lib-inline-array', 0, LIBS + ['libdir=' + str(libs / 'inl')],
     'BEGIN { trace(g[arg0]); }\n@@then -\n'
     'BEGIN { trace(sizeof (g[2])); trace(f[g[arg1]]); }',
     lambda g: [val(a) for a in acts(g) if a['return']] == [4, 17] and
     val(acts(g['phase0'])[0]) == 12),
    ('typefile-error', 0, ['typefile'], 'short double',
     lambda g: 'failed to resolve type' in g.get('error', '')),
    ('agg-key-dynamic', ETAGS, [], X + 'BEGIN { @a[xlate <struct xout *> ((struct xin *)arg0)] '
     '= count(); }', lambda g: 'error' in g),
    ('substr-too-few', ETAGS, [], 'BEGIN { trace(substr("a")); }',
     lambda g: g.get('error', '').startswith('[D_PROTO_LEN]') and 'at least 2' in g['error']),
    ('substr-too-many', ETAGS, [], 'BEGIN { trace(substr("a", 1, 2, 3)); }',
     tagged('D_PROTO_LEN')),
    ('inline-chain', 0, [], 'int gv; inline int K = gv; inline int L = K; '
     'BEGIN { gv = 5; trace(L + 1); L2 = L; trace(sizeof (L)); }',
     lambda g: ok(g)),
    ('key-dynamic', ETAGS, [], X + 'BEGIN { a[xlate <struct xout *> ((struct xin *)arg0)] = 1; }',
     tagged('D_KEY_TYPE')),
    ('key-void', ETAGS, [], 'BEGIN { a[trace(1)] = 1; }', tagged('D_KEY_TYPE')),
    ('func-arg-dynamic', ETAGS, [], X + 'BEGIN { trace(strlen(xlate <struct xout *> '
     '((struct xin *)arg0))); }', tagged('D_PROTO_ARG')),
    # Regression: compiling a translator body (dynamic translators) left the
    # input register allocated (dt_regset_assert_free aborts under
    # DTRACE_DEBUG_REGSET, which every case here runs with).
    ('xlate-dynamic-member-regs', 0, ['late=dynamic'],
     X + 'BEGIN { trace(xlate <struct xout> ((struct xin *)arg0).b); }', ok),
    # Regression: a joined printa() validated every %@ conversion against
    # the first aggregation's function, so after count() (unsigned) a sum()
    # column got an unsigned conversion.  Each %@ conversion takes the value
    # of the aggregation in its position: count() unsigned, sum() and min()
    # signed (D: only count() has an unsigned result).
    ('printa-joined-types', 0, [], 'BEGIN { @c = count(); @s = sum(arg0); @m = min(arg0); } '
     'END { printa("%@d %@d %@d\\n", @c, @s, @m); printa("%@d %@d\\n", @s, @c); }',
     lambda g: [['u' if f[-1] == 'u' else 's' for f in st['fmts']]
                for st in g['stmts'] if st['fmts']] == [['u', 's', 's'], ['s', 'u']]),
    # Indexing an aggregation that was never assigned creates it unmodified
    # (dt_parser.c LBRAC path), so the *_AGGBAD checks are reachable.
    ('aggbad-clear', ETAGS, [], 'BEGIN { clear(@x[1]); }', tagged('D_CLEAR_AGGBAD')),
    ('aggbad-normalize', ETAGS, [], 'BEGIN { normalize(@x[1], 2); }',
     tagged('D_NORMALIZE_AGGBAD')),
    ('aggbad-trunc', ETAGS, [], 'BEGIN { trunc(@x[1]); }', tagged('D_TRUNC_AGGBAD')),
    ('aggbad-printa', ETAGS, [], 'BEGIN { printa(@x[1]); }', tagged('D_PRINTA_AGGBAD')),
    # A translated pointer as a whole statement reaches code generation.
    ('cg-dyn-statement', ETAGS, [], X + 'BEGIN { xlate <struct xout *> ((struct xin *)arg0); }',
     tagged('D_CG_DYN')),
    # The per-DIFO type-name table (TYPECAST operands) overflows exactly at
    # the stringof() / constant-cast insertion: 570 distinct struct pointer
    # casts of 115 bytes each fill it to 65556 bytes with the last at 65441.
    ('limit-symtab-stringof', ETAGS, [], FILL_DECLS + 'BEGIN { trace(' + FILL_SUM +
     ' + strlen(stringof(arg1))); }',
     lambda g: 'String constant table limit exceeded' in g.get('error', '')),
    ('limit-symtab-intcast', ETAGS, [], FILL_DECLS + 'BEGIN { trace(' + FILL_SUM +
     ' + (char)3); }',
     lambda g: 'String constant table limit exceeded' in g.get('error', '')),
    # 128 registers fill two bitmap words exactly, so exhaustion scans past
    # every word.
    ('regs-multiword-exhausted', ETAGS, ['iregs=128'],
     'BEGIN { trace(' + '+'.join(f'(arg{i % 4}' for i in range(140)) + ')' * 140 + '); }',
     tagged('D_NOREG')),
    ('provider-declared-args', 0x4, [], 'provider zz { probe q(int, char *); }; '
     'zz:::q { trace(args[0]); trace(stringof(args[1])); }', ok),
    ('provider-declared-xlated', 0x4, [], 'provider zz { probe q(int a) : (int a); }; '
     'zz:::q { trace(args[0]); }', ok),
    ('key-count-mismatch', ETAGS, [], 'BEGIN { a[1] = 1; a[1, 2] = 2; }',
     lambda g: tagged('D_PROTO_LEN')(g) and '2 keys passed' in g['error']),
    ('args-len-message', ETAGS, [], 'typed:kernel:fn:t { trace(args[0, 1]); }',
     lambda g: tagged('D_PROTO_LEN')(g) and '2 args passed, 1 expected' in g['error']),
    ('key-bottom', 0x4, [], 'nosuchvmx:fbt::foo:entry { a[args[0]] = 1; }', ok),
    ('inline-func-root', 0, [], 'inline int F = strlen(probefunc); BEGIN { trace(F); }',
     lambda g: val(acts(g)[0], {'args': [0], 'probefunc': 'fn'}) == 2),
    ('inline-param-root', 0, [], 'inline int f[int x] = x; BEGIN { trace(f[arg1]); }',
     lambda g: val(acts(g)[0]) == 7),
    ('destructive-copyoutstr', 0, [], 'BEGIN { copyoutstr("x", arg0, 2); }',
     lambda g: acts(g)[0]['difo']['destructive'] == 1),
    # Relocations together with labeled instructions and translator
    # references in one DIFO (the assembler's relocation pass).
    ('reloc-labeled-setx', 0x60, ['fakemods', 'linkmode=dynamic'],
     'BEGIN { trace((uintptr_t)&`fake_var > arg0); }',
     lambda g: reloc(g, 0, 1, 0, 'fake_var')),
    ('reloc-xlarg', 0x60, ['fakemods', 'linkmode=dynamic', 'late=dynamic'],
     N + 'typed:kernel:fn:nox { trace(args[0].q + (long)&`fake_var); }',
     lambda g: len(acts(g)[0]['difo']['krel']) == 1 and
     [x['member'] for x in acts(g)[0]['difo']['xl']] == ['q']),
    # String table full (65626 bytes, last literal at 65521) when the
    # relocation's symbol name is inserted.
    ('limit-strtab-reloc', ETAGS | 0x60, ['fakemods', 'linkmode=dynamic'],
     'BEGIN { trace(' + ' + '.join(f'strlen("{i:04d}' + 'x' * 100 + '")' for i in range(625))
     + ' + (long)&`fake_var); }',
     lambda g: 'String constant table limit exceeded' in g.get('error', '')),
    ('forward-then-defined', 0, [], 'struct fw; struct fw *gp; struct fw { int a; }; '
     'BEGIN { trace(gp->a); }', ok),
    ('compare-int-pointer', 0, [], 'BEGIN { trace(0 < (int *)arg0); }',
     lambda g: val(acts(g)[0], {'args': [8]}) == 1 and val(acts(g)[0], {'args': [0]}) == 0),
    ('xlate-dynamic-assign', 0, ['late=dynamic'], N + 'struct nosuch_xlate go; '
     'typed:kernel:fn:nox { go = args[0]; trace(go.q); }', ok),
    # A type name longer than DT_TYPE_NAMELEN cannot be formatted: the
    # TYPECAST annotation carries "unknown" (not an allocation failure).
    ('typecast-long-name', 0, [], 'struct s' + 'q' * 140 + ' { int a; }; '
     'BEGIN { trace(((struct s' + 'q' * 140 + ' *)arg0)->a); }',
     lambda g: '\x00unknown\x00' in acts(g)[0]['difo']['sym']),
    ('foreign-bottom-agg', 0x4, [], 'nosuchvmx:fbt::foo:entry { this->x = (int)args[0]; '
     '@a = sum(args[0]); }', ok),
    ('ustack-unsigned-strsize', 0, [], 'BEGIN { ustack(2, 64u); }',
     lambda g: acts(g)[0]['arg'] == str(ustack_arg(2, 64))),
    ('ctf-cache-device', 0, ['ctypes=/dev/zero', 'dtypes=/dev/zero'], 'BEGIN { trace(1); }', ok),
    # Joined printa(): key conversions precede the %@ conversions, and an
    # aggregation without a %@ conversion of its own keeps the default.
    ('printa-joined-keys', 0, [], 'BEGIN { @c[probefunc] = count(); @s[probefunc] = sum(arg0); } '
     'END { printa("%s %@d %@d\\n", @c, @s); printa("%s %@d\\n", @c, @s); }',
     lambda g: [['u' if f[-1] == 'u' else 's' for f in st['fmts'] if f[-1] in 'diu']
                for st in g['stmts'] if st['fmts']] == [['u', 's'], ['u']]),
    # A provider name ending in a digit that is a kernel provider without
    # the process privilege is not treated as a pid provider.
    ('provider-digit-name', 0, [], 'ip6:::n { trace(1); }', ok),
    ('version-reduce-ok', 0, ['version=1.0'], 'BEGIN { trace(1); }', ok),
    # Library inlines have no version binding and survive a reduction.
    ('version-reduce-libinline', 0, LIBS + ['libdir=' + str(libs / 'inl')],
     'BEGIN { trace(f[1]); }\n@@then version=1.5\nBEGIN { trace(f[arg1]); }',
     lambda g: val(acts(g)[0]) == 8),
    ('lib-ctl-error-sysdir', 0, ['libs', 'syslibdir=' + str(libs / 'malformed')],
     'BEGIN { trace(1); }', lambda g: 'malformed' in g.get('error', '')),
    # Regression: built-in host/guest arrays (ids above DIF_VAR_ARRAY_MAX)
    # were taken for associative arrays and code generation crashed; DIF
    # cannot encode them (ldga's array field is 8 bits), so they are refused.
    ('huregs-refused', ETAGS, [], 'BEGIN { trace(huregs[0]); }',
     lambda g: tagged('D_IDENT_BADREF')(g) and 'huregs' in g['error']),
    ('hargs-refused', ETAGS, [], 'typed:kernel:fn:t { trace(hargs[0]); }',
     lambda g: tagged('D_IDENT_BADREF')(g) and 'hargs' in g['error']),
    # An undeclared thread-local read is a diagnostic, not an abort.
    ('self-undeclared', ETAGS, [], 'BEGIN { trace(self->x); }', tagged('D_VAR_UNDEF')),
    # --- round 4 --------------------------------------------------------------
    # Symbols of an offline module with CTF: value loads and members of
    # kernel/user types use the linker's relocation pseudo-ops.
    ('sym-value-load', 0x60, ['fakemods', 'linkmode=static'], 'BEGIN { trace(`fake_long); }',
     lambda g: disasm(acts(g)[0]['difo'])[:2] == [('SETX', 0, 0, 1), ('LDX', 1, 0, 1)] and
     int(acts(g)[0]['difo']['int'][0]) == syms['fake_long'][0]),
    ('sym-member-usetx', 0x60, ['fakemods', 'linkmode=static'],
     'BEGIN { trace(fakek`fake_kobj.b); trace(&fakek`fake_kobj.c); }',
     lambda g: [op[0] for op in disasm(acts(g)[0]['difo'])] ==
     ['SETX', 'USETX', 'ADD', 'ULOAD', 'RET'] and
     '\x00b\x00' in acts(g)[0]['difo']['sym'] and
     'ULOAD' not in [op[0] for op in disasm(acts(g)[1]['difo'])]),
    ('sym-user-member', 0x60, ['fakemods', 'linkmode=static'],
     'BEGIN { trace(fakeu``fake_kobj.b); }',
     lambda g: 'UULOAD' in [op[0] for op in disasm(acts(g)[0]['difo'])]),
    ('limit-symtab-usetx', ETAGS | 0x60, ['fakemods', 'linkmode=static'],
     FILL_DECLS + 'BEGIN { trace(' + FILL_SUM + ' + fakek`fake_kobj.b); }',
     lambda g: 'String constant table limit exceeded' in g.get('error', '')),
    # cpp input that cannot seek (a pipe), fork failure, and signals during
    # the wait for cpp.
    ('cpp-pipe', 0x10, ['pipe'], '#define X 3\nBEGIN { trace(X); }\n',
     lambda g: val(acts(g)[0]) == 3),
    ('cpp-fork-fails', 0x10, ['file', 'nproc0'], 'BEGIN { trace(1); }\n',
     lambda g: 'fork' in g.get('error', '').lower()),
    ('cpp-wait-interrupted', 0x10, ['file', 'alarm'], '#define X 4\nBEGIN { trace(X); }\n',
     lambda g: val(acts(g)[0]) == 4 and g.get('alarms') == 1),
    # CTF cache files that cannot be truncated (pipes: the driver's stdout
    # and stderr) are skipped with a debug message.
    ('ctf-cache-pipe', 0, ['ctypes=/dev/fd/1', 'dtypes=/dev/fd/2'], 'BEGIN { trace(1); }', ok),
    ('provider-static-args', 0x4, [], 'provider zz { probe q(int, char *); }; '
     'zz*:::q { trace(args[0]); trace(args[1]); }', lambda g: 'error' not in g),
] + [
    # Regression: each scalar inline reference used to leak a DIF register,
    # so a handful of references exhausted the register set (D_NOREG).
    (f'inline-noleak-{n}', 0, [], 'inline string s = "ab"; BEGIN { trace('
     + ' + '.join(['strlen(s)'] * n) + '); }',
     (lambda n: lambda g: ok(g) and val(acts(g)[0]) == 2 * n)(n)) for n in (5, 9, 16)
]

(out / 'inc.h').write_text('#define INCVAL 77\n')
(out / 'notexec.sh').write_text('#!/bin/sh\nexit 0\n')
(out / 'notexec.sh').chmod(0o644)
cases = [{'name': n, 'cflags': f, 'opts': o, 'prog': p} for n, f, o, p, _ in CASES]
got = compile_cases(exe, obj, out, cases)
results = []
for name, f, o, p, check in CASES:
    g = got[name]
    try:
        passed = bool(check(g))
        note = None
    except Exception as err:  # a malformed result is a failure, not a crash
        passed, note = False, f'{type(err).__name__}: {err}'
    results.append({'case': name, 'passed': passed, 'note': note,
                    'error': g.get('error'), 'setopt_error': g.get('setopt_error'),
                    'kinds': kinds(g)})
(libs / 'unread/h.d').chmod(0o644)
finish(out, results, [Path(__file__), Path(__file__).with_name('frontend-codegen.c'),
                      Path(__file__).with_name('frontend_codegen_common.py'),
                      obj / 'cddl/lib/libdtrace/libdtrace.so.2'],
       'dt_cc/dt_as/dt_regset: actions, encodings, relocations, cpp, libraries, '
       'options and registers; NOSYS dtrace_vopen model with offline symbol modules',
       'compiler driver/assembler cases')
