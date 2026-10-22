#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Each compiler diagnostic is detected for the documented reason.

Every case compiles an invalid D program with DTRACE_C_ETAGS through the
actual libdtrace (NODEV|NOSYS) and requires the message to begin with the
expected [D_TAG].  Tags were chosen from the compiler sources; each program is
written to trigger that tag alone.  Diagnostics that need kernel symbols,
live providers or USDT definitions are out of scope here.  Not reached from
plain D in this configuration (recorded in COVERAGE.5BSD.md): D_DECL_MNAME,
D_OP_ACT, D_FUNC_IDENT, D_DECL_IDENT, D_OP_IDENT, D_OP_DYN, D_ARGS_IDX and the
four *_AGGBAD tags.
"""
from pathlib import Path
import ctypes as C
import hashlib
import json
import re
import sys

out, binary = (Path(x).resolve() for x in sys.argv[1:])
if not out.is_relative_to('/usr/obj') or not binary.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('usage: compiler-diagnostics.py /usr/obj/new-output /usr/obj/.../libdtrace.so.2')
out.mkdir(parents=True)
lib = C.CDLL(str(binary))
lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.c_uint,
                                          C.c_int, C.c_void_p]
lib.dtrace_program_strcompile.restype = C.c_void_p
lib.dtrace_errno.argtypes = [C.c_void_p]
lib.dtrace_errmsg.argtypes = [C.c_void_p, C.c_int]
lib.dtrace_errmsg.restype = C.c_char_p
ETAGS = 0x0100
B = 'BEGIN '
AGG = B + '{ @a[1] = count(); } '

CASES = [
    # Lexical
    ('D_CHR_NULL', B + "{ trace(''); }"),
    ('D_CHR_OFLOW', B + "{ trace('abcdefghi'); }"),
    ('D_CHR_NL', B + "{ trace('a\n'); }"),
    ('D_STR_NL', B + '{ trace("a\nb"); }'),
    ('D_INT_DIGIT', B + '{ trace(09); }'),
    ('D_INT_OFLOW', B + '{ trace(0x1ffffffffffffffff); }'),
    ('D_MACRO_UNDEF', B + '{ trace($1); }'),
    ('D_SYNTAX', B + '{ trace(1) +; }'),
    ('D_EMPTY', ''),
    # Declarations
    ('D_DECL_COMBO', 'int float x; ' + B + '{ trace(1); }'),
    ('D_DECL_LONGINT', 'struct s { int a; }; long struct s x; ' + B + '{ trace(1); }'),
    ('D_DECL_SIGNINT', 'signed float x; ' + B + '{ trace(1); }'),
    ('D_DECL_CHARATTR', 'short short char x; ' + B + '{ trace(1); }'),
    ('D_DECL_CLASS', 'extern static int x; ' + B + '{ trace(1); }'),
    ('D_DECL_BADCLASS', 'register int x; ' + B + '{ trace(1); }'),
    ('D_DECL_USELESS', 'int; ' + B + '{ trace(1); }'),
    ('D_DECL_TYPERED', 'struct s { int a; }; struct s { int b; }; ' + B + '{ trace(1); }'),
    ('D_DECL_IDRED', 'int x; char x; ' + B + '{ trace(1); }'),
    ('D_DECL_BFCONST', 'struct s { int a : -1; }; ' + B + '{ trace(1); }'),
    ('D_DECL_BFSIZE', 'struct s { char a : 9; }; ' + B + '{ trace(1); }'),
    ('D_DECL_BFTYPE', 'struct s { float a : 3; }; ' + B + '{ trace(1); }'),
    ('D_DECL_ARRSUB', 'int x[-1]; ' + B + '{ trace(1); }'),
    ('D_DECL_ARRBIG', 'int x[0x7fffffffffffffff]; ' + B + '{ trace(1); }'),
    ('D_DECL_ARRNULL', 'int x[]; ' + B + '{ trace(1); }'),
    ('D_DECL_DYNOBJ', 'int x[2][int]; ' + B + '{ trace(1); }'),
    ('D_DECL_VOIDOBJ', 'void x; ' + B + '{ trace(1); }'),
    ('D_DECL_ENCONST', 'enum e { A = timestamp }; ' + B + '{ trace(1); }'),
    ('D_DECL_ENOFLOW', 'enum e { A = 0x7fffffff, B }; ' + B + '{ trace(1); }'),
    ('D_DECL_INCOMPLETE', 'struct s; struct s x; ' + B + '{ trace(1); }'),
    ('D_DECL_PROTO_VOID', 'int f(int, void); ' + B + '{ trace(1); }'),
    ('D_DECL_PROTO_NAME', 'int f(void v); ' + B + '{ trace(1); }'),
    ('D_DECL_PROTO_VARARGS', 'provider p97 { probe x(...); }; ' + B + '{ trace(1); }'),
    ('D_DECL_SCOPE', 'int D`x; ' + B + '{ trace(1); }'),
    ('D_DECL_LOCASSC', 'this int x[int]; ' + B + '{ trace(1); }'),
    # Expressions and operators
    ('D_DIV_ZERO', B + '{ trace(1 / 0); }'),
    ('D_DEREF_NONPTR', B + '{ x = 1; trace(*x); }'),
    ('D_DEREF_VOID', B + '{ trace(*(void *)0); }'),
    ('D_ADDROF_VAR', B + '{ x = 1; trace(&x); }'),
    ('D_ADDROF_BITFIELD', 'struct s { int a : 3; }; struct s g; ' + B + '{ trace(&g.a); }'),
    ('D_SIZEOF_BITFIELD', 'struct s { int a : 3; }; struct s g; ' + B + '{ trace(sizeof (g.a)); }'),
    ('D_SIZEOF_TYPE', B + '{ trace(sizeof (void)); }'),
    ('D_OFFSETOF_TYPE', B + '{ trace(offsetof(int, a)); }'),
    ('D_OFFSETOF_BITFIELD', 'struct s { int a : 3; }; ' + B + '{ trace(offsetof(struct s, a)); }'),
    ('D_TYPE_MEMBER', 'struct s { int a; }; struct s g; ' + B + '{ trace(g.b); }'),
    ('D_OP_LVAL', B + '{ 1 = 2; }'),
    ('D_OP_INT', B + '{ trace("a" % 2); }'),
    ('D_OP_ARITH', B + '{ trace("a" * 2); }'),
    ('D_OP_SCALAR', 'struct s { int a; }; struct s g; ' + B + '{ trace(!g); }'),
    ('D_OP_INCOMPAT', B + '{ trace(timestamp ? "a" : 1); }'),
    ('D_OP_SOU', B + '{ x = 1; trace(x.a); }'),
    ('D_OP_PTR', B + '{ x = 1; trace(x->a); }'),
    ('D_OP_INCOMPLETE', 'struct s; ' + B + '{ trace(((struct s *)0)->a); }'),
    ('D_OP_WRITE', B + '{ timestamp = 1; }'),
    ('D_OP_VFPTR', B + '{ x = (void *)0; x++; }'),
    ('D_CAST_INVAL', 'struct s { int a; }; struct s g; ' + B + '{ trace((int)g); }'),
    ('D_PRED_SCALAR', 'struct s { int a; }; struct s g; ' + B + '/g/ { trace(1); }'),
    ('D_STRINGOF_TYPE', 'struct s { int a; }; struct s g; ' + B + '{ trace(stringof(g)); }'),
    ('D_VAR_UNDEF', B + '{ trace(self->undef); }'),
    ('D_IDENT_UNDEF', B + '{ trace(`no_such_symbol_97); }'),
    ('D_FUNC_UNDEF', B + '{ no_such_function_97(); }'),
    ('D_FUNC_IDKIND', B + '{ trace(timestamp()); }'),
    ('D_ARR_BADREF', B + '{ this->p = (int *)0; trace(this->p[1, 2]); }'),
    ('D_ARR_LOCAL', B + '{ this->a[1] = 2; }'),
    ('D_KEY_TYPE', B + '{ a[(void)1] = 1; }'),
    ('D_REGS_IDX', B + '{ trace(uregs[-1]); }'),
    ('D_ARGS_NONE', 'int x; inline int y = args[0]; ' + B + '{ trace(1); }'),
    ('D_PDESC_INVAL', 'a:b:c:d:e:f { trace(1); }'),
    # Aggregations and actions
    ('D_AGG_FUNC', B + '{ @a = 1; }'),
    ('D_AGG_REDEF', B + '{ @a = count(); @a = sum(1); }'),
    ('D_AGG_MDIM', B + '{ @a[1][2] = count(); }'),
    ('D_AGG_NULL', B + '{ @a = count(); @a; }'),
    ('D_AGG_SCALAR', 'struct s { int a; }; struct s g; ' + B + '{ @a = sum(g); }'),
    ('D_PROTO_LEN', B + '{ @a = count(1); }'),
    ('D_PROTO_ARG', B + '{ @a = quantize(1, "a"); }'),
    ('D_LQUANT_BASETYPE', B + '{ @a = lquantize(1, timestamp, 10, 1); }'),
    ('D_LQUANT_BASEVAL', B + '{ @a = lquantize(1, 0x100000000, 0x100000001, 1); }'),
    ('D_LQUANT_LIMTYPE', B + '{ @a = lquantize(1, 0, timestamp, 1); }'),
    ('D_LQUANT_LIMVAL', B + '{ @a = lquantize(1, 0, 0x100000000, 1); }'),
    ('D_LQUANT_STEPTYPE', B + '{ @a = lquantize(1, 0, 10, "a"); }'),
    ('D_LQUANT_STEPVAL', B + '{ @a = lquantize(1, 0, 10, 0x10000); }'),
    ('D_LQUANT_MISMATCH', B + '{ @a = lquantize(1, 10, 0, 1); }'),
    ('D_LQUANT_STEPLARGE', B + '{ @a = lquantize(1, 0, 10, 20); }'),
    ('D_LQUANT_STEPSMALL', B + '{ @a = lquantize(1, 0, 0x10000 * 100, 1); }'),
    ('D_LQUANT_MATCHBASE', B + '{ @a = lquantize(1, 0, 10, 1); @a = lquantize(1, 1, 10, 1); }'),
    ('D_LQUANT_MATCHLIM', B + '{ @a = lquantize(1, 0, 10, 1); @a = lquantize(1, 0, 20, 1); }'),
    ('D_LQUANT_MATCHSTEP', B + '{ @a = lquantize(1, 0, 10, 1); @a = lquantize(1, 0, 10, 2); }'),
    ('D_LLQUANT_FACTORSMALL', B + '{ @a = llquantize(1, 1, 0, 3, 10); }'),
    ('D_LLQUANT_MAGRANGE', B + '{ @a = llquantize(1, 10, 3, 2, 10); }'),
    ('D_LLQUANT_FACTORNSTEPS', B + '{ @a = llquantize(1, 10, 0, 3, 5); }'),
    ('D_LLQUANT_FACTOREVEN', B + '{ @a = llquantize(1, 10, 0, 3, 15); }'),
    ('D_LLQUANT_MAGTOOBIG', B + '{ @a = llquantize(1, 10, 0, 30, 10); }'),
    ('D_CLEAR_PROTO', AGG + 'END { clear(); }'),
    ('D_CLEAR_AGGARG', AGG + 'END { clear(1); }'),
    ('D_NORMALIZE_PROTO', AGG + 'END { normalize(@a); }'),
    ('D_NORMALIZE_AGGARG', AGG + 'END { normalize(1, 2); }'),
    ('D_NORMALIZE_SCALAR', AGG + 'END { normalize(@a, "two"); }'),
    ('D_TRUNC_PROTO', AGG + 'END { trunc(); }'),
    ('D_TRUNC_AGGARG', AGG + 'END { trunc(1); }'),
    ('D_TRUNC_SCALAR', AGG + 'END { trunc(@a, "two"); }'),
    ('D_PRINTA_PROTO', AGG + 'END { printa("%d"); }'),
    ('D_PRINTA_AGGARG', AGG + 'END { printa(1); }'),
    ('D_PRINTA_AGGKEY', B + '{ @a[1] = count(); @b[1, 2] = count(); } END { printa(@a, @b); }'),
    ('D_PRINTA_AGGPROTO', B + '{ @a[1] = count(); @b["k"] = count(); } END { printa(@a, @b); }'),
    ('D_PRINTF_ARG_FMT', B + '{ printf(1); }'),
    ('D_PRINTF_FMT_EMPTY', B + '{ printf(""); }'),
    ('D_PRINTF_ARG_PROTO', B + '{ printf("%d %d", 1); }'),
    ('D_PRINTF_ARG_EXTRA', B + '{ printf("%d", 1, 2); }'),
    ('D_PRINTF_ARG_TYPE', B + '{ printf("%d", "text"); }'),
    ('D_PRINTF_DYN_PROTO', B + '{ printf("%*d"); }'),
    ('D_PRINTF_DYN_TYPE', B + '{ printf("%*d", "w", 1); }'),
    ('D_PRINTF_AGG_CONV', B + '{ printf("%@d", 1); }'),
    ('D_PRINT_VOID', B + '{ print((void)1); }'),
    ('D_PRINT_AGG', AGG + 'END { print(@a); }'),
    ('D_TRACEMEM_ARGS', B + '{ tracemem(arg0, 16, 8, 1); }'),
    ('D_TRACEMEM_ADDR', B + '{ tracemem(1 + "a", 16); }'),
    ('D_TRACEMEM_SIZE', B + '{ tracemem(arg0, arg1); }'),
    ('D_TRACEMEM_DYNSIZE', B + '{ tracemem(arg0, 16, "a"); }'),
    ('D_PRINTM_SIZE', B + '{ printm(arg1, (uintptr_t *)arg0); }'),
    ('D_PRINTM_ADDR', B + '{ printm(16, 0); }'),
    ('D_STACK_PROTO', B + '{ stack(1, 2); }'),
    ('D_STACK_SIZE', B + '{ stack(arg0); }'),
    ('D_USTACK_PROTO', B + '{ ustack(1, 2, 3); }'),
    ('D_USTACK_FRAMES', B + '{ ustack(arg0); }'),
    ('D_USTACK_STRSIZE', B + '{ ustack(1, arg0); }'),
    ('D_EXIT_SPEC', B + '{ speculate(1); exit(0); }'),
    ('D_SPEC_SPEC', B + '{ speculate(1); speculate(2); }'),
    ('D_SPEC_DREC', B + '{ trace(1); speculate(1); }'),
    ('D_SPEC_COMM', B + '{ commit(1); speculate(1); }'),
    ('D_COMM_COMM', B + '{ commit(1); commit(2); }'),
    ('D_COMM_DREC', B + '{ trace(1); commit(1); }'),
    ('D_DREC_COMM', B + '{ commit(1); trace(1); }'),
    ('D_AGG_SPEC', B + '{ speculate(1); @a = count(); }'),
    ('D_AGG_COMM', B + '{ commit(1); @a = count(); }'),
    ('D_ACT_SPEC', B + '{ speculate(1); chill(1); }'),
    ('D_FREOPEN_INVALID', B + '{ freopen("."); }'),
    # Pragmas
    ('D_PRAGMA_MALFORM', '#pragma D option\n' + B + '{ trace(1); }'),
    ('D_PRAGMA_OPTSET', '#pragma D option nosuchoption=1\n' + B + '{ trace(1); }'),
    ('D_PRAGMA_INVAL', '#pragma D attributes Bogus/Bogus/Bogus provider dtrace provider\n'
     + B + '{ trace(1); }'),
    ('D_PRAGMA_UNUSED', '#pragma D binding "1.0" nosuchident_97\n' + B + '{ trace(1); }'),
    ('D_PRAGMA_DEPEND', '#pragma D depends_on library nonexistent_97.d\n' + B + '{ trace(1); }'),
    ('D_PRAGERR', '#error stop here\n' + B + '{ trace(1); }'),
    ('D_PRAGCTL_INVAL', '#nosuchdirective\n' + B + '{ trace(1); }'),
    # Translators
    ('D_XLATE_REDECL', 'struct in { int a; }; struct out { int b; }; '
     'translator struct out < struct in *p > { b = p->a; }; '
     'translator struct out < struct in *p > { b = p->a; }; ' + B + '{ trace(1); }'),
    ('D_XLATE_MEMB', 'struct in { int a; }; struct out { int b; }; '
     'translator struct out < struct in *p > { c = p->a; }; ' + B + '{ trace(1); }'),
    ('D_XLATE_INCOMPAT', 'struct in { int a; }; struct out { int b; }; '
     'translator struct out < struct in *p > { b = "text"; }; ' + B + '{ trace(1); }'),
    ('D_XLATE_SOU', 'struct in { int a; }; struct out; '
     'translator struct out < struct in *p > { b = p->a; }; ' + B + '{ trace(1); }'),
    ('D_XLATE_NONE', 'struct in { int a; }; struct out { int b; }; '
     + B + '{ trace(xlate <struct out> (1)); }'),
    ('D_XLATE_NOCONV', 'struct in { int a; }; struct out { int b; int c; }; '
     'translator struct out < struct in *p > { b = p->a; }; '
     + B + '{ trace(xlate <struct out> ((struct in *)0).c); }'),
]

results = []
for tag, prog in CASES:
    err = C.c_int()
    h = lib.dtrace_open(3, 3, C.byref(err))
    assert h, err.value
    p = lib.dtrace_program_strcompile(h, prog.encode(), 4, ETAGS, 0, None)
    msg = '' if p else lib.dtrace_errmsg(h, lib.dtrace_errno(h)).decode(errors='replace')
    m = re.match(r'\[(D_[A-Z0-9_]+)\]', msg)
    got = m.group(1) if m else None
    results.append({'tag': tag, 'program': prog, 'compiled': bool(p), 'got': got,
                    'message': msg, 'passed': got == tag})
    lib.dtrace_close(h)
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): hashlib.sha256(
    p.read_bytes()).hexdigest() for p in (binary, Path(__file__).resolve())},
    'scope': 'Compiler diagnostics with DTRACE_C_ETAGS; NODEV|NOSYS'}, indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(f"{r['tag']}: got {r['got']} compiled={r['compiled']} :: {r['message'].strip()[:150]}")
if failed:
    raise SystemExit(1)
print('PASS:', len(results), 'tagged compiler diagnostics')
