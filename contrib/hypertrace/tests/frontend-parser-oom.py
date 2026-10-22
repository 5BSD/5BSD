#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Allocation-failure sweep over the D front end (parser, lexer, declarations,
pragmas, translators, providers).

Uses the frontend-codegen.c driver and the frontend-codegen-oom-shim.so
injector (see frontend-codegen-oom.py): for each program every allocation
request made during compilation is failed in turn.  Requirements: no crash;
each run either fails with a reported error or compiles to exactly the
fault-free program; the error for an injected failure is the documented
"Memory allocation failure" (EDT_NOMEM), or a failure libctf reports for
its own allocation failure (libctf sets EAGAIN, "Resource temporarily
unavailable", when ctf_alloc() fails; dt_decl.c/dt_parser.c pass that message
through), or -- for a failed pointer-type creation while a translator is
defined -- the missing pointer translation that dt_xlator_create() records
(it treats an uncreatable "T *" as "no translation to T *").  The programs are chosen to drive
the allocation sites of dt_parser.c, dt_lex.l, dt_decl.c, dt_pragma.c and
dt_xlator.c: string/identifier tokens, macro arguments, declarations of
every kind, inline arrays, enums, providers, translators, pragmas.
"""
import json
import subprocess
import sys
from pathlib import Path
from frontend_codegen_common import check_args, build, env_for, finish, TESTS

out, obj = check_args(sys.argv, 'world')
exe = build(out, obj, 'frontend-codegen.c', sanitize=False, extra=['-DFCG_NOSAN'])
shim = out / 'frontend-codegen-oom-shim.so'
r = subprocess.run(['cc', '-shared', '-fPIC', '-O1', '-g', '-o', str(shim),
                    str(TESTS / 'frontend-codegen-oom-shim.c')], capture_output=True, text=True)
if r.returncode:
    raise SystemExit('shim build failed: ' + r.stderr)
XL = ('struct xin { int a; }; struct xout { int b; long c; }; '
      'translator struct xout < struct xin *p > { b = p->a; c = 2; }; ')
CASES = [
    ('decls', 0, [], 'typedef unsigned long ul_t; struct s { int a : 3; ul_t b; char c[4]; }; '
     'union u { int a; long b; }; enum e { EA = 1, EB, EC = EA + 5 }; struct s gs; int ga[3]; '
     'struct fwd97 *fwp;\n# 1 "h.h" 1\nstruct cm { int a; };\n# 2 "p.d" 2\n'
     'int gx[int, string]; self int sx; this int tx; extern int ex; int (*fp)(int, ...); '
     'BEGIN { trace(gs.b + EB + sizeof (union u) + offsetof(struct s, c)); }'),
    ('inlines', 0, [], 'inline int K = 3; inline int sq[int x, int y] = x * y + K; '
     'inline string S = "zz"; BEGIN { trace(sq[2, 3]); trace(S); }'),
    ('strings', 0, [], 'BEGIN { trace("esc\\t\\n\\x41"); trace(\'ab\'); s = "x"; trace(s); '
     'trace($pid); trace($$pid); @[probefunc] = count(); @agg97 = sum(1); }'),
    ('translators', 0, [], XL + 'BEGIN { trace(xlate <struct xout> ((struct xin *)arg0).b); '
     'trace(xlate <struct xout *> ((struct xin *)arg0)->c); }'),
    ('dyn-xlate', 0, ['xlate=dynamic'], XL + 'BEGIN { trace(xlate <struct xout> ((struct xin *)arg0).b); }'),
    ('providers', 0, [], 'provider pa { probe ev(int x, char *s) : (char *s, int x); probe ev2(); }; '
     'provider pa { probe ev(int x, char *s) : (char *s, int x); probe ev2(); }; BEGIN { trace(1); }'),
    ('pragmas', 0, [], '#pragma D option quiet\n#pragma D attributes Evolving/Evolving/Common xx\n'
     '#pragma D binding "1.0" yy\n#line 20 "file.d"\n# 1 "h.h" 1\nstruct hh { int a; };\n'
     '# 22 "file.d" 2\ninline int xx = 1; inline int yy = 2;\nBEGIN { trace(xx + yy); }'),
    ('clauses', 0, [], 'BEGIN /arg0/ { if (arg1) { trace(1); } else { trace(2); } } END { exit(0); }'),
    ('typestring', 0, ['type'], 'struct { int a; long b; } *'),
    ('file', 0, ['file'], '#!/usr/sbin/dtrace -s\nBEGIN { trace(1); }\n'),
]
text = [f"@@case {n} {c:x} 4 {','.join(o) or '-'}\n{p}" for n, c, o, p in CASES]
(out / 'cases.txt').write_text('\n'.join(text) + '\n')
(out / 'tmp').mkdir()
env = env_for(obj)
env.pop('ASAN_OPTIONS', None)
env['LD_PRELOAD'] = str(shim)
run = subprocess.run([str(exe), str(out / 'cases.txt'), str(out / 'cases.jsonl'), str(out / 'tmp')],
                     env=env, capture_output=True, text=True, timeout=7200, cwd=out)
(out / 'run.log').write_text(run.stdout + run.stderr[-200000:])
got = {}
for line in (out / 'cases.jsonl').read_text().splitlines():
    d = json.loads(line)
    got[d['case']] = d
results = []
for name, *_ in CASES:
    d = got.get(name)
    if d is None:
        results.append({'case': name, 'passed': False, 'note': 'no result'})
        continue
    # The driver keeps each message up to its first embedded quote, so a
    # message prefixed with a quoted file tag ("h.h", line N: ...) is
    # recorded as just that tag; the case lists the tags it expects.
    others = [o for o in d.get('others', '').split('";') if o.strip('"; ')]
    bad = [o for o in others if 'Resource temporarily unavailable' not in o and
           not (name in ('pragmas', 'decls') and o.strip('"\\') == 'h.h') and
           not (name in ('translators', 'dyn-xlate') and 'cannot translate from' in o)]
    ok = ('crash' not in d and d['baseline_ok'] == 1 and d['requests'] > 0 and d['differ'] == 0
          and d['firstdiff'] == 0 and not bad and d['nomem'] + d['other'] + d['same'] == d['requests'])
    d['unaccepted_others'] = bad
    results.append(dict(d, passed=ok))
if run.returncode:
    results.append({'case': 'driver-exit', 'passed': False, 'note': run.returncode})
finish(out, results, [Path(__file__), TESTS / 'frontend-codegen.c', TESTS / 'frontend-codegen-oom-shim.c',
                      TESTS / 'frontend_codegen_common.py', obj / 'cddl/lib/libdtrace/libdtrace.so.2'],
       'Allocation-failure sweep over the D front end (preloaded injector); NOSYS dtrace_vopen model',
       'front-end allocation-failure sweeps')
