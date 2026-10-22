#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""D front-end acceptance and rejection corpus (parser, grammar, lexer, decls).

Every case is a D program written for one rule of the D language (Dynamic
Tracing Guide) or of the compiler source (dt_parser.c, dt_decl.c, dt_lex.l,
dt_grammar.y, dt_xlator.c, dt_pragma.c): either it must compile, optionally
with a structural property of the result that follows from that rule, or it
must be rejected with the [D_TAG] (and, where the rule names it, the message
fragment) that the rule requires.  Programs are compiled through the actual
libdtrace (NODEV|NOSYS unless a case says otherwise) with DTRACE_C_ETAGS.
Expected values are derived from the rules, never from observed output.
"""
from pathlib import Path
import json
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend_parser as fp
from frontend_parser_cases import CASES

out, obj = fp.check_args(sys.argv, 'usage: frontend-parser-corpus.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
h = fp.Harness(out, obj)
K = fp.dif_constants()
batch, meta = [], {}
for c in CASES:
    case = {'id': c['id'], 'src': c.get('src', ''), 'flags': c.get('flags', fp.ETAGS),
            # The D system libraries are compiled only where a case asks for
            # them (libs=True); other suites cover library processing.
            'opts': c.get('opts', []) + ([] if c.get('libs') else ['nolibs']),
            'args': c.get('args', []), 'mode': c.get('mode', 'prog'),
            'keep': c.get('keep', False), 'nosrc': c.get('nosrc', False)}
    if 'oflags' in c:
        case['oflags'] = c['oflags']
    if 'libfiles' in c:
        # A private library directory with the case's D library files.
        libdir = out / ('libs-' + c['id'])
        libdir.mkdir()
        for name, text in c['libfiles'].items():
            (libdir / name).write_text(text)
        case['opts'] = [o for o in case['opts'] if o != 'nolibs'] + ['libdir=' + str(libdir)]
    if 'modules' in c:
        case['modules'] = c['modules']
    if c.get('dof'):
        case['dof'] = True
    assert c['id'] not in meta, c['id']
    meta[c['id']] = c
    batch.append(case)
shim_ids = {c['id'] for c in CASES if c.get('providers') is not None}
res = h.run([c for c in batch if c['id'] not in shim_ids])
# Cases that model the kernel provider list run with a preloaded sysctl shim.
shim = out / 'frontend-parser-shim.so'
build = subprocess.run(['cc', '-shared', '-fPIC', '-o', str(shim),
                        str(Path(__file__).with_name('frontend-parser-shim.c'))],
                       capture_output=True, text=True)
if build.returncode:
    raise SystemExit('shim build failed: ' + build.stderr)
for c in CASES:
    if c['id'] in shim_ids:
        res.update(h.run([b for b in batch if b['id'] == c['id']],
                         extra_env={'LD_PRELOAD': str(shim), 'FRONTEND_PROVIDERS': c['providers']}))
results, failed = [], []
for cid, c in meta.items():
    r = res[cid]
    exp = c['expect']
    got = fp.tag(r)
    why = None
    if r.get('open_error'):
        why = 'open failed: ' + r['open_error']
    elif exp == 'ok':
        if not r['compiled']:
            why = 'expected success: ' + (r['error'] or '')
    elif exp == 'noprog':
        # Control-line-only compilation: no program and no error.
        if r['compiled'] or 'No error' not in (r['error'] or ''):
            why = 'expected no program without error: ' + str(r['error'])
    else:
        want, sub = (exp, None) if isinstance(exp, str) else exp
        if r['compiled']:
            why = f'expected {want}, compiled'
        elif want != '*' and got != want:
            why = f'expected {want}, got {r["error"]}'
        elif sub and sub not in r['error']:
            why = f'message lacks {sub!r}: {r["error"]}'
    if why is None and 'check' in c:
        try:
            ok = c['check'](r, K)
        except (KeyError, IndexError, TypeError, ValueError, AssertionError) as e:
            ok = False
            why = f'check raised {e!r}'
        if not ok and why is None:
            why = 'structural check failed'
    rec = {'id': cid, 'src': c.get('src'), 'expect': exp if isinstance(exp, str) else list(exp),
           'compiled': r.get('compiled'), 'error': r.get('error'), 'passed': why is None}
    if why:
        rec['why'] = why
        rec['output'] = r.get('output', '')[:2000]
        failed.append(rec)
    results.append(rec)
(out / 'results.json').write_text(json.dumps(results, indent=1) + '\n')
h.provenance([__file__, Path(__file__).with_name('frontend_parser_cases.py'),
              Path(__file__).with_name('frontend-parser-shim.c')],
             'D front-end corpus: rule-derived accept/reject cases; NODEV|NOSYS')
for f in failed:
    print('FAIL', f['id'], '::', f['why'][:300])
if failed:
    raise SystemExit(f'{len(failed)} of {len(results)} corpus cases failed')
print('PASS:', len(results), 'front-end corpus cases')
