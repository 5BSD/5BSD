#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Scoped type names: module`type with multi-word C base types and '-' modules.

dt_pid.c and dt_provider.c pass ctf_type_qname() output such as
"userland pid123`sshd-session`unsigned short" to dtrace_type_strcompile().
The name must denote the C base type named after the scope, looked up in
that module's CTF, with the size the C compiler gives that type (oracle:
cc sizeof), and the unscoped grammar must be unchanged: subtraction "a-b",
"x-1", "a->b" and symbol arithmetic still parse as expressions.  Modules
with '-' are modelled offline as loaded dt_module_t's with in-memory CTF
(frontend-parser.c @module); "D" and "C" are libdtrace's own containers.
"""
from pathlib import Path
import json
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend_parser as fp

out, obj = fp.check_args(sys.argv, 'usage: frontend-parser-scoped.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
BASE = ['unsigned short', 'unsigned long long', 'unsigned char', 'unsigned int', 'short',
        'long long', 'unsigned long', 'signed char', 'char', 'long', 'int', 'unsigned']
src = out / 'sizes.c'
src.write_text('#include <stdio.h>\nint main(void) {\n' + ''.join(
    f'printf("%zu %d\\n", sizeof ({t}), ({t})-1 < 0);\n' for t in BASE) + 'return 0; }\n')
subprocess.run(['cc', '-o', str(out / 'sizes'), str(src)], check=True)
csz = {t: tuple(map(int, l.split())) for t, l in zip(BASE, subprocess.run(
    [str(out / 'sizes')], capture_output=True, text=True, check=True).stdout.splitlines())}
h = fp.Harness(out, obj)
cases, expect = [], {}
for scope, mods in [('D', []), ('C', []), ('sshd-session', ['sshd-session']),
                    ('a-b-c', ['a-b-c'])]:
    # The synthetic modules hold the canonical CTF base type names (as
    # ctfconvert emits them); "unsigned" alone is a D container alias.
    for t in BASE if not mods else [b for b in BASE if b != 'unsigned']:
        for pre in ('', 'userland '):
            cid = f'type:{pre}{scope}`{t}'
            cases.append({'id': cid, 'src': f'{pre}{scope}`{t}', 'mode': 'type', 'modules': mods})
            expect[cid] = ('type', t, bool(pre))
    cid = f'ptr:{scope}`unsigned short *'
    cases.append({'id': cid, 'src': f'{scope}`unsigned short *', 'mode': 'type', 'modules': mods})
    expect[cid] = ('ptr', 'unsigned short', False)
# Program text: scoped base types in casts and declarations; '-' stays an operator.
progs = {
    'cast-scoped-multiword': ('BEGIN { trace(sizeof ((D`unsigned short)arg0)); }', 2),
    'decl-scoped-multiword': ('D`unsigned long long g97; BEGIN { trace(sizeof (g97)); }', 8),
    'scoped-then-ident': ('D`unsigned short_count97; BEGIN { trace(sizeof (short_count97)); }', 4),
    'sub-idents': ('BEGIN { a = 7; b = 2; trace(a-b); }', None),
    'sub-const': ('BEGIN { x = 7; trace(x-1); }', None),
    'arrow': ('struct s { int b; }; BEGIN { this->a = (struct s *)arg0; trace(this->a->b); }', None),
    'sub-cast': ('BEGIN { a = 7; trace(a-(D`unsigned short)1); }', None),
    'scoped-struct-tag': ('struct st97 { int a; long b; }; BEGIN { trace(sizeof (D`struct st97)); }', 16),
    'scoped-struct-noname': ('BEGIN { trace(sizeof (D`struct)); }', None),
}
for cid, (s, _) in progs.items():
    cases.append({'id': cid, 'src': s})
cases.append({'id': 'sub-scoped-symbol', 'src': 'BEGIN { a = 7; trace(a-`ticks); }'})
cases.append({'id': 'dash-not-scope', 'src': 'char [9-1]', 'mode': 'type'})
cases.append({'id': 'dash-unknown-module', 'src': 'no-such-mod97`int', 'mode': 'type'})
res = h.run(cases)
results, failed = [], []
for c in cases:
    r = res[c['id']]
    ok, why = True, ''
    if c['id'] in expect:
        kind, t, user = expect[c['id']]
        ty = r.get('type')
        size, signed = csz[t]
        if not r['compiled']:
            ok, why = False, r['error']
        elif kind == 'type':
            ok = (ty['kind'] == 1 and ty['size'] == size and bool(ty['enc'][0] & 1) == bool(signed)
                  and ty['flags'] == (1 if user else 0))
        else:
            ok = ty['kind'] == 3 and ty['size'] == 8 and ty['ref'] == t
    elif c['id'] == 'scoped-struct-noname':
        ok = not r['compiled']
    elif c['id'] in progs:
        want = progs[c['id']][1]
        ok = r['compiled']
        if ok and want is not None:
            d = r['stmts'][-1]['acts'][-1]['difo']
            ok = int(d['ints'][0]) == want
        why = r.get('error') or ''
    elif c['id'] == 'sub-scoped-symbol':
        # a - kernel`ticks: the symbol is resolved (no types offline), so the
        # '-' was taken as subtraction, not as part of a module name.
        ok = fp.tag(r) == 'D_SYM_NOTYPES' and 'kernel`ticks' in r['error']
    elif c['id'] == 'dash-not-scope':
        ok = r['compiled'] and r['type']['nelems'] == 8
    elif c['id'] == 'dash-unknown-module':
        ok = not r['compiled']
    results.append({'id': c['id'], 'src': c['src'], 'passed': ok, 'error': r.get('error'),
                    'type': r.get('type')})
    if not ok:
        failed.append((c['id'], why or json.dumps(r)[:300]))
(out / 'results.json').write_text(json.dumps({'c_sizes': csz, 'cases': results}, indent=1) + '\n')
h.provenance([__file__], 'scoped type names (module`base type, modules with -); NODEV|NOSYS, synthetic modules')
for f in failed:
    print('FAIL', *f)
if failed:
    raise SystemExit(f'{len(failed)} of {len(results)} scoped-name cases failed')
print('PASS:', len(results), 'scoped type-name cases')
