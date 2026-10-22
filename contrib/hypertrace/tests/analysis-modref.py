#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Program analysis APIs in dt_analysis.c through the actual libdtrace.

dtrace_analyze_program_modref() classifies each action of a compiled
program.  Expected bits follow the documented rules: variable accesses come
from the DIFO variable table (global, thread-local, clause-local; MOD for
stores, REF for loads), any subroutine call is DTRACE_MODREF_ALL, and
non-DIF actions use the fixed classification (printf none; exit/tracemem
memory-mod; ustack memory ref+mod; speculate state ref+mod; stack and other
kernel actions ALL).  The callback also receives the cumulative bits of the
preceding actions.  dtrace_graph_program() must emit a Graphviz digraph
with each clause's variable stores and loads as edges, and dtrace_dump_actions() one "ACTION RETURNS" block per
action.  NODEV|NOSYS; no device.
"""
from pathlib import Path
import ctypes as C
import hashlib
import json
import os
import sys
import tempfile

out, binary = (Path(x).resolve() for x in sys.argv[1:])
if not out.is_relative_to('/usr/obj') or not binary.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('usage: analysis-modref.py /usr/obj/new-output /usr/obj/.../libdtrace.so.2')
out.mkdir(parents=True)
lib = C.CDLL(str(binary))
libc = C.CDLL(None)
lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.c_uint,
                                          C.c_int, C.c_void_p]
lib.dtrace_program_strcompile.restype = C.c_void_p
CHECK = C.CFUNCTYPE(C.c_bool, C.c_int, C.c_int, C.c_void_p, C.c_void_p)
lib.dtrace_analyze_program_modref.argtypes = [C.c_void_p, CHECK, C.c_void_p]
lib.dtrace_analyze_program_modref.restype = C.c_bool
lib.dtrace_graph_program.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
lib.dtrace_dump_actions.argtypes = [C.c_void_p]
lib.dtrace_dump_ecbs.argtypes = [C.c_void_p]
lib.dtrace_errmsg.argtypes = [C.c_void_p, C.c_int]
lib.dtrace_errmsg.restype = C.c_char_p
lib.dtrace_errno.argtypes = [C.c_void_p]
libc.fopen.argtypes = [C.c_char_p, C.c_char_p]
libc.fopen.restype = C.c_void_p
libc.fclose.argtypes = [C.c_void_p]
libc.fflush.argtypes = [C.c_void_p]

GM, GR, TM, TR, CM, CR, MM, MR, SM, SR = (1 << i for i in range(10))
ALL = (1 << 10) - 1
CASES = [
    ('constant', 'BEGIN { trace(1); }', [0]),
    ('global-store', 'BEGIN { x = 1; }', [GM]),
    ('global-load-after-store', 'BEGIN { x = 1; } END { trace(x); }', [GM, GR]),
    ('thread-store', 'BEGIN { self->t = 1; }', [TM]),
    ('clause-store-load', 'BEGIN { this->c = 1; trace(this->c); }', [CM, CR]),
    ('printf', 'BEGIN { printf("x"); }', [0]),
    ('exit', 'BEGIN { exit(0); }', [MM]),
    ('ustack', 'BEGIN { ustack(); }', [MR | MM]),
    ('speculate', 'BEGIN { speculate(1); trace(1); }', [SR | SM, 0]),
    ('subroutine', 'BEGIN { trace(strlen("ab")); }', [ALL]),
    ('stack', 'BEGIN { stack(); }', [ALL]),
]

results = []
for name, prog, want in CASES:
    err = C.c_int()
    h = lib.dtrace_open(3, 3, C.byref(err))
    p = lib.dtrace_program_strcompile(h, prog.encode(), 4, 0, 0, None)
    if not p:
        results.append({'case': name, 'passed': False,
                        'error': lib.dtrace_errmsg(h, lib.dtrace_errno(h)).decode()})
        lib.dtrace_close(h)
        continue
    seen = []

    def cb(modref, cumulative, desc, output, seen=seen):
        seen.append((modref, cumulative))
        return True
    ok = lib.dtrace_analyze_program_modref(p, CHECK(cb), None)
    got = [m for m, _ in seen]
    cumulative_ok = all(c == (0 if i == 0 else
                              __import__('functools').reduce(lambda a, b: a | b, got[:i]))
                        for i, (_, c) in enumerate(seen))
    # A rejecting check makes the whole analysis fail.
    rejected = lib.dtrace_analyze_program_modref(p, CHECK(lambda *a: False), None)
    results.append({'case': name, 'program': prog, 'want': want, 'got': got,
                    'cumulative_ok': cumulative_ok, 'passed': ok and got == want and
                    cumulative_ok and not rejected})
    lib.dtrace_close(h)

# Graph and dumps for a two-clause program.
err = C.c_int()
h = lib.dtrace_open(3, 3, C.byref(err))
p = lib.dtrace_program_strcompile(
    h, b'BEGIN { x = 1; trace(x); } END { trace(x); printf("%d", x); exit(0); }',
    4, 0, 0, None)
dot_path = out / 'graph.dot'
fp = libc.fopen(str(dot_path).encode(), b'w')
lib.dtrace_graph_program(h, p, fp)
libc.fclose(fp)
dot = dot_path.read_text()
# Only DIF expressions are graphed (printf/exit are upstream TODOs): each
# clause's store or load of x appears as an edge.
results.append({'case': 'graph', 'passed': dot.lstrip().startswith('digraph') and
                dot.rstrip().endswith('}') and '":::BEGIN" -> "x"' in dot and
                '"x" -> ":::BEGIN"' in dot and '"x" -> ":::END"' in dot,
                'head': dot[:300]})
dump_path = out / 'dump.txt'
saved = os.dup(2)
fd = os.open(dump_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.dup2(fd, 2)
lib.dtrace_dump_actions(p)
lib.dtrace_dump_ecbs(p)
libc.fflush(None)
os.dup2(saved, 2)
os.close(fd)
dump = dump_path.read_text(errors='replace')
results.append({'case': 'dump-actions', 'passed': dump.count('ACTION RETURNS') >= 4,
                'blocks': dump.count('ACTION RETURNS')})
lib.dtrace_close(h)

(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(x): hashlib.sha256(
    x.read_bytes()).hexdigest() for x in (binary, Path(__file__).resolve())},
    'scope': 'dt_analysis.c public APIs; NODEV|NOSYS'}, indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r)[:800])
if failed:
    raise SystemExit(1)
print('PASS:', len(results), 'program analysis cases')
