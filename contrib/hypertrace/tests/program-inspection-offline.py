#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check program metadata and statement iteration without enabling probes."""
import ctypes as C
import hashlib
import json
import random
from pathlib import Path
import sys
import subprocess

out,binary = (Path(p).resolve() for p in sys.argv[1:])
assert all(p.is_relative_to('/usr/obj') for p in (out,binary)) and not out.exists()
out.mkdir(parents=True)
lib = C.CDLL(str(binary))
class Attribute(C.Structure):
    _fields_ = [('name',C.c_uint8),('data',C.c_uint8),('dependency',C.c_uint8)]
class Info(C.Structure):
    _fields_ = [('description',Attribute),('statement',Attribute),('aggregates',C.c_uint),
        ('records',C.c_uint),('matches',C.c_uint),('speculations',C.c_uint),('probes',C.c_void_p)]
# Verify ctypes layout against a C compiler using the source-tree API.
root = Path(__file__).resolve().parents[3]
abi_source = out/'inspection-abi.c'
abi_source.write_text('#include <stddef.h>\n#include <stdio.h>\n#include <dtrace.h>\nint main(void) {\n' +
    'printf("%zu %zu", sizeof(dtrace_attribute_t), sizeof(dtrace_proginfo_t));\n' +
    ''.join('printf(" %zu", offsetof(dtrace_proginfo_t, '+field+'));\n' for field in
        ('dpi_descattr','dpi_stmtattr','dpi_aggregates','dpi_recgens','dpi_matches','dpi_speculations','dpi_pds')) +
    'puts(""); return 0; }\n')
include_dirs = ('sys/cddl/compat/opensolaris','cddl/compat/opensolaris/include',
    'sys/cddl/contrib/opensolaris/uts/common','sys',
    'cddl/contrib/opensolaris/lib/libdtrace/common',
    'cddl/contrib/opensolaris/lib/libctf/common','lib/librtld_db')
subprocess.run(['/usr/bin/cc',*[arg for directory in include_dirs for arg in ('-I',str(root/directory))],
    str(abi_source),'-o',str(out/'inspection-abi')],check=True)
actual_layout = list(map(int,subprocess.check_output([str(out/'inspection-abi')],text=True).split()))
expected_layout = [C.sizeof(Attribute),C.sizeof(Info)] + [getattr(Info,name).offset for name,_ in Info._fields_]
(out/'abi.json').write_text(json.dumps(dict(actual=actual_layout,ctypes=expected_layout))+'\n')
assert actual_layout == expected_layout
Callback = C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p)
lib.dtrace_open.argtypes = [C.c_int,C.c_int,C.POINTER(C.c_int)];lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_program_strcompile.argtypes = [C.c_void_p,C.c_char_p,C.c_int,C.c_uint,C.c_int,C.c_void_p]
lib.dtrace_program_strcompile.restype = C.c_void_p
lib.dtrace_program_info.argtypes = [C.c_void_p,C.c_void_p,C.POINTER(Info)];lib.dtrace_program_info.restype = None
lib.dtrace_stmt_iter.argtypes = [C.c_void_p,C.c_void_p,Callback,C.c_void_p]
lib.dtrace_errno.argtypes = [C.c_void_p]
lib.dtrace_errmsg.argtypes = [C.c_void_p,C.c_int];lib.dtrace_errmsg.restype = C.c_char_p
# Expectations: statements, aggregations, records, speculations.
cases = [
    ('empty','',(0,0,0,0)),
    ('bare-probe','BEGIN',(1,0,1,0)),
    ('empty-clause','BEGIN { }',(1,0,1,0)),
    ('trace','BEGIN { trace(1); }',(1,0,1,0)),
    ('two-statements','BEGIN { trace(1); trace(2); }',(2,0,2,0)),
    ('two-clauses','BEGIN { trace(1); } END { trace(2); }',(2,0,2,0)),
    ('assignment','BEGIN { x = 1; }',(1,0,0,0)),
    ('aggregation','BEGIN { @a = count(); }',(1,1,0,0)),
    ('keyed-aggregation','BEGIN { @a[1, 2] = count(); }',(1,1,0,0)),
    ('linear-aggregation','BEGIN { @a = lquantize(4, 10, 20, 2); }',(1,1,0,0)),
    ('log-aggregation','BEGIN { @a = llquantize(4, 2, 1, 3, 2); }',(1,1,0,0)),
    ('weighted-aggregation','BEGIN { @a = quantize(4, 3); }',(1,1,0,0)),
    ('weighted-keyed','BEGIN { @a[1, 2] = quantize(4, 3); }',(1,1,0,0)),
    ('mixed-aggregation','BEGIN { trace(7); @a[1] = count(); trace(8); @b = quantize(4, 3); }',(4,2,2,0)),
    ('speculation','BEGIN { speculate(1); trace(2); }',(2,0,1,1)),
    ('destructive-compile-only','BEGIN { stop(); }',(1,0,0,0)),
]
# Model-generated statement sequences: aggregate tuples never contribute
# ordinary records, regardless of neighboring actions or clause boundaries.
rng = random.Random(0x5b5d1f0)
for sample in range(32):
    actions = []; aggregates = records = speculations = 0
    for index in range(rng.randrange(2,13)):
        kind = rng.randrange(7)
        if kind == 0:
            actions.append('trace('+str(index)+');');records += 1
        elif kind == 1:
            actions.append('x = '+str(index)+';')
        elif kind == 2:
            actions.append('stop();')
        elif kind == 3:
            actions.append('x += 1;')
        else:
            name = '@a'+str(index)
            expression = ('count()' if kind == 4 else
                'quantize(4, 3)' if kind == 5 else 'lquantize(4, 10, 20, 2)')
            key = '[1, 2]' if rng.randrange(2) else ''
            actions.append(name+key+' = '+expression+';');aggregates += 1
    split = rng.randrange(1,len(actions))
    source = 'int x; BEGIN { '+' '.join(actions[:split])+' } END { '+' '.join(actions[split:])+' }'
    statements = len(actions)
    if sample % 4 == 0:
        # Speculation must precede recording, and aggregates/destructive
        # actions cannot follow it in the same clause.
        source += ' BEGIN { speculate(1); trace(17); }'
        statements += 2;records += 1;speculations += 1
    cases.append(('sequence-'+str(sample),source,(statements,aggregates,records,speculations)))
results = []
for name,source,expected in cases:
    error = C.c_int();handle = lib.dtrace_open(3,3,C.byref(error));assert handle
    try:
        program = lib.dtrace_program_strcompile(handle,source.encode(),4,0x1006,0,None)
        if not program:
            results.append(dict(case=name,passed=False,error=lib.dtrace_errmsg(handle,lib.dtrace_errno(handle)).decode()));continue
        info = Info();C.memset(C.byref(info),0xa5,C.sizeof(info))
        lib.dtrace_program_info(handle,program,C.byref(info))
        lib.dtrace_program_info(handle,program,None)
        sentinel = C.c_uint64(0x5b5d2026); callback_errors = []
        def iterate(stop_after,status):
            seen = []
            @Callback
            def callback(h,p,statement,data):
                if h != handle or p != program or not statement or data != C.addressof(sentinel):
                    callback_errors.append('callback identity mismatch');return -99
                if C.cast(data,C.POINTER(C.c_uint64)).contents.value != 0x5b5d2026:
                    callback_errors.append('callback data mismatch');return -99
                seen.append(statement)
                return status if len(seen) == stop_after else 0
            rc = lib.dtrace_stmt_iter(handle,program,callback,C.byref(sentinel))
            return rc,seen
        rc,all_statements = iterate(0,0)
        actual = (len(all_statements),info.aggregates,info.records,info.speculations)
        checks = [rc == 0,len(set(all_statements)) == len(all_statements),actual == expected,
            info.matches == 0,info.probes is None]
        iterations = []
        for stop_after in sorted(set((1,max(1,len(all_statements)),len(all_statements)+1))):
            for status in (7,-3):
                rc,seen = iterate(stop_after,status)
                expected_rc = status if len(all_statements) >= stop_after else 0
                passed = rc == expected_rc and seen == all_statements[:stop_after]
                checks.append(passed);iterations.append(dict(stop_after=stop_after,status=status,
                    returned=rc,callbacks=len(seen),passed=passed))
        rc,again = iterate(0,0);checks.append(rc == 0 and again == all_statements)
        results.append(dict(case=name,source=source,expected=expected,actual=actual,
            iterations=iterations,callback_errors=callback_errors,passed=all(checks) and not callback_errors))
    finally:
        lib.dtrace_close(handle)
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()
    for p in (binary,Path(__file__).resolve(),abi_source,root/'cddl/contrib/opensolaris/lib/libdtrace/common/dtrace.h',root/'sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h')},'scope':'NODEV/NOSYS compilation, metadata and callbacks only; no program_exec'},indent=2)+'\n')
for row in results:
    if not row['passed']:print(json.dumps(row))
print('Program inspection:',len(results),'cases;',sum(not r['passed'] for r in results),'failures')
raise SystemExit(not all(r['passed'] for r in results))
