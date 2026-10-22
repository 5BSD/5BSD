#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise public compiler API modes with NODEV/NOSYS and no system libraries."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
from dof_validation import validate_dof

out, binary = (Path(s).resolve() for s in sys.argv[1:])
if not out.is_relative_to('/usr/obj') or not binary.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('Use an existing /usr/obj library and new /usr/obj output')
out.mkdir(parents=True)
lib = C.CDLL(str(binary))
class TypeInfo(C.Structure):
    _fields_ = [('object', C.c_void_p), ('ctfp', C.c_void_p),
        ('type', C.c_long), ('flags', C.c_uint), ('copied', C.c_int)]
lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_setopt.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
lib.dtrace_type_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.POINTER(TypeInfo)]
lib.ctf_type_size.argtypes = [C.c_void_p, C.c_long]
lib.ctf_type_size.restype = C.c_ssize_t
lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.c_uint, C.c_int, C.POINTER(C.c_char_p)]
lib.dtrace_program_strcompile.restype = C.c_void_p
lib.dtrace_errno.argtypes = [C.c_void_p]
lib.dtrace_errmsg.argtypes = [C.c_void_p, C.c_int]
lib.dtrace_errmsg.restype = C.c_char_p
lib.dtrace_dof_create.argtypes = [C.c_void_p, C.c_void_p, C.c_uint]
lib.dtrace_dof_create.restype = C.c_void_p
lib.dtrace_dof_destroy.argtypes = [C.c_void_p, C.c_void_p]

def open_handle():
    error = C.c_int()
    h = lib.dtrace_open(3, 3, C.byref(error))
    assert h, error.value
    assert lib.dtrace_setopt(h, b'nolibs', None) == 0
    return h

results = []
for source, expected_size in [('char',1), ('short',2), ('int',4),
    ('long long',8), ('uint64_t',8), ('int *',C.sizeof(C.c_void_p)),
    ('int [4]',16), ('const unsigned int',4), ('unknown_api_type',None),
    ('int [',None), (None,None)]:
    h = open_handle()
    try:
        info = TypeInfo()
        rc = lib.dtrace_type_strcompile(h, source.encode() if source else None, C.byref(info))
        diagnostic = lib.dtrace_errmsg(h, lib.dtrace_errno(h)).decode(errors='replace') if rc else ''
        actual_size = lib.ctf_type_size(info.ctfp, info.type) if rc == 0 else None
        passed = (rc == 0 and actual_size == expected_size) if expected_size is not None else (rc == -1 and bool(diagnostic))
        results.append({'mode':'type','source':source,'expected_size':expected_size,
            'size':actual_size,'status':rc,'diagnostic':diagnostic,'passed':passed})
    finally:
        lib.dtrace_close(h)

# Bit values are the public DTRACE_C_* definitions in dtrace.h.
for name, source, extra, args, expected in [
    ('empty-rejected','',0,[],False), ('empty-allowed','',2,[],True),
    ('null-source',None,0,[],False), ('unknown-flag','BEGIN { trace(1); }',0x4000,[],False),
    ('numeric-macro','BEGIN { trace($1); }',0,['fixture','42'],True),
    ('missing-macro','BEGIN { trace($1); }',0,['fixture'],False),
    ('default-macro','BEGIN { trace($1); }',0x800,['fixture'],True),
    ('unused-macro','BEGIN { trace(1); }',0,['fixture','42'],False),
    ('unused-macro-allowed','BEGIN { trace(1); }',0x200,['fixture','42'],True),
    ('tagged-error','BEGIN { trace(1 + ); }',0x100,[],False),
]:
    h = open_handle()
    try:
        argv = (C.c_char_p * len(args))(*(a.encode() for a in args)) if args else None
        program = lib.dtrace_program_strcompile(h,source.encode() if source is not None else None,4,0x1004|extra,len(args),argv)
        diagnostic = lib.dtrace_errmsg(h,lib.dtrace_errno(h)).decode(errors='replace') if not program else ''
        required = {
            'empty-rejected':'empty D program', 'null-source':'Invalid argument',
            'unknown-flag':'Invalid argument', 'missing-macro':'macro argument $1 is not defined',
            'unused-macro':'extraneous argument', 'tagged-error':'[D_SYNTAX]',
        }.get(name)
        passed = bool(program)==expected and (expected or bool(diagnostic))
        if required: passed = passed and required in diagnostic
        dof_summary = None
        if program:
            dof = lib.dtrace_dof_create(h,program,1)
            assert dof
            try:
                size = C.c_uint64.from_address(dof+48).value
                assert 64 <= size <= 64*1024*1024
                data = C.string_at(dof,size)
                dof_summary = validate_dof(data)
                (out/(name+'.dof')).write_bytes(data)
            finally:
                lib.dtrace_dof_destroy(h,dof)
        results.append({'mode':'program','case':name,'source':source,'flags':0x1004|extra,
            'args':args,'expected_compile':expected,'compiled':bool(program),
            'diagnostic':diagnostic,'dof':dof_summary,'passed':passed})
    finally:
        lib.dtrace_close(h)
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'binary':str(binary),
    'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in
        (binary,Path(__file__),Path(__file__).with_name('dof_validation.py'))},
    'scope':'Public type/program compilation only; NODEV/NOSYS, nolibs'},indent=2)+'\n')
failed = [r for r in results if not r['passed']]
for r in failed: print(json.dumps(r))
if failed: raise SystemExit(1)
print('PASS:',len(results),'compiler API mode cases')
