#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compare real compiler string/file APIs and harmless source transformations."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from dof_validation import validate_dof

out, binary, corpus = (Path(p).resolve() for p in sys.argv[1:])
assert all(p.is_relative_to('/usr/obj') for p in (out,binary,corpus)) and not out.exists()
out.mkdir(parents=True)
inputs = json.loads(corpus.read_text())
assert inputs and all(row['passed'] for row in inputs)
lib = C.CDLL(str(binary)); libc = C.CDLL(None)
lib.dtrace_open.argtypes = [C.c_int,C.c_int,C.POINTER(C.c_int)];lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_program_strcompile.argtypes = [C.c_void_p,C.c_char_p,C.c_int,C.c_uint,C.c_int,C.c_void_p]
lib.dtrace_program_strcompile.restype = C.c_void_p
lib.dtrace_program_fcompile.argtypes = [C.c_void_p,C.c_void_p,C.c_uint,C.c_int,C.c_void_p]
lib.dtrace_program_fcompile.restype = C.c_void_p
lib.dtrace_dof_create.argtypes = [C.c_void_p,C.c_void_p,C.c_uint];lib.dtrace_dof_create.restype = C.c_void_p
lib.dtrace_dof_destroy.argtypes = [C.c_void_p,C.c_void_p]
lib.dtrace_errno.argtypes = [C.c_void_p]
lib.dtrace_errmsg.argtypes = [C.c_void_p,C.c_int];lib.dtrace_errmsg.restype = C.c_char_p
libc.tmpfile.restype = C.c_void_p
libc.fwrite.argtypes = [C.c_void_p,C.c_size_t,C.c_size_t,C.c_void_p];libc.fwrite.restype = C.c_size_t
for name in ('fclose','rewind'):
    getattr(libc,name).argtypes = [C.c_void_p]

def canonical_dof(data):
    # dt_program.c assigns dtad_uarg = (uintptr_t)sdp, and dt_dof.c
    # serializes that statement pointer at action offset 24. Preserve zero
    # and pointer alias relationships; do not normalize any other field.
    result = bytearray(data); cookies = {}; offsets = []
    endian = '<' if data[5] == 1 else '>'
    section_size, count = struct.unpack_from(endian+'II',data,24)
    table = struct.unpack_from(endian+'Q',data,32)[0]
    for i in range(count):
        kind, alignment, flags, stride, start, size = struct.unpack_from(endian+'IIIIQQ',data,table+i*section_size)
        if kind != 5:
            continue
        assert stride == 32 and size % stride == 0
        for action in range(start,start+size,stride):
            offset = action+24; value = struct.unpack_from(endian+'Q',data,offset)[0]
            if value:
                if value not in cookies:cookies[value] = len(cookies)+1
                struct.pack_into(endian+'Q',result,offset,cookies[value])
            offsets.append(offset)
    return bytes(result), offsets

def compile_one(name,source,mode):
    error = C.c_int(); handle = lib.dtrace_open(3,3,C.byref(error)); assert handle
    stream = None
    try:
        encoded = source.encode()
        if mode == 'file':
            stream = libc.tmpfile(); assert stream
            assert libc.fwrite(encoded,1,len(encoded),stream) == len(encoded)
            libc.rewind(stream)
            program = lib.dtrace_program_fcompile(handle,stream,0x1104,0,None)
        else:
            program = lib.dtrace_program_strcompile(handle,encoded,4,0x1104,0,None)
        diagnostic = lib.dtrace_errmsg(handle,lib.dtrace_errno(handle)).decode(errors='replace') if not program else ''
        tag = re.search(r'\[D_[A-Z0-9_]+\]',diagnostic)
        data = None; canonical = None; offsets = []
        if program:
            dof = lib.dtrace_dof_create(handle,program,1); assert dof
            try:
                size = C.c_uint64.from_address(dof+48).value
                assert 64 <= size <= 64*1024*1024
                data = C.string_at(dof,size);validate_dof(data)
                (out/(name+'.dof')).write_bytes(data)
                canonical, offsets = canonical_dof(data)
                (out/(name+'.canonical.dof')).write_bytes(canonical)
            finally:
                lib.dtrace_dof_destroy(handle,dof)
        return dict(compiled=bool(program),diagnostic=diagnostic,tag=tag.group(0) if tag else None,
            dof_sha256=hashlib.sha256(data).hexdigest() if data is not None else None,
            canonical_sha256=hashlib.sha256(canonical).hexdigest() if canonical is not None else None,
            action_cookie_offsets=offsets)
    finally:
        if stream:libc.fclose(stream)
        lib.dtrace_close(handle)

results = []
for item in inputs:
    name,source,expected = item['case'],item['source'],item['expected_compile']
    versions = {}
    for transform,text in [('original',source),('comment-prefix','/* differential test */\n\n'+source)]:
        for mode in ('string','file'):
            key = transform+'-'+mode
            versions[key] = compile_one(name+'-'+key,text,mode)
    passed = all(v['compiled'] == expected for v in versions.values())
    if expected:
        passed = passed and len({v['canonical_sha256'] for v in versions.values()}) == 1
    else:
        passed = passed and all(v['tag'] for v in versions.values()) and len({v['tag'] for v in versions.values()}) == 1
        required = item.get('required_diagnostic')
        if required:passed = passed and all(required in v['diagnostic'] for v in versions.values())
    results.append(dict(case=name,source=source,expected_compile=expected,versions=versions,passed=passed))
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()
    for p in (binary,corpus,Path(__file__).resolve(),Path(__file__).with_name('dof_validation.py').resolve())},
    'scope':'NODEV/NOSYS; no preprocessing or system libraries; temporary FILE streams'},indent=2)+'\n')
failed = [r for r in results if not r['passed']]
for r in failed:print(json.dumps(r))
print('Compared',len(results),'programs through four compilation paths;',len(failed),'failures')
raise SystemExit(bool(failed))
