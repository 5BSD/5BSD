#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual-library malformed histogram tests, each isolated behind a guard page."""
import ctypes as C
import hashlib
import json
import mmap
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys

header = (2 << 48) | (1 << 32) | (2 << 16) | 2
cases = {
    'header-only': struct.pack('<Q', header),
    'one-zero-count': struct.pack('<Qq', header, 0),
    'missing-overflow': struct.pack('<Q3q', header, 0, 0, 0),
    'extra-count': struct.pack('<Q5q', header, 0, 0, 0, 0, 1),
    'partial-count': struct.pack('<Q4q', header, 0, 0, 0, 0) + b'x',
    'nondividing-steps': struct.pack('<Q4q', (3 << 48) | (1 << 32) | (2 << 16) | 4, 0, 0, 0, 0),
    'steps-not-power-divisor': struct.pack('<Q4q', (2 << 48) | (1 << 32) | (2 << 16) | 6, 0, 0, 0, 0),
    'overflow-low': struct.pack('<Q4q', (2 << 48) | (63 << 32) | (64 << 16) | 2, 0, 0, 0, 0),
    'overflow-high': struct.pack('<Q4q', (2 << 48) | (1 << 32) | (63 << 16) | 2, 0, 0, 0, 0),
}
if sys.argv[1] == '--case':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    lib = C.CDLL(sys.argv[2]); libc = C.CDLL(None)
    lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
    lib.dtrace_open.restype = C.c_void_p
    lib.dtrace_close.argtypes = [C.c_void_p]
    lib.dt_print_llquantize.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t, C.c_uint64]
    lib.dt_format_llquantize.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t, C.c_uint64]
    lib.dtrace_errno.argtypes = [C.c_void_p]
    lib.dtrace_errmsg.argtypes = [C.c_void_p, C.c_int]
    lib.dtrace_errmsg.restype = C.c_char_p
    libc.tmpfile.restype = C.c_void_p
    libc.fclose.argtypes = [C.c_void_p]
    libc.mprotect.argtypes = [C.c_void_p, C.c_size_t, C.c_int]
    payload = cases[sys.argv[3]]
    mem = mmap.mmap(-1, 2*mmap.PAGESIZE)
    address = C.addressof(C.c_char.from_buffer(mem))
    assert libc.mprotect(address+mmap.PAGESIZE, mmap.PAGESIZE, 0) == 0
    start = address + mmap.PAGESIZE - len(payload)
    C.memmove(start, payload, len(payload))
    error = C.c_int(); handle = lib.dtrace_open(3, 3, C.byref(error)); assert handle
    stream = libc.tmpfile(); assert stream
    rc = (lib.dt_print_llquantize(handle, stream, start, len(payload), 1)
        if sys.argv[4] == 'text' else lib.dt_format_llquantize(handle, start, len(payload), 1))
    diagnostic = lib.dtrace_errmsg(handle, lib.dtrace_errno(handle)).decode() if rc < 0 else ''
    libc.fclose(stream); lib.dtrace_close(handle)
    assert libc.mprotect(address+mmap.PAGESIZE, mmap.PAGESIZE, 3) == 0
    mem.close()
    print(json.dumps({'returncode': rc, 'diagnostic': diagnostic}))
    raise SystemExit(0 if rc == -1 and diagnostic == 'Data record list does not match statement' else 1)
out, binary = (Path(x).resolve() for x in sys.argv[1:])
assert out.is_relative_to('/usr/obj') and binary.is_relative_to('/usr/obj') and not out.exists()
out.mkdir(parents=True)
results = []
for name, mode in ((name, mode) for name in cases for mode in ('text', 'structured')):
    label = name+'-'+mode
    env = dict(os.environ, LLVM_PROFILE_FILE=str(out / (label+'-%p.profraw')))
    try:
        run = subprocess.run([sys.executable, __file__, '--case', str(binary), name, mode], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        results.append({'case':label, 'status':run.returncode, 'stdout':run.stdout,
            'stderr':run.stderr, 'passed':run.returncode == 0 and not run.stderr})
    except subprocess.TimeoutExpired:
        results.append({'case':label, 'passed':False, 'timeout':True})
(out/'results.json').write_text(json.dumps(results, indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()
    for p in (binary, Path(__file__).resolve())}, 'scope':'NODEV/NOSYS actual-library guarded-memory malformed records'}, indent=2)+'\n')
print(json.dumps(results, indent=2))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
