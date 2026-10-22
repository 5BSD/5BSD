#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check reproducible compiled DTrace identities without opening a device."""
import ctypes as C
import struct
import subprocess
import sys
from pathlib import Path

if len(sys.argv) < 2:
    raise SystemExit('usage: program-identity.py LIB [--child SOURCE]')
library = str(Path(sys.argv[1]).resolve())
lib = C.CDLL(library, use_errno=True)
lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p,
    C.c_int, C.c_uint, C.c_int, C.c_void_p]
lib.dtrace_program_strcompile.restype = C.c_void_p
lib.dtrace_program_compiled_digest.argtypes = [C.c_void_p, C.c_void_p,
    C.POINTER(C.c_ubyte)]
lib.dtrace_program_compiled_digest.restype = C.c_int
lib.dtrace_dof_create.argtypes = [C.c_void_p, C.c_void_p, C.c_uint]
lib.dtrace_dof_create.restype = C.c_void_p
lib.dtrace_dof_destroy.argtypes = [C.c_void_p, C.c_void_p]

def dof_bytes(handle, program):
    dof = lib.dtrace_dof_create(handle, program, 1)  # DTRACE_D_STRIP
    assert dof
    try:
        length = struct.unpack_from('<Q', C.string_at(dof, 56), 48)[0]
        assert 64 <= length <= 64 * 1024 * 1024
        return C.string_at(dof, length)
    finally:
        lib.dtrace_dof_destroy(handle, dof)

def identity(source):
    error = C.c_int()
    handle = lib.dtrace_open(3, 3, C.byref(error))  # NODEV | NOSYS
    assert handle, ('dtrace_open', error.value)
    try:
        program = lib.dtrace_program_strcompile(handle, source, 4,
            0x1004, 0, None)  # NAME; NOLIBS | ZDEFS
        assert program, ('compile', source)
        original_dof = dof_bytes(handle, program)
        first = (C.c_ubyte * 32)()
        second = (C.c_ubyte * 32)()
        assert lib.dtrace_program_compiled_digest(handle, program,
            first) == 0, ('first digest', C.get_errno())
        assert lib.dtrace_program_compiled_digest(handle, program,
            second) == 0, ('second digest', C.get_errno())
        assert bytes(first) == bytes(second) and any(first)
        assert dof_bytes(handle, program) == original_dof, \
            'identity hashing changed the executable DOF'
        return bytes(first)
    finally:
        lib.dtrace_close(handle)

if len(sys.argv) == 4 and sys.argv[2] == '--child':
    print(identity(bytes.fromhex(sys.argv[3])).hex())
    raise SystemExit(0)
if len(sys.argv) != 2:
    raise SystemExit('unexpected arguments')

cases = [b'BEGIN { trace(1); }', b'BEGIN { trace(2); }',
    b'BEGIN { printf("value=%d\\n", 42); }',
    b'BEGIN { @counts[1] = count(); }',
    b'BEGIN { x = 1; trace(x); }',
    b'BEGIN { this->x = timestamp; trace(this->x); }']
identities = {}
for source in cases:
    local = identity(source)
    remote = []
    for _ in range(2):
        result = subprocess.run([sys.executable, __file__, library,
            '--child', source.hex()], capture_output=True, text=True,
            check=True, timeout=30)
        remote.append(bytes.fromhex(result.stdout.strip()))
    assert local == remote[0] == remote[1], ('restart changed identity',
        source, local.hex(), [value.hex() for value in remote])
    identities[source] = local
assert len(set(identities.values())) == len(cases), 'changed programs collide'
print(f'PASS: {len(cases)} compiled program identities stable across restarts '
      'and distinct across changed programs; no DTrace device opened')
