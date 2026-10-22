#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check the built libdtrace guest UADDR formatter without a live DTrace device."""
from pathlib import Path
import os
import subprocess
import sys

if len(sys.argv) != 2:
    raise SystemExit('usage: guest-uaddr-format.py /usr/obj/.../amd64.amd64')
world = Path(sys.argv[1]).resolve()
if not world.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
library = world / 'cddl/lib/libdtrace/libdtrace.so.2'
if not library.is_file():
    raise SystemExit(f'missing built libdtrace: {library}')
env = os.environ.copy()
env.pop('LD_PRELOAD', None)
env['LD_LIBRARY_PATH'] = ':'.join(str(world / p) for p in
    ('cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
program = r'''
import ctypes
import sys

lib = ctypes.CDLL(sys.argv[1])
format_uaddr = lib.dt_hypertrace_uaddr_format
format_uaddr.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_uint64, ctypes.c_uint64]
format_uaddr.restype = ctypes.c_int
tagged = (1 << 63) | (7 << 32) | 321
buf = ctypes.create_string_buffer(96)
count = format_uaddr(buf, len(buf), tagged, 0x1234)
expected = b'guest[7]:pid[321]`0x1234'
assert count == len(expected) and buf.value == expected, (count, buf.value)
count = format_uaddr(buf, len(buf), tagged, 0xffffffffffffffff)
expected = b'guest[7]:pid[321]`0xffffffffffffffff'
assert count == len(expected) and buf.value == expected, (count, buf.value)
print('PASS: built libdtrace formats tagged guest VM/PID/address records')
'''
subprocess.run([sys.executable, '-c', program, str(library)],
    env=env, check=True, timeout=30)
