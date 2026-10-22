#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual compile/link/DOF API with an explicitly empty module inventory."""
from pathlib import Path
import ctypes as C
import hashlib
import json
import os
import subprocess
import sys

CASES = {
    'constant': 'BEGIN { trace(1); }',
    'arithmetic': 'BEGIN { x = timestamp; trace((x + 3) * 7 - x / 2); }',
    'conditional': 'BEGIN { x = timestamp; trace(x ? 11 : 22); }',
    'logical': 'BEGIN { x = timestamp; trace(x > 0 && x < 100); }',
    'thread-local': 'BEGIN { self->x = 3; trace(self->x + 4); }',
    'clause-local': 'BEGIN { this->x = timestamp; trace(this->x); }',
    'string': 'BEGIN { trace("hello"); }',
    'printf': 'BEGIN { printf("value=%d\\n", 42); }',
    'count': 'BEGIN { @a[1] = count(); }',
    'sum': 'BEGIN { @a[1] = sum(7); }',
    'predicate': 'BEGIN /timestamp != 0/ { trace(1); } END { trace(2); }',
}

def child(binary, name):
    import struct
    lib = C.CDLL(str(binary))
    lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
    lib.dtrace_open.restype = C.c_void_p
    lib.dtrace_close.argtypes = [C.c_void_p]
    lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.c_uint, C.c_int, C.c_void_p]
    lib.dtrace_program_strcompile.restype = C.c_void_p
    lib.hypertrace_link.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
    lib.hypertrace_link.restype = C.c_int
    lib.dtrace_dof_create.argtypes = [C.c_void_p, C.c_void_p, C.c_uint]
    lib.dtrace_dof_create.restype = C.c_void_p
    lib.dtrace_dof_destroy.argtypes = [C.c_void_p, C.c_void_p]
    error = C.c_int()
    h = lib.dtrace_open(3, 3, C.byref(error))  # NODEV | NOSYS
    assert h, error.value
    try:
        p = lib.dtrace_program_strcompile(h, CASES[name].encode(), 4, 0x1004, 0, None)
        assert p, name
        message = C.create_string_buffer(512)
        result = lib.hypertrace_link(h, p, message)
        assert result == 0, (name, result, message.value)
        dof = lib.dtrace_dof_create(h, p, 1)
        assert dof, name
        try:
            header = C.string_at(dof, 64)
            assert header[:4] == b'\x7fDOF'
            assert 64 <= struct.unpack_from('<Q', header, 48)[0] <= 64 * 1024 * 1024
        finally:
            lib.dtrace_dof_destroy(h, dof)
    finally:
        lib.dtrace_close(h)
    print('PASS:', name)

if len(sys.argv) == 4 and sys.argv[1] == '--child':
    child(Path(sys.argv[2]), sys.argv[3])
    raise SystemExit(0)
if len(sys.argv) != 3:
    raise SystemExit('usage: linker-offline.py /usr/obj/output /usr/obj/matched-objtop')
out, world = (Path(x).resolve() for x in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, world)):
    raise SystemExit('Use isolated /usr/obj artifacts')
out.mkdir(parents=True, exist_ok=True)
binary = world / 'cddl/lib/libdtrace/libdtrace.so.2'
source = out / 'no-modules.c'
source.write_text('/* Test boundary: do not query host module inventory. */\n'
                  'int kldnext(int id) { (void)id; return 0; }\n')
shim = out / 'no-modules.so'
subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                str(source), '-o', str(shim)], check=True)
env = os.environ.copy()
env['LD_PRELOAD'] = str(shim)
env['LD_LIBRARY_PATH'] = ':'.join(str(world / p) for p in
    ('cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
results = []
for name in CASES:
    try:
        r = subprocess.run([sys.executable, __file__, '--child', str(binary), name],
                           env=env, capture_output=True, text=True, timeout=30)
        (out / (name + '.log')).write_text(r.stdout + r.stderr)
        results.append({'case': name, 'status': r.returncode})
    except subprocess.TimeoutExpired:
        results.append({'case': name, 'status': 'timeout'})
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
(out / 'provenance.json').write_text(json.dumps({
    'binary': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
    'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'device_mode': 'NODEV | NOSYS', 'mock_boundary': 'kldnext returns empty inventory',
    'separate_process_per_case': True, 'live': False}, indent=2) + '\n')
failed = [r for r in results if r['status'] != 0]
for r in failed:
    print(r)
if failed:
    raise SystemExit(1)
print(f'PASS: {len(results)} actual compile/link/DOF cases with no host module inventory')
