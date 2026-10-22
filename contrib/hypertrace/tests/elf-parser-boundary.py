#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the built libdtrace ELF parser without opening /dev/dtrace."""
from pathlib import Path
import ctypes as C
import os, struct, sys, hashlib
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
lib = C.CDLL(str(Path(sys.argv[2]).resolve()))
parse = lib.dtrace_elf_parse
parse.restype = C.c_void_p
parse.argtypes = [C.c_void_p, C.c_int, C.c_char_p, C.c_int,
                 C.POINTER(C.c_int), C.c_char_p, C.c_void_p]
class Program(C.Structure):
    _fields_ = [('first', C.c_uint32), ('version', C.c_uint8),
                ('options', C.c_uint32), ('flags', C.c_uint32), ('haserror', C.c_int),
                ('error', C.c_char * 4096), ('ident', C.c_char * 128),
                ('source', C.c_char * 128), ('execute', C.c_int),
                ('pid', C.c_int), ('count', C.c_uint32)]
def elf(payload):
    strings = b'\0.shstrtab\0.dtrace_prog\0'
    offset = (64 + len(strings) + 7) & ~7
    sections = (offset + len(payload) + 7) & ~7
    header = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
        1, 62, 1, 0, 0, sections, 0, 64, 0, 0, 64, 3, 1)
    content = header + strings
    content += bytes(offset - len(content)) + payload
    content += bytes(sections - len(content)) + bytes(64)
    content += struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, 64, len(strings), 0, 0, 1, 0)
    content += struct.pack('<IIQQQQIIQQ', 11, 1, 0, 0, offset, len(payload), 0, 0, 8, 0)
    return content
cases = [(f'truncated-{n}', bytes(n), b'invalid program record')
         for n in (1, 4, 16, 128, C.sizeof(Program) - 1)]
p = Program(); p.haserror = 1; p.error = b'expected program rejection'
cases.append(('valid-error-record', bytes(p), b'expected program rejection'))
p.count = 0xffffffff
cases.append(('oversized-probe-array', bytes(p), b'invalid program record'))
p.count = 0; p.error = b'A' * 4096
cases.append(('unterminated-error', bytes(p), b'invalid program record'))
cases = [(name, elf(payload), expected) for name, payload, expected in cases]
p = Program(); p.haserror = 1; p.error = b'expected program rejection'
valid = elf(bytes(p))
wrapped = hashlib.sha256(valid).digest() + valid
cases.append(('checksummed-error-record', wrapped, b'expected program rejection'))
for n in (0, 1, 3, 4, 16, 31):
    cases.append((f'short-checksum-{n}', bytes(n), b'read('))
for n in (32, 33, 34, 35):
    cases.append((f'short-checksummed-body-{n}', bytes(n), b'invalid checksummed file size'))
cases.append(('wrong-checksum', bytes(32) + valid, b'SHA256 mismatch'))
body = b'not ELF'
cases.append(('checksummed-non-elf', hashlib.sha256(body).digest() + body, b'not an ELF file'))
initial_temps = set(Path('/tmp').glob('ddtrace-elf.*'))
# Warm up libelf before checking repeated parse resource ownership.
for iteration in range(3):
    initial_fds = len(list(Path('/dev/fd').iterdir()))
    for name, payload, expected in cases:
        path = out / (name + '.elf'); path.write_bytes(payload)
        fd = os.open(path, os.O_RDONLY)
        try:
            error = C.c_int(); message = C.create_string_buffer(512)
            # All these cases reject before any tracing-handle use.
            result = parse(None, fd, os.fsencode(path), 0, C.byref(error), message, None)
            assert not result and error.value and expected in message.value, (name, error.value, message.value)
            os.fstat(fd)  # The caller's descriptor must remain open.
        finally: os.close(fd)
    assert len(list(Path('/dev/fd').iterdir())) == initial_fds, 'parser leaked descriptors'
    assert set(Path('/tmp').glob('ddtrace-elf.*')) == initial_temps, 'parser leaked temporary files'
print(f'PASS: actual built libdtrace rejects {len(cases)} malformed/error ELF program boundaries, repeated 3 times without descriptor or temporary-file leaks; no tracing device')
