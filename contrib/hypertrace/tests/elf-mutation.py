#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Deterministic crash check for serialized programs, with a fresh process per case."""
from pathlib import Path
import ctypes as C
import os, random, struct, subprocess, sys
if len(sys.argv) == 3 and sys.argv[1] == '--child':
    library = C.CDLL(os.environ['HYPERTRACE_TEST_LIBRARY'])
    library.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
    library.dtrace_open.restype = C.c_void_p
    library.dtrace_close.argtypes = [C.c_void_p]
    library.dt_program_destroy.argtypes = [C.c_void_p, C.c_void_p]
    library.dtrace_elf_parse.argtypes = [C.c_void_p, C.c_int, C.c_char_p, C.c_int,
                                        C.POINTER(C.c_int), C.c_char_p, C.c_void_p]
    library.dtrace_elf_parse.restype = C.c_void_p
    error = C.c_int(); handle = library.dtrace_open(3, 3, C.byref(error))
    assert handle, error.value
    path = Path(sys.argv[2]); fd = os.open(path, os.O_RDONLY)
    try:
        message = C.create_string_buffer(512)
        result = library.dtrace_elf_parse(handle, fd, os.fsencode(path), 0,
                                          C.byref(error), message, None)
        if result: library.dt_program_destroy(handle, result)
    finally:
        os.close(fd); library.dtrace_close(handle)
    sys.exit(0)
if len(sys.argv) != 4:
    raise SystemExit('usage: elf-mutation.py /usr/obj/results libdtrace.so program.elf')
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = Path(sys.argv[3]).read_bytes()
assert source[:6] == b'\x7fELF\x01\x01'
shoff, shwidth = struct.unpack_from('<I', source, 32)[0], struct.unpack_from('<H', source, 46)[0]
count = struct.unpack_from('<I', source, shoff + 20)[0]
regions = []
for section in range(2, count):
    header = shoff + section * shwidth
    offset, length = struct.unpack_from('<II', source, header + 16)
    if length: regions.append((f'section-{section}', offset, length))
    regions.append((f'header-{section}', header, shwidth))
randomizer = random.Random(0x48545243)
environment = os.environ.copy()
library = Path(sys.argv[2]).resolve()
environment['HYPERTRACE_TEST_LIBRARY'] = str(library)
world = library.parents[3]
environment['LD_LIBRARY_PATH'] = ':'.join(str(world / item) for item in
    ('cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
for number in range(160):
    name, offset, length = regions[number % len(regions)]
    position = offset + randomizer.randrange(length)
    copy = bytearray(source)
    copy[position] ^= 1 << randomizer.randrange(8)
    path = out / f'{number:03}-{name}.elf'
    path.write_bytes(copy)
    result = subprocess.run([sys.executable, __file__, '--child', str(path)],
                            env=environment, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, (name, number, result.returncode, result.stderr)
print('PASS: 160 deterministic ELF section/header mutations survived in isolated NODEV/NOSYS parser processes')
