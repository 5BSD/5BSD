#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual libdtrace string-table growth, collisions and callbacks."""
import ctypes as C
import hashlib
import json
import random
import sys
from pathlib import Path
out, binary = [Path(s).resolve() for s in sys.argv[1:]]
if not all(p.is_relative_to('/usr/obj') for p in (out, binary)):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
lib = C.CDLL(str(binary))
lib.dt_strtab_create.argtypes = [C.c_size_t]; lib.dt_strtab_create.restype = C.c_void_p
lib.dt_strtab_destroy.argtypes = [C.c_void_p]
lib.dt_strtab_empty.argtypes = [C.c_void_p]; lib.dt_strtab_empty.restype = C.c_int
lib.dt_strtab_size.argtypes = [C.c_void_p]; lib.dt_strtab_size.restype = C.c_size_t
for name in ('dt_strtab_insert', 'dt_strtab_index'):
    f = getattr(lib, name); f.argtypes = [C.c_void_p, C.c_char_p]; f.restype = C.c_ssize_t
callback_type = C.CFUNCTYPE(C.c_ssize_t, C.c_void_p, C.c_size_t, C.c_size_t, C.c_void_p)
lib.dt_strtab_write.argtypes = [C.c_void_p, callback_type, C.c_void_p]
lib.dt_strtab_write.restype = C.c_ssize_t
buckets = C.c_uint.in_dll(lib, '_dtrace_strbuckets')
original = buckets.value
rng = random.Random(0x5b5d2028)
strings = [b'', b'a', b'aa', b'aaa'] + [bytes(rng.randrange(1,256) for _ in range(rng.randrange(1,80))) for _ in range(64)]
results = []
try:
    for bucket_count in (1, original):
        buckets.value = bucket_count
        for size in (1, 2, 3, 7, 16, 31, 64, 4096):
            table = lib.dt_strtab_create(size); assert table
            try:
                expected = bytearray(b'\0'); offsets = {b'': 0}
                assert lib.dt_strtab_empty(table) == 1
                assert lib.dt_strtab_index(table, None) == 0
                for value in strings:
                    offset = offsets.get(value, len(expected))
                    if value not in offsets:
                        assert lib.dt_strtab_index(table, value) == -1
                        offsets[value] = offset; expected += value + b'\0'
                    assert lib.dt_strtab_insert(table, value) == offset
                    assert lib.dt_strtab_insert(table, value) == offset
                    assert lib.dt_strtab_size(table) == len(expected)
                assert lib.dt_strtab_empty(table) == 0
                for value, offset in offsets.items():
                    assert lib.dt_strtab_index(table, value) == offset
                assert lib.dt_strtab_index(table, b'never inserted missing value') == -1
                chunks = []
                @callback_type
                def collect(p, n, offset, private):
                    chunks.append((offset, C.string_at(p, n)))
                    return n
                assert lib.dt_strtab_write(table, collect, None) == len(expected)
                assert b''.join(data for _, data in chunks) == expected
                running = 0
                for offset, data in chunks:
                    assert offset == running; running += len(data)
                for stop in sorted({0, len(chunks)//2, len(chunks)-1}):
                    for failure in (0, -1):
                        calls = []
                        @callback_type
                        def fail(p, n, offset, private):
                            calls.append((offset, n))
                            return failure if len(calls)-1 == stop else n
                        total = sum(len(data) for _,data in chunks[:stop])
                        assert lib.dt_strtab_write(table, fail, None) == (total or -1)
                        assert len(calls) == stop + 1
                results.append({'buckets':bucket_count, 'buffer_size':size,
                                'unique_strings':len(offsets), 'bytes':len(expected), 'passed':True})
            finally:
                lib.dt_strtab_destroy(table)
finally:
    buckets.value = original
root = Path(__file__).resolve().parents[3]
paths = [Path(__file__), binary, root/'cddl/contrib/opensolaris/lib/libdtrace/common/dt_strtab.c']
(out/'results.json').write_text(json.dumps({'results':results, 'sanitized':False,
 'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}},indent=2)+'\n')
print('PASS: %d string-table configurations with collision, growth, lookup and callback checks' % len(results))
