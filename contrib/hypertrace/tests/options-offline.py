#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual libdtrace option parsing and nonmutation on rejected values; NODEV."""
from pathlib import Path
import ctypes as C
import hashlib
import json
import os
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: options-offline.py /usr/obj/output /usr/obj/libdtrace.so.2')
out, binary = (Path(x).resolve() for x in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, binary)):
    raise SystemExit('Use isolated /usr/obj artifacts')
out.mkdir(parents=True, exist_ok=True)
lib = C.CDLL(str(binary))
lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_setopt.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
lib.dtrace_setopt.restype = C.c_int
lib.dtrace_getopt.argtypes = [C.c_void_p, C.c_char_p, C.POINTER(C.c_int64)]
lib.dtrace_getopt.restype = C.c_int
error = C.c_int()
h = lib.dtrace_open(3, 3, C.byref(error))
assert h, error.value
results = []
def check(option, value, expected, seed="64"):
    key = option.encode()
    assert lib.dtrace_setopt(h, key, seed.encode()) == 0
    before = C.c_int64()
    assert lib.dtrace_getopt(h, key, C.byref(before)) == 0
    status = lib.dtrace_setopt(h, key, None if value is None else value.encode())
    actual = C.c_int64()
    assert lib.dtrace_getopt(h, key, C.byref(actual)) == 0
    passed = status == 0 and actual.value == expected if expected is not None else status == -1 and actual.value == before.value
    results.append({'option': option, 'input': value, 'expected': expected,
                    'status': status, 'value': actual.value, 'passed': passed})
try:
    # Policy values are observable through getopt; failed updates must retain
    # the previous policy, including after a different valid selection.
    for key, choices in [('bufpolicy', [('ring', 0), ('fill', 1), ('switch', 2)]),
                         ('bufresize', [('auto', 0), ('manual', 1)])]:
        for seed, _ in choices:
            for value, expected in choices:
                check(key, value, expected, seed)
            for value in (None, '', 'bogus', '0', '1', ' '+seed, seed+' ', seed.upper()):
                check(key, value, None, seed)
    for key in ('bufsize', 'aggsize', 'dynvarsize', 'specsize'):
        for text, value in [(None, 0), ('0', 0), ('0x20', 32), ('010', 8),
                            (' 12', 12), ('+12', 12), ('9223372036854775807', (1 << 63)-1)]:
            check(key, text, value)
        for suffix, scale in [('k', 1024), ('m', 1024**2), ('g', 1024**3), ('t', 1024**4)]:
            for variant in (suffix, suffix.upper()):
                check(key, '2' + variant, 2 * scale)
            limit = ((1 << 63)-1) // scale
            check(key, str(limit) + suffix, limit * scale)
            check(key, str(limit+1) + suffix, None)
        for text in ('', ' ', 'k', '12kb', '12x', '-1', '-18446744073709551615',
                     '9223372036854775808', '18446744073709551616', '18014398509481984k'):
            check(key, text, None)
    for suffix, scale in [('ns', 1), ('nsec', 1), ('us', 1000), ('usec', 1000),
                          ('ms', 10**6), ('msec', 10**6), ('s', 10**9), ('sec', 10**9),
                          ('m', 60*10**9), ('min', 60*10**9), ('h', 3600*10**9),
                          ('hour', 3600*10**9), ('d', 86400*10**9), ('day', 86400*10**9)]:
        check('cleanrate', '2'+suffix, 2*scale)
        check('cleanrate', '2'+suffix.upper(), 2*scale)
        limit = ((1 << 63)-1) // scale
        check('cleanrate', str(limit)+suffix, limit*scale)
        check('cleanrate', str(limit+1)+suffix, None)
    for text, value in [(None, 0), ('0', 0), ('2hz', 500000000), ('0hz', 0), ('4HZ', 250000000)]:
        check('cleanrate', text, value)
    for text in ('', ' ', 'ms', 'hz', '-1', '-18446744073709551615', '1xs',
                 '18446744073709552ms', '18446744073709551616ns'):
        check('cleanrate', text, None)
    for text, value in [(None, 0), ('', -2), ('7', 7), ('0x10', 16)]:
        check('quiet', text, value)
    for positive, negative in [('yes','no'), ('enable','disable'), ('enabled','disabled'),
                               ('true','false'), ('on','off'), ('set','unset')]:
        check('quiet', positive, 1)
        check('quiet', negative, -2)
        check('quiet', positive.upper(), 1)
    for text in (' ', 'bogus', '12x', '-1', '-18446744073709551615', '9223372036854775808'):
        check('quiet', text, None)
    lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int,
                                              C.c_uint, C.c_int, C.c_void_p]
    lib.dtrace_program_strcompile.restype = C.c_void_p
    def empty_compiles():
        return bool(lib.dtrace_program_strcompile(h, b'', 4, 0x1004, 0, None))
    results.append({'case': 'empty-program-default-rejected',
                    'passed': not empty_compiles()})
    for value in (b'', b'yes', b'1'):
        status = lib.dtrace_setopt(h, b'empty', value)
        results.append({'case': 'invalid-empty-option-retains-compiler-policy',
                        'input': value.decode(),
                        'passed': status == -1 and not empty_compiles()})
    status = lib.dtrace_setopt(h, b'empty', None)
    results.append({'case': 'empty-option-enables-empty-compilation',
                    'passed': status == 0 and empty_compiles()})
    status = lib.dtrace_setopt(h, b'empty', b'no')
    results.append({'case': 'invalid-empty-option-retains-enabled-policy',
                    'passed': status == -1 and empty_compiles()})
finally:
    lib.dtrace_close(h)
(out/'results.json').write_text(json.dumps(results, indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'pid':os.getpid(),'binary':str(binary),
    'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
    'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'device_mode':'NODEV | NOSYS'},indent=2)+'\n')
failed = [x for x in results if not x['passed']]
for x in failed: print(x)
if failed: raise SystemExit(1)
print(f'PASS: {len(results)} option conversions/rejections with unchanged values on failure')
