#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Option parsing through the actual libdtrace dtrace_setopt/dtrace_getopt.

Expected values follow the documented option grammar: sizes take binary
k/m/g/t suffixes; rates take ns..day suffixes or hz; switches accept
yes/no-style words or non-negative integers; enumerations are case
sensitive.  Out-of-range and malformed values must be refused and leave the
previous value in place.  NODEV|NOSYS handles only; no device is opened.
"""
from pathlib import Path
import ctypes as C
import hashlib
import json
import sys

out, binary = (Path(x).resolve() for x in sys.argv[1:])
if not out.is_relative_to('/usr/obj') or not binary.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('usage: options-properties.py /usr/obj/new-output /usr/obj/.../libdtrace.so.2')
out.mkdir(parents=True)
lib = C.CDLL(str(binary))
lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_setopt.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
lib.dtrace_getopt.argtypes = [C.c_void_p, C.c_char_p, C.POINTER(C.c_int64)]
lib.dtrace_errno.argtypes = [C.c_void_p]
lib.dtrace_errmsg.argtypes = [C.c_void_p, C.c_int]
lib.dtrace_errmsg.restype = C.c_char_p
lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.c_uint,
                                          C.c_int, C.c_void_p]
lib.dtrace_program_strcompile.restype = C.c_void_p

UNSET = -2  # DTRACEOPT_UNSET (dtrace_optval_t)0xfffffffffffffffe
BADVAL = 'Invalid value for specified option'
BADNAME = 'Invalid option name'
NS = 10 ** 9
K, M, G, T = 1 << 10, 1 << 20, 1 << 30, 1 << 40
I64 = (1 << 63) - 1
RING, FILL, SWITCH = 0, 1, 2      # DTRACEOPT_BUFPOLICY_*
AUTO, MANUAL = 0, 1               # DTRACEOPT_BUFRESIZE_*

# (option, value or None, expected getopt value or error message)
RUNTIME = [
    ('bufsize', '100', 100), ('bufsize', '4k', 4 * K), ('bufsize', '4K', 4 * K),
    ('bufsize', '2m', 2 * M), ('bufsize', '1g', G), ('bufsize', '1t', T),
    ('bufsize', '0x10k', 16 * K), ('bufsize', '010', 8),
    ('bufsize', str(I64 // T) + 't', (I64 // T) * T),
    ('bufsize', str(I64 // T + 1) + 't', BADVAL),
    ('bufsize', str(I64), I64), ('bufsize', str(I64) + '0', BADVAL),
    ('bufsize', '', BADVAL), ('bufsize', 'k', BADVAL), ('bufsize', '-1', BADVAL),
    ('bufsize', '4kb', BADVAL), ('bufsize', '4 k', BADVAL), ('bufsize', None, 0),
    ('aggsize', '8m', 8 * M), ('dynvarsize', '1m', M), ('specsize', '32k', 32 * K),
    ('jstackstrsize', '512', 512),
    ('strsize', '512', 512), ('strsize', '4294967295', 4294967295),
    ('strsize', '4294967296', 'Value too large to be stored in data type'),
    ('switchrate', '7', 7), ('switchrate', '1ns', 1), ('switchrate', '3nsec', 3),
    ('switchrate', '1us', 1000), ('switchrate', '2usec', 2000),
    ('switchrate', '5ms', 5 * 10 ** 6), ('switchrate', '5MSEC', 5 * 10 ** 6),
    ('switchrate', '2s', 2 * NS), ('switchrate', '2sec', 2 * NS),
    ('switchrate', '1m', 60 * NS), ('switchrate', '1min', 60 * NS),
    ('switchrate', '1h', 3600 * NS), ('switchrate', '1hour', 3600 * NS),
    ('switchrate', '1d', 86400 * NS), ('switchrate', '1day', 86400 * NS),
    ('switchrate', '10hz', NS // 10), ('switchrate', '0hz', 0),
    ('switchrate', '3hz', NS // 3),
    ('switchrate', str(I64 // (86400 * NS)) + 'd', (I64 // (86400 * NS)) * 86400 * NS),
    ('switchrate', str(I64 // (86400 * NS) + 1) + 'd', BADVAL),
    ('switchrate', '5fortnights', BADVAL), ('switchrate', '-1s', BADVAL),
    ('switchrate', 'hz', BADVAL), ('switchrate', None, 0),
    ('aggrate', '1s', NS), ('statusrate', '100ms', 10 ** 8),
    ('cleanrate', '101hz', NS // 101),
    ('quiet', 'yes', 1), ('quiet', 'no', UNSET), ('quiet', 'ENABLE', 1),
    ('quiet', 'disable', UNSET), ('quiet', 'Enabled', 1), ('quiet', 'disabled', UNSET),
    ('quiet', 'true', 1), ('quiet', 'FALSE', UNSET), ('quiet', 'on', 1),
    ('quiet', 'off', UNSET), ('quiet', 'set', 1), ('quiet', 'unset', UNSET),
    ('quiet', '', UNSET), ('quiet', '3', 3), ('quiet', '0x10', 16), ('quiet', '0', 0),
    ('quiet', '-2', BADVAL), ('quiet', '2x', BADVAL), ('quiet', 'maybe', BADVAL),
    ('quiet', None, 0),
    ('stackframes', '40', 40), ('ustackframes', '12', 12), ('nspec', '4', 4),
    ('cpu', '1', 1), ('temporal', 'yes', 1), ('hypertrace', 'no', UNSET),
    ('immstackframes', '8', 8), ('immstackstrsize', '32', 32),
    ('flowindent', 'yes', 1), ('rawbytes', 'yes', 1), ('stackindent', '4', 4),
    ('aggsortkey', 'yes', 1), ('aggsortkeypos', '2', 2), ('aggsortpos', '1', 1),
    ('aggsortrev', 'yes', 1), ('aggpack', 'yes', 1), ('agghist', 'yes', 1),
    ('aggzoom', 'yes', 1),
    ('bufpolicy', 'ring', RING), ('bufpolicy', 'fill', FILL),
    ('bufpolicy', 'switch', SWITCH), ('bufpolicy', 'Ring', BADVAL),
    ('bufpolicy', 'rings', BADVAL), ('bufpolicy', None, BADVAL),
    ('bufresize', 'auto', AUTO), ('bufresize', 'manual', MANUAL),
    ('bufresize', 'AUTO', BADVAL), ('bufresize', None, BADVAL),
    ('nosuchoption', '1', BADNAME),
]

# Compile-time options: accepted values and refusals (their effects are
# internal; getopt does not report them).
COMPILE = [
    ('linkmode', 'kernel', None), ('linkmode', 'primary', None),
    ('linkmode', 'dynamic', None), ('linkmode', 'static', None),
    ('linkmode', 'Static', BADVAL), ('linkmode', None, BADVAL),
    ('linktype', 'elf', None), ('linktype', 'dof', None), ('linktype', 'coff', BADVAL),
    ('encoding', 'ascii', None), ('encoding', 'utf8', None), ('encoding', 'latin1', BADVAL),
    ('evaltime', 'exec', None), ('evaltime', 'preinit', None),
    ('evaltime', 'postinit', None), ('evaltime', 'main', None),
    ('evaltime', 'later', BADVAL),
    ('stdc', 'a', None), ('stdc', 'c', None), ('stdc', 's', None), ('stdc', 't', None),
    ('stdc', 'x', BADVAL), ('stdc', None, BADVAL),
    ('late', 'dynamic', None), ('late', 'static', None), ('late', 'eager', BADVAL),
    ('iregs', '8', None), ('iregs', '0', BADVAL), ('iregs', '-3', BADVAL),
    ('tregs', '4', None), ('tregs', '0', BADVAL),
    ('pgmax', '0', None), ('pgmax', '16', None), ('pgmax', '-1', BADVAL),
    ('tree', '4', None), ('tree', '0', BADVAL),
    ('version', '1.0', None), ('version', '1.1', None),
    ('version', 'one', 'Version is not properly formatted or is too large'),
    ('version', '1.2.3.4', 'Version is not properly formatted or is too large'),
    ('version', '99.0', 'Requested version is not supported by compiler'),
    ('version', None, BADVAL),
    ('amin', 'Evolving/Evolving/Common', None), ('amin', 'Bogus/Bogus', BADVAL),
    ('amin', None, BADVAL),
    ('define', 'FOO=1', None), ('undef', 'FOO', None), ('incdir', '/nonexistent', None),
    ('setenv', 'DT_TEST_OPT=1', None), ('unsetenv', 'DT_TEST_OPT', None),
    ('setenv', None, BADVAL),
    ('droptags', None, None), ('lazyload', None, None),
    ('aggpercpu', None, None), ('zdefs', None, None), ('verbose', None, None),
]


def handle():
    err = C.c_int()
    h = lib.dtrace_open(3, 3, C.byref(err))
    assert h, err.value
    return h


def message(h):
    return lib.dtrace_errmsg(h, lib.dtrace_errno(h)).decode()


results = []
for option, value, want in RUNTIME:
    h = handle()
    sentinel = C.c_int64()
    lib.dtrace_getopt(h, option.encode(), C.byref(sentinel))
    rc = lib.dtrace_setopt(h, option.encode(), None if value is None else value.encode())
    got = C.c_int64(0x5b5d)
    grc = lib.dtrace_getopt(h, option.encode(), C.byref(got))
    if isinstance(want, str):
        # Refused: the message matches and the previous value is unchanged.
        passed = rc == -1 and message(h) == want and (grc != 0 or got.value == sentinel.value)
        actual = message(h) if rc else got.value
    else:
        passed = rc == 0 and grc == 0 and got.value == want
        actual = got.value if rc == 0 else message(h)
    results.append({'group': 'runtime', 'option': option, 'value': value,
                    'expected': want, 'actual': actual, 'passed': passed})
    lib.dtrace_close(h)

for option, value, want in COMPILE:
    h = handle()
    rc = lib.dtrace_setopt(h, option.encode(), None if value is None else value.encode())
    actual = 'ok' if rc == 0 else message(h)
    passed = (rc == 0) if want is None else (rc == -1 and actual == want)
    # Compile-time options are not readable through getopt.
    g = C.c_int64()
    passed = passed and lib.dtrace_getopt(h, option.encode(), C.byref(g)) == -1 and \
        message(h) == BADNAME
    results.append({'group': 'compile', 'option': option, 'value': value,
                    'expected': want or 'ok', 'actual': actual, 'passed': passed})
    lib.dtrace_close(h)

# Options that must not be set from a D program's pragmas.
for name, pragma, want in [
    ('pragma-setenv', '#pragma D option setenv=X=1', 'Option cannot be used from within a D program'),
    ('pragma-stdc', '#pragma D option stdc=a', 'Option cannot be used from within a D program'),
    ('pragma-quiet', '#pragma D option quiet', None),
]:
    h = handle()
    p = lib.dtrace_program_strcompile(h, (pragma + '\nBEGIN { trace(1); }\n').encode(),
                                      4, 0, 0, None)
    actual = 'ok' if p else message(h)
    passed = bool(p) if want is None else (not p and want in actual)
    if want is None and p:
        q = C.c_int64()
        passed = lib.dtrace_getopt(h, b'quiet', C.byref(q)) == 0 and q.value == 0
    results.append({'group': 'pragma', 'option': name, 'value': pragma,
                    'expected': want or 'ok', 'actual': actual, 'passed': passed})
    lib.dtrace_close(h)

(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): hashlib.sha256(
    p.read_bytes()).hexdigest() for p in (binary, Path(__file__).resolve())},
    'scope': 'dtrace_setopt/getopt and pragma options; NODEV|NOSYS'}, indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r))
if failed:
    raise SystemExit(1)
print('PASS:', len(results), 'option parsing cases')
