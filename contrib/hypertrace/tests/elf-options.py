#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Options carried in HyperTrace program ELF from host to guest.

A host handle with HyperTrace enabled sets options, compiles and serializes
a program with dtrace_elf_create().  A guest handle (dtrace_set_guest)
parses it with dtrace_elf_parse(); every runtime option must then read back
with the host's value.  A non-guest parse must not apply options, and
malformed option records must be refused.  NODEV|NOSYS; files under the
output directory only.  Each scenario runs in its own process because the
library keeps HyperTrace option strings in process-global tables.
"""
from pathlib import Path
import ctypes as C
import hashlib
import json
import os
import struct
import subprocess
import sys

OPTIONS = [('bufsize', '8m'), ('aggsize', '2m'), ('switchrate', '10hz'),
           ('strsize', '512'), ('quiet', 'yes'), ('bufpolicy', 'ring'),
           ('aggsortkey', 'yes'), ('stackframes', '7'), ('zdefs', None),
           ('define', 'HT_OPT=1')]
RUNTIME = ['bufsize', 'aggsize', 'switchrate', 'strsize', 'quiet', 'bufpolicy',
           'aggsortkey', 'stackframes']


def load(binary):
    lib = C.CDLL(str(binary))
    lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
    lib.dtrace_open.restype = C.c_void_p
    lib.dtrace_close.argtypes = [C.c_void_p]
    lib.dtrace_enable_hypertrace.argtypes = [C.c_void_p]
    lib.dtrace_set_guest.argtypes = [C.c_void_p]
    lib.dtrace_setopt.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
    lib.dtrace_getopt.argtypes = [C.c_void_p, C.c_char_p, C.POINTER(C.c_int64)]
    lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int,
                                              C.c_uint, C.c_int, C.c_void_p]
    lib.dtrace_program_strcompile.restype = C.c_void_p
    lib.dtrace_elf_create.argtypes = [C.c_void_p, C.c_void_p, C.c_int, C.c_int,
                                      C.c_char_p, C.c_char_p]
    lib.dtrace_elf_create.restype = C.c_int
    lib.dtrace_elf_parse.argtypes = [C.c_void_p, C.c_int, C.c_char_p, C.c_int,
                                     C.POINTER(C.c_int), C.c_char_p, C.c_void_p]
    lib.dtrace_elf_parse.restype = C.c_void_p
    lib.dtrace_errno.argtypes = [C.c_void_p]
    lib.dtrace_errmsg.argtypes = [C.c_void_p, C.c_int]
    lib.dtrace_errmsg.restype = C.c_char_p
    return lib


def handle(lib):
    err = C.c_int()
    h = lib.dtrace_open(3, 3, C.byref(err))
    assert h, err.value
    return h


def getopts(lib, h):
    vals = {}
    for name in RUNTIME:
        v = C.c_int64()
        assert lib.dtrace_getopt(h, name.encode(), C.byref(v)) == 0, name
        vals[name] = v.value
    return vals


def create(lib, path):
    host = handle(lib)
    lib.dtrace_enable_hypertrace(host)
    for name, value in OPTIONS:
        assert lib.dtrace_setopt(host, name.encode(),
                                 None if value is None else value.encode()) == 0, name
    expected = getopts(lib, host)
    prog = lib.dtrace_program_strcompile(host, b'BEGIN { trace(1); }',
                                         4, 0x1004, 0, None)
    assert prog, lib.dtrace_errmsg(host, lib.dtrace_errno(host))
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
    msg = C.create_string_buffer(512)
    assert lib.dtrace_elf_create(host, prog, 1, fd, os.fsencode(path), msg) == 0, msg.value
    os.close(fd)
    return expected


def parse(lib, path, guest):
    h = handle(lib)
    if guest:
        lib.dtrace_set_guest(h)
    before = getopts(lib, h)
    fd = os.open(path, os.O_RDONLY)
    err = C.c_int()
    msg = C.create_string_buffer(512)
    parsed = lib.dtrace_elf_parse(h, fd, os.fsencode(path), 0, C.byref(err), msg, None)
    os.close(fd)
    return parsed, msg.value.decode(errors='replace'), before, getopts(lib, h)


def option_section(content):
    """Offset and size of the option section (the only one holding names)."""
    assert content[:5] == b'\x7fELF\x01'  # ELF32, as elf-roundtrip.py
    start = struct.unpack_from('<I', content, 32)[0]
    width = struct.unpack_from('<H', content, 46)[0]
    count = struct.unpack_from('<H', content, 48)[0]
    for i in range(1, count):
        base = start + i * width
        offset, size = struct.unpack_from('<II', content, base + 16)
        if b'bufsize\0' in content[offset:offset + size] and size >= 80:
            return offset, size
    raise AssertionError('option section not found')


def child(binary, out, scenario):
    lib = load(binary)
    path = out / (scenario + '.elf')
    expected = create(lib, path)
    if scenario == 'guest-applies':
        parsed, msg, before, after = parse(lib, path, True)
        assert parsed, msg
        assert after == expected, (after, expected)
        assert before != expected
    elif scenario == 'host-ignores':
        parsed, msg, before, after = parse(lib, path, False)
        assert parsed, msg
        assert after == before, (after, before)
    else:
        content = bytearray(path.read_bytes())
        offset, size = option_section(content)
        # _dt_elf_eopt_t: name[64], option (8), len (8), arg[]
        if scenario == 'oversized-length':
            struct.pack_into('<Q', content, offset + 72, size * 4)
        elif scenario == 'unterminated-name':
            content[offset:offset + 64] = b'A' * 64
        elif scenario == 'unterminated-argument':
            # Find a record with an argument and overwrite its terminator.
            pos = offset
            while pos < offset + size:
                ln = struct.unpack_from('<Q', content, pos + 72)[0]
                if ln:
                    content[pos + 80:pos + 80 + ln] = b'x' * ln
                    break
                pos += 80 + ln
            else:
                raise AssertionError('no option argument')
        path.write_bytes(bytes(content))
        parsed, msg, before, after = parse(lib, path, True)
        assert not parsed, scenario
        assert 'invalid option name, length or argument' in msg, msg
        assert after == before
    print('PASS:', scenario)


SCENARIOS = ['guest-applies', 'host-ignores', 'oversized-length',
             'unterminated-name', 'unterminated-argument']

if len(sys.argv) == 5 and sys.argv[1] == '--child':
    child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    raise SystemExit(0)
out, binary = (Path(x).resolve() for x in sys.argv[1:])
if not out.is_relative_to('/usr/obj') or not binary.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('usage: elf-options.py /usr/obj/new-output /usr/obj/.../libdtrace.so.2')
out.mkdir(parents=True)
results = []
for scenario in SCENARIOS:
    r = subprocess.run([sys.executable, __file__, '--child', str(binary), str(out), scenario],
                       capture_output=True, text=True, timeout=120)
    (out / (scenario + '.log')).write_text(r.stdout + r.stderr)
    results.append({'scenario': scenario, 'status': r.returncode,
                    'passed': r.returncode == 0 and ('PASS: ' + scenario) in r.stdout})
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): hashlib.sha256(
    p.read_bytes()).hexdigest() for p in (binary, Path(__file__).resolve())},
    'scope': 'Program ELF option round trip; NODEV|NOSYS'}, indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r), (out / (r['scenario'] + '.log')).read_text()[-600:])
if failed:
    raise SystemExit(1)
print('PASS:', len(results), 'ELF option scenarios')
