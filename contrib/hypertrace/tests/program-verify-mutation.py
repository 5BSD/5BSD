#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exhaustive single-byte mutation of serialized programs against dt_prog_verify.

Builds program-verify-mutation.c with libdtrace's own compile flags and
ASan/UBSan against the library under test; see the C file for the oracle
(an accepted mutant must keep the compiled-program digest).  NODEV|NOSYS.
"""
from pathlib import Path
import hashlib
import re
import struct
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: program-verify-mutation.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
root = Path(__file__).resolve().parents[3]
out, obj = (Path(arg).resolve() for arg in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output and an existing object tree')
out.mkdir(parents=True)
lib = obj / 'cddl/lib/libdtrace'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])
cflags = subprocess.run(
    ['make', '-C', str(root / 'cddl/lib/libdtrace'), '-m', str(root / 'share/mk'),
     'SRCTOP=' + str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
     '-V', 'CFLAGS'], env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)},
    capture_output=True, text=True, check=True).stdout.split()
keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
source = root / 'contrib/hypertrace/tests/program-verify-mutation.c'
command = ['cc', *keep, '-g', '-O1', '-fsanitize=address,undefined',
           '-fno-sanitize-recover=undefined', '-Wall', '-Wno-unknown-pragmas',
           str(source), '-L' + str(lib), '-Wl,-rpath,' + str(lib), '-ldtrace',
           '-o', str(out / 'program-verify-mutation')]
build = subprocess.run(command, capture_output=True, text=True)
(out / 'build.log').write_text(' '.join(command) + '\n' + build.stdout + build.stderr)
if build.returncode:
    raise SystemExit('harness compilation failed; inspect build.log')
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
env['ASAN_OPTIONS'] = 'detect_leaks=0'
r = subprocess.run([str(out / 'program-verify-mutation')], cwd=out, env=env,
                   capture_output=True, text=True, timeout=3600)
(out / 'run.log').write_text(r.stdout + r.stderr)
lines = [l for l in r.stdout.splitlines() if l.startswith('program ')]


def field_map(data):
    """(section name, offset in section) for each byte of a program ELF."""
    shoff = struct.unpack_from('<I', data, 32)[0]
    width = struct.unpack_from('<H', data, 46)[0]
    s0 = struct.unpack_from('<10I', data, shoff)
    count = struct.unpack_from('<H', data, 48)[0] or s0[5]
    strndx = struct.unpack_from('<H', data, 50)[0]
    if strndx in (0, 0xffff):
        strndx = s0[6]
    secs = [struct.unpack_from('<10I', data, shoff + i * width) for i in range(count)]
    names = data[secs[strndx][4]:secs[strndx][4] + secs[strndx][5]]

    def where(offset):
        for sec in secs[1:]:
            if sec[4] <= offset < sec[4] + sec[5]:
                return names[sec[0]:].split(b'\0')[0].decode(), offset - sec[4]
        return 'header', offset
    return where


# Accepted mutants whose compiled program changed, by field:
#  vartab type size  - relinking legitimately changes variable sizes and the
#                      verifier reconciles them (by design);
#  difo rtype        - accepted only when the original's return type is
#                      DIF_TYPE_BOTTOM (resolved by relinking): a known gap;
#  anything else     - a verifier escape (failure).
classes = {'by-design: variable size reconciliation': 0,
           'known gap: BOTTOM-typed DIFO return type': 0}
escapes = []
for l in r.stdout.splitlines():
    m = re.match(r'VIOLATION program (\d+) offset (-?\d+) mask (0x[0-9a-f]+)', l)
    if not m:
        continue
    prog, offset = int(m.group(1)), int(m.group(2))
    if offset < 0:
        escapes.append({'program': prog, 'field': 'unmodified file', 'line': l})
        continue
    where = field_map((out / f'program-{prog}.elf').read_bytes())
    name, rel = where(offset)
    if name == '.dtrace_vartab' and 16 <= rel % 136 < 20:
        classes['by-design: variable size reconciliation'] += 1
    elif name == '.dtrace_difo' and 48 <= rel < 56:
        classes['known gap: BOTTOM-typed DIFO return type'] += 1
    else:
        escapes.append({'program': prog, 'field': f'{name}+{rel}', 'line': l})
# Targeted return-type mutants on BOTTOM-typed host DIFOs (see the C file).
bottom = [l.split() for l in r.stdout.splitlines() if l.startswith('bottom-rtype ')]
bottom_wrong = [' '.join(b) for b in bottom if b[2] != b[4]]
if not bottom:
    bottom_wrong.append('no bottom-rtype mutants ran')
(out / 'results.json').write_text(json.dumps({'returncode': r.returncode,
    'bottom_rtype': [' '.join(b) for b in bottom], 'bottom_rtype_wrong': bottom_wrong,
    'summary': lines, 'accepted_changes_by_class': classes,
    'escapes': escapes[:200]}, indent=2) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (lib / 'libdtrace.so.2', source, Path(__file__).resolve())},
    'scope': 'byte mutation of program ELF, parser and verifier; NODEV|NOSYS'},
    indent=2) + '\n')
print('\n'.join(lines))
print(json.dumps(classes))
for b in bottom_wrong:
    print('bottom-rtype mismatch:', b)
if escapes or bottom_wrong or r.returncode != 0:
    for e in escapes[:20]:
        print(json.dumps(e))
    raise SystemExit('program verifier mutation found escapes; inspect results.json')
print('PASS: no mutated program escaped verification outside the documented classes')
