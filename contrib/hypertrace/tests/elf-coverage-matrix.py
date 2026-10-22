#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""HyperTrace program ELF writer/parser matrix (dt_elf.cc).

Builds elf-coverage-matrix.c with libdtrace's own compile flags against the
library under test and elf-fault-shim.c as a preloaded fault injector, then
runs the scenarios (round trips, crafted programs, targeted malformed input,
options, input channels, writer and parser fault matrices); see the C file
for the oracles.  Every ELF file written with a manifest is decoded again
here by an independent ELF32 reader written from the ELF specification and
the dt_elf.h record layout, and cross-checked with llvm-readelf and the
elftoolchain readelf.  NODEV (host kernel CTF read-only) or NODEV|NOSYS;
no tracing device, daemon, VM or module load.

usage: elf-coverage-matrix.py /usr/obj/new-output /usr/obj/.../amd64.amd64
"""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit(__doc__.strip().splitlines()[-1])
root = Path(__file__).resolve().parents[3]
out, obj = (Path(a).resolve() for a in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output and an existing object tree')
out.mkdir(parents=True)
tests = Path(__file__).resolve().parent
lib = obj / 'cddl/lib/libdtrace'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])
cflags = subprocess.run(
    ['make', '-C', str(root / 'cddl/lib/libdtrace'), '-m', str(root / 'share/mk'),
     'SRCTOP=' + str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
     '-V', 'CFLAGS'], env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)},
    capture_output=True, text=True, check=True).stdout.split()
keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
harness, shim = out / 'elf-coverage-matrix', out / 'elf-fault-shim.so'
builds = [
    ['cc', '-c', '-fPIC', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
     str(tests / 'elf-fault-shim.c'), '-o', str(out / 'elf-fault-shim.o')],
    ['c++', '-shared', '-fPIC', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
     str(tests / 'elf-fault-new.cc'), str(out / 'elf-fault-shim.o'),
     '-o', str(shim)],
    ['cc', *keep, '-g', '-O0', '-Wall', '-Wno-unknown-pragmas',
     '-Wno-unused-result', str(tests / 'elf-coverage-matrix.c'),
     '-L' + str(lib), '-Wl,-rpath,' + str(lib), '-ldtrace', '-lcrypto',
     '-o', str(harness)]]
with (out / 'build.log').open('w') as log:
    for command in builds:
        log.write(' '.join(command) + '\n')
        log.flush()
        if subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode:
            raise SystemExit('build failed; inspect build.log')

env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
env['LD_PRELOAD'] = str(shim)
# Forked children are numerous: merge their profiles into a small pool next
# to the caller's profile directory (or our output) instead of one per pid.
pool = Path(os.environ['LLVM_PROFILE_FILE']).parent if 'LLVM_PROFILE_FILE' in \
    os.environ else out
env['LLVM_PROFILE_FILE'] = str(pool / 'elf-matrix-%4m.profraw')

scenarios = [('roundtrip',), ('logged',), ('crafted',), ('mutate',), ('io',), ('pfault',),
             ('wfault',)] + [(s, v) for v in ('rt-null', 'drt-null', 'ct')
                             for s in ('options', 'wfault')]


def run(item):
    name = '-'.join(item)
    work = out / name
    work.mkdir()
    r = subprocess.run([str(harness), item[0], str(work), *item[1:]], env=env,
                       capture_output=True, text=True, timeout=3600, cwd=work)
    (out / (name + '.log')).write_text(r.stdout + r.stderr)
    return {'scenario': name, 'status': r.returncode,
            'summary': (r.stdout.strip().splitlines() or [''])[-1]}


with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
    results = list(ex.map(run, scenarios))

# ---------------------------------------------------------------------------
# Independent decoding of every file that has a manifest.
SHT_STRTAB, SHT_DTRACE, SHF_OSNC, PT_PHDR = 3, 0x6eeeeee0, 0x100, 6
DTRACE_NAMES = {'.dtrace_prog', '.dtrace_difo', '.dtrace_actdesc', '.dtrace_ecbdesc',
                '.difo_strtab', '.difo_inttab', '.difo_symtab', '.dtrace_stmtdesc',
                '.dtrace_opts', '.dtrace_vartab', '.dtrace_ident',
                '.dtrace_fmtdata', '.dtrace_pfv_argv'}


def decode(path):
    data = path.read_bytes()
    problems = []
    if data[:7] != b'\x7fELF\x01\x01\x01':
        return None, ['not a 32-bit LSB ELF']
    (etype, machine, _, _, phoff, shoff, _, ehsize, phentsize, phnum,
     shentsize, eshnum, shstrndx) = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
    # The writer requests extended numbering (e_shstrndx = SHN_XINDEX, the
    # count in section 0); libelf also fills e_shnum when it fits.
    if (etype, machine, shstrndx, phnum) != (2, 0, 0xffff, 1):
        problems.append(f'header {etype} {machine} {shstrndx} {phnum}')
    ptype, poffset, _, _, pfilesz = struct.unpack_from('<IIIII', data, phoff)
    if (ptype, poffset, pfilesz) != (PT_PHDR, phoff, phentsize):
        problems.append(f'program header {ptype} {poffset} {pfilesz}')
    s0 = struct.unpack_from('<10I', data, shoff)
    count, strndx = s0[5], s0[6]
    if eshnum not in (0, count) or strndx != 1:
        problems.append(f'section count {eshnum}/{count}, names in {strndx}')
    secs = [struct.unpack_from('<10I', data, shoff + i * shentsize)
            for i in range(count)]
    st = secs[strndx]
    names = data[st[4]:st[4] + st[5]]
    named = [(names[s[0]:].split(b'\0', 1)[0].decode(), s) for s in secs]
    return (data, named), problems


def check_file(path):
    manifest = Path(str(path) + '.manifest').read_text().split('\n')
    decoded, problems = decode(path)
    if decoded is None:
        return problems
    data, named = decoded
    info = {}
    difos = []
    for line in manifest:
        f = line.split()
        if not f:
            continue
        if f[0] == 'difo':
            difos.append(tuple(int(x) for x in f[1:]))
        elif f[0] == 'sizes':
            info['sizes'] = dict(zip(f[1::2], map(int, f[2::2])))
        elif f[0] in ('statements', 'actions', 'ecbs'):
            info[f[0]] = int(f[1])
    sz = info['sizes']
    want_ent = {'.dtrace_actdesc': sz['actdesc'], '.dtrace_ecbdesc': sz['ecbdesc'],
                '.dtrace_stmtdesc': sz['stmt'], '.dtrace_ident': sz['ident'],
                '.dtrace_fmtdata': sz['pfargv'], '.dtrace_pfv_argv': sz['pfargd'],
                '.difo_inttab': 8, '.dtrace_vartab': sz['difv'],
                '.difo_strtab': 0, '.difo_symtab': 0, '.dtrace_opts': 0}
    if named[1][0] != '.shstrtab' or named[1][1][1] != SHT_STRTAB:
        problems.append('section 1 is not .shstrtab')
    if named[2][0] != '.dtrace_prog':
        problems.append('section 2 is not .dtrace_prog')
    if named[-1][0] != '.dtrace_stmt_idname_table' or named[-1][1][1] != SHT_STRTAB:
        problems.append('last section is not the identifier string table')
    found_difos = []
    for i, (name, s) in enumerate(named[2:-1], 2):
        if name not in DTRACE_NAMES or s[1] != SHT_DTRACE or s[2] != SHF_OSNC:
            problems.append(f'section {i} {name} type {s[1]:#x} flags {s[2]:#x}')
        if name in want_ent and s[9] != want_ent[name]:
            problems.append(f'section {i} {name} entsize {s[9]}')
        if name in ('.dtrace_actdesc', '.dtrace_ecbdesc', '.dtrace_stmtdesc',
                    '.dtrace_ident', '.dtrace_fmtdata', '.dtrace_pfv_argv') and \
                s[5] != want_ent[name]:
            problems.append(f'section {i} {name} size {s[5]}')
        if name in ('.difo_inttab', '.dtrace_vartab') and s[5] % want_ent[name]:
            problems.append(f'section {i} {name} size {s[5]}')
        if name == '.dtrace_prog' and s[9] != sz['prog']:
            problems.append(f'program entsize {s[9]}')
        if name == '.dtrace_difo':
            body = data[s[4]:s[4] + s[5]]
            refs = struct.unpack_from('<4I', body, 0)
            lens = struct.unpack_from('<4Q', body, 16)
            n = struct.unpack_from('<Q', body, 64)[0]
            if s[9] != s[5] or s[5] != 72 + 4 * n:
                problems.append(f'DIFO section {i} size {s[5]} for {n} insns')
            found_difos.append((n, *struct.unpack_from(f'<{n}I', body, 72)))
            for ref, length, tname, width in zip(
                    refs, lens, ('.difo_inttab', '.difo_strtab', '.difo_symtab',
                                 '.dtrace_vartab'), (8, 1, 1, sz['difv'])):
                if ref == 0:
                    continue
                if named[ref][0] != tname or named[ref][1][5] != length * width:
                    problems.append(f'DIFO {i} table {tname} ref {ref}')
        if name == '.dtrace_stmtdesc':
            st = struct.unpack_from('<3I', data, s[4])
            self_ref = struct.unpack_from('<I', data, s[4] + s[5] - 4)[0]
            if self_ref != i:
                problems.append(f'statement {i} self reference {self_ref}')
            if st[0] and named[st[0]][0] != '.dtrace_ecbdesc':
                problems.append(f'statement {i} ECB reference')
            for a in st[1:]:
                if a and named[a][0] != '.dtrace_actdesc':
                    problems.append(f'statement {i} action reference')
    counts = {k: sum(1 for n, _ in named if n == sec) for k, sec in
              (('statements', '.dtrace_stmtdesc'), ('actions', '.dtrace_actdesc'),
               ('ecbs', '.dtrace_ecbdesc'))}
    for k, v in counts.items():
        if info[k] != v:
            problems.append(f'{k}: manifest {info[k]} file {v}')
    if sorted(found_difos) != sorted(difos):
        problems.append('DIF instruction arrays differ from the compiled program')
    # Third-party readers agree on the section inventory.
    llvm = subprocess.run(['llvm-readelf', '-S', '--wide', str(path)],
                          capture_output=True, text=True)
    llvm_names = re.findall(r'^\s*\[\s*(\d+)\]\s+(\S*)', llvm.stdout, re.M)
    if llvm.returncode or [n for _, n in llvm_names][1:] != [n for n, _ in named][1:]:
        problems.append('llvm-readelf section inventory differs')
    bsd = subprocess.run(['readelf', '-S', '-W', str(path)],
                         capture_output=True, text=True)
    if bsd.returncode or len(re.findall(r'^\s*\[\s*\d+\]', bsd.stdout, re.M)) != len(named):
        problems.append('elftoolchain readelf section count differs')
    return problems


decoded_files = sorted(out.rglob('*.elf.manifest'))
decode_results = {}
for m in decoded_files:
    elf = Path(str(m)[:-len('.manifest')])
    decode_results[str(elf.relative_to(out))] = check_file(elf)
bad_decode = {k: v for k, v in decode_results.items() if v}

summary = {'scenarios': results, 'decoded_files': len(decode_results),
           'decode_failures': bad_decode}
(out / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (lib / 'libdtrace.so.2', tests / 'elf-coverage-matrix.c',
     tests / 'elf-fault-shim.c', tests / 'elf-fault-new.cc',
     Path(__file__).resolve())},
    'device_mode': 'NODEV (host kernel CTF read-only) and NODEV|NOSYS',
    'fault_injection': 'preloaded shim; documented failure returns of the '
                       'Nth libdtrace-originated call', 'live': False},
    indent=2) + '\n')
failed = [r for r in results if r['status'] != 0]
for r in results:
    print(r['scenario'], r['status'], r['summary'])
for k, v in list(bad_decode.items())[:20]:
    print('decode', k, v)
if failed or bad_decode or not decoded_files:
    raise SystemExit('fail: inspect results.json and the scenario logs')
print(f'PASS: {len(results)} ELF scenarios and {len(decode_results)} '
      'independently decoded files')
