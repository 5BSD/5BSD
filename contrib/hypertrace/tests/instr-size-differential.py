#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Differential test of the x86 instruction-length decoder against LLVM.

dtrace_instr_size_isa() (sys/cddl/dev/dtrace/x86/dis_tables.c, linked into
libdtrace) sizes instructions for pid/fasttrap probe placement; a wrong length
corrupts the traced process.  For each binary, llvm-objdump supplies the
instruction boundaries of .text and the decoder must return the same length
for every instruction, given the real following bytes.  A decoder refusal
(-1) is counted as unsupported, not as agreement; a different length is a
failure.  Read-only use of installed binaries (hashes recorded).
"""
from pathlib import Path
import ctypes as C
import collections
import hashlib
import json
import re
import subprocess
import sys

out, binary = (Path(x).resolve() for x in sys.argv[1:3])
if not out.is_relative_to('/usr/obj') or not binary.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('usage: instr-size-differential.py /usr/obj/new-output /usr/obj/.../libdtrace.so.2')
out.mkdir(parents=True)
TARGETS = [Path(p) for p in ('/bin/sh', '/lib/libc.so.7', '/usr/bin/awk',
                             '/boot/kernel/kernel')] + [binary]
LIMIT = 300000          # instructions per binary, from the start of .text
LP64 = 0                # DATAMODEL_LP64 on amd64 (dtrace_cddl.h)

lib = C.CDLL(str(binary))
lib.dtrace_instr_size_isa.argtypes = [C.c_void_p, C.c_uint, C.POINTER(C.c_int)]
lib.dtrace_instr_size_isa.restype = C.c_int


def text_section(path):
    readelf = subprocess.run(['llvm-readelf', '-SW', str(path)], capture_output=True,
                             text=True, check=True).stdout
    for line in readelf.splitlines():
        fields = line.replace('[', ' ').replace(']', ' ').split()
        if '.text' in fields:
            i = fields.index('.text')
            return int(fields[i + 2], 16), int(fields[i + 3], 16), int(fields[i + 4], 16)
    raise AssertionError('no .text in ' + str(path))


def boundaries(path, start, end):
    """Instruction start addresses and LLVM mnemonics within .text."""
    # -z: do not elide runs of zero bytes.
    cmd = ['llvm-objdump', '-d', '-z', '--no-show-raw-insn', '--section=.text', str(path)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    rows = []
    pattern = re.compile(r'^\s*([0-9a-f]+):\s+(.*)$')
    label = re.compile(r'^([0-9a-f]+) <.*>:$')
    for line in proc.stdout:
        m = label.match(line.strip())
        if m:
            LABELS.add(int(m.group(1), 16))
            continue
        m = pattern.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if start <= addr < end:
            rows.append((addr, ' '.join(m.group(2).split())))
            if len(rows) > LIMIT:
                break
    proc.kill()
    proc.wait()
    # llvm-objdump prints some prefixes on their own line; they belong to
    # the following instruction.
    merged = []
    pending = None
    for addr, mnemonic in rows:
        if mnemonic in PREFIXES:          # a prefix alone on its line
            pending = pending if pending is not None else addr
            continue
        merged.append((pending if pending is not None else addr, mnemonic))
        pending = None
    return merged


PREFIXES = {'lock', 'rep', 'repe', 'repz', 'repne', 'repnz', 'data16', 'data32',
            'addr32', 'cs', 'ds', 'es', 'fs', 'gs', 'ss', 'rex', 'rex64',
            'notrack', 'xacquire', 'xrelease', 'bnd'}


report = {}
failures = []
LABELS = set()
for target in TARGETS:
    addr, offset, size = text_section(target)
    data = target.read_bytes()[offset:offset + size]
    buf = C.create_string_buffer(data + b'\0' * 16, len(data) + 16)
    rows = boundaries(target, addr, addr + size)
    counts = collections.Counter()
    mismatches = []
    refused = []
    rm = C.c_int()
    for (a, mnemonic), nxt in zip(rows, rows[1:]):
        want = nxt[0] - a
        if mnemonic.startswith('<unknown>') or want <= 0 or want > 15:
            counts['skipped-llvm-unknown'] += 1
            continue
        got = lib.dtrace_instr_size_isa(C.addressof(buf) + (a - addr), LP64, C.byref(rm))
        if got == want:
            counts['agree'] += 1
        elif got > want and nxt[0] in LABELS:
            # LLVM restarts at a symbol; padding before it decodes longer.
            counts['skipped-symbol-boundary'] += 1
        elif got < 0:
            counts['decoder-refused'] += 1
            if len(refused) < 40:
                refused.append({'address': hex(a), 'llvm': mnemonic,
                                'bytes': data[a - addr:a - addr + want].hex()})
        else:
            counts['length-mismatch'] += 1
            if len(mismatches) < 40:
                raw = data[a - addr:a - addr + 15]
                mismatches.append({'address': hex(a), 'llvm': mnemonic, 'llvm_length': want,
                                   'decoder_length': got, 'bytes': raw[:max(want, got)].hex()})
    report[str(target)] = {'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                           'counts': dict(counts), 'mismatches': mismatches,
                           'refused': refused}
    if counts['length-mismatch']:
        failures.append(str(target))

(out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'provenance.json').write_text(json.dumps({
    'sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in (binary, Path(__file__).resolve())},
    'oracle': subprocess.run(['llvm-objdump', '--version'], capture_output=True,
                             text=True).stdout.splitlines()[:3],
    'scope': 'x86-64 instruction lengths only; no process is traced'}, indent=2) + '\n')
for target, r in report.items():
    print(target, r['counts'])
    for m in r['mismatches'][:10]:
        print('   ', m)
if failures:
    raise SystemExit('length mismatches in: ' + ', '.join(failures))
print('PASS: decoder lengths agree with LLVM wherever the decoder accepts an instruction')
