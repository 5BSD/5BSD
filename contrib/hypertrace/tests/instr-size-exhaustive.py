#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Systematic differential of the x86 instruction-length decoder against LLVM.

instr-size-differential.py checks the instructions that occur in real
binaries; this suite generates encodings instead, so rare forms are covered:
every opcode of the one-byte, 0F, 0F38 and 0F3A maps under a set of legacy
and REX prefixes, with ModRM/SIB/displacement shapes for every reg field;
all 256 ModRM bytes for x87 and group opcodes; 3DNow!; and VEX (C5/C4) and
EVEX (62) encodings across maps, W, L and pp.  Both 64-bit and 32-bit modes.

Each candidate is followed by filler bytes and sized independently by
dtrace_instr_size_isa() (sys/cddl/dev/dtrace/x86/dis_tables.c, linked into
libdtrace) and by LLVM's disassembler (libLLVM C API, LLVMDisasmInstruction).

  agree      LLVM decodes it and both lengths are equal
  refused    LLVM decodes it, libdtrace returns -1 (conservative, allowed)
  MISMATCH   LLVM decodes it and the lengths differ: a pid/fasttrap probe
             would be placed mid-instruction.  Fails the suite.
  invalid    LLVM refuses it, or decodes only a prefix by itself (lock,
             rep, data16, a segment or REX prefix): LLVM splits off a prefix
             that cannot apply to what follows, which the CPU rejects (#UD).
             instr_size.c documents that invalid instructions are not
             flagged, so libdtrace may size them; these are counted, not
             judged.
  vendor     a near branch (E8, E9, 0F 80-8F) with an operand-size (66)
             prefix.  In 64-bit mode Intel ignores 66 for near branches and
             AMD honours it (rel16), and LLVM itself is not consistent
             across prefix combinations (66 E9 is rel16, 66 F2 0F 8x rel32,
             even in 32-bit mode); compilers never emit these.  Counted, not
             judged.
"""
from pathlib import Path
import collections
import ctypes as C
import hashlib
import json
import sys

out, binary = (Path(x).resolve() for x in sys.argv[1:3])
if not out.is_relative_to('/usr/obj') or not binary.is_relative_to('/usr/obj') or out.exists():
    raise SystemExit('usage: instr-size-exhaustive.py /usr/obj/new-output '
                     '/usr/obj/.../libdtrace.so.2')
out.mkdir(parents=True)
LLVM = Path('/usr/local/llvm19/lib/libLLVM.so')
MODELS = {'64': (0, b'x86_64-unknown-freebsd'), '32': (1, b'i386-unknown-freebsd')}

lib = C.CDLL(str(binary))
lib.dtrace_instr_size_isa.argtypes = [C.c_char_p, C.c_uint, C.POINTER(C.c_int)]
lib.dtrace_instr_size_isa.restype = C.c_int
llvm = C.CDLL(str(LLVM))
for init in ('LLVMInitializeX86TargetInfo', 'LLVMInitializeX86TargetMC',
             'LLVMInitializeX86Disassembler'):
    getattr(llvm, init)()
llvm.LLVMCreateDisasm.restype = C.c_void_p
llvm.LLVMCreateDisasm.argtypes = [C.c_char_p, C.c_void_p, C.c_int, C.c_void_p, C.c_void_p]
llvm.LLVMDisasmInstruction.restype = C.c_size_t
llvm.LLVMDisasmInstruction.argtypes = [C.c_void_p, C.c_char_p, C.c_uint64, C.c_uint64,
                                       C.c_char_p, C.c_size_t]
FILLER = bytes([0x11] * 16)
PREFIX_ONLY = {'lock', 'rep', 'repe', 'repz', 'repne', 'repnz', 'data16', 'data32', 'addr32',
               'addr16', 'cs', 'ds', 'es', 'fs', 'gs', 'ss', 'rex', 'rex64', 'rex.w', 'rex.b',
               'rex.wb', 'notrack', 'xacquire', 'xrelease', 'bnd'}

# ModRM shapes for each reg field: register; [reg]; SIB [base+index*s];
# SIB with no base (disp32); disp32/RIP; disp8; disp32.
def tails():
    for reg in range(8):
        r = reg << 3
        yield (0xc0 | r,)
        yield (0x00 | r,)
        yield (0x04 | r, 0x24)
        yield (0x04 | r, 0x25, 0, 0, 0, 0)
        yield (0x05 | r, 0, 0, 0, 0)
        yield (0x40 | r, 0x10)
        yield (0x80 | r, 0, 0, 0, 0)


TAILS = list(tails())
PREFIXES = [(), (0x66,), (0xf2,), (0xf3,), (0x67,), (0xf0,), (0x2e,), (0x66, 0xf2),
            (0x48,), (0x41,), (0x66, 0x48)]
MAPS = [(), (0x0f,), (0x0f, 0x38), (0x0f, 0x3a)]
GROUPS = [(op,) for op in range(0xd8, 0xe0)] + [(op,) for op in (0x80, 0x81, 0x83, 0x8f,
          0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7, 0xfe, 0xff)] + \
    [(0x0f, op) for op in (0x00, 0x01, 0x18, 0x1e, 0x71, 0x72, 0x73, 0xae, 0xb9, 0xba,
                           0xc7)]


def candidates():
    for pfx in PREFIXES:
        for m in MAPS:
            for op in range(256):
                for tail in TAILS:
                    yield 'legacy', bytes(pfx + m + (op,) + tail)
    for pfx in ((), (0x66,), (0xf2,), (0xf3,)):
        for g in GROUPS:
            for modrm in range(256):
                yield 'group', bytes(pfx + g + (modrm,))
                if modrm & 0xc7 == 0x04:
                    yield 'group', bytes(pfx + g + (modrm, 0x05, 0, 0, 0, 0))
    for modrm in (0xc1, 0x01, 0x44):
        for suffix in range(256):
            extra = (0x24, 0x00) if modrm == 0x44 else ()
            yield '3dnow', bytes((0x0f, 0x0f, modrm) + extra + (suffix,))
    vex_tails = [(0xc1,), (0x01,), (0x04, 0x24), (0x05, 0, 0, 0, 0), (0x44, 0x24, 0x10),
                 (0x84, 0x24, 0, 0, 0, 0), (0xd1,), (0x11,)]
    # The inverted R/X/B (and EVEX R') extension bits both set (no
    # extension) and clear (extended registers).
    for R in (1, 0):
     for L in (0, 1):
        for pp in range(4):
            for vvvv in (0xf, 0x0):
                b1 = (R << 7) | (vvvv << 3) | (L << 2) | pp
                for op in range(256):
                    for tail in vex_tails:
                        yield 'vex2', bytes((0xc5, b1, op) + tail)
    for rxb, mmmmm in [(r, m) for r in (0xe0, 0x00) for m in (1, 2, 3)]:
        for W in (0, 1):
            for L in (0, 1):
                for pp in range(4):
                    b1, b2 = rxb | mmmmm, (W << 7) | 0x78 | (L << 2) | pp
                    for op in range(256):
                        for tail in vex_tails:
                            yield 'vex3', bytes((0xc4, b1, b2, op) + tail)
    for rxbr, mm in [(r, m) for r in (0xf0, 0x00) for m in (0, 1, 2, 3)]:
        for W in (0, 1):
            for pp in range(4):
                for LL in (0, 1, 2):
                    p0, p1 = rxbr | mm, (W << 7) | 0x7c | pp
                    p2 = (LL << 5) | 0x08
                    for op in range(256):
                        for tail in ((0xc1,), (0x01,), (0x44, 0x24, 0x01), (0x05, 0, 0, 0, 0)):
                            yield 'evex', bytes((0x62, p0, p1, p2, op) + tail)


LEGACY = {0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65}


def is_branch66(enc):
    i, seen66 = 0, False
    while i < len(enc) and (enc[i] in LEGACY or 0x40 <= enc[i] <= 0x4f):
        seen66 |= enc[i] == 0x66
        i += 1
    op = enc[i:i + 2]
    return seen66 and (op[:1] in (b'\xe8', b'\xe9') or
                       (op[:1] == b'\x0f' and len(op) == 2 and op[1] & 0xf0 == 0x80))


report = {}
mismatches = []
rm = C.c_int()
text = C.create_string_buffer(256)
for name, (model, triple) in MODELS.items():
    dc = llvm.LLVMCreateDisasm(triple, None, 0, None, None)
    if not dc:
        raise SystemExit('LLVMCreateDisasm failed for ' + triple.decode())
    counts = collections.Counter()
    for kind, enc in candidates():
        if name == '32' and kind == 'legacy' and enc[:1] in (b'\x48', b'\x41') or \
                name == '32' and enc[:2] == b'\x66\x48':
            continue                     # REX is inc/dec in 32-bit mode
        buf = enc + FILLER
        want = llvm.LLVMDisasmInstruction(dc, buf, len(buf), 0x1000, text, 256)
        got = lib.dtrace_instr_size_isa(buf, model, C.byref(rm))
        words = text.value.decode(errors='replace').split() if want else []
        if want == 0 or all(w in PREFIX_ONLY for w in words):
            counts[kind, 'invalid'] += 1
        elif is_branch66(enc):
            counts[kind, 'vendor'] += 1
        elif got == want:
            counts[kind, 'agree'] += 1
        elif got < 0:
            counts[kind, 'refused'] += 1
        else:
            counts[kind, 'MISMATCH'] += 1
            if len(mismatches) < 4000:
                mismatches.append({'mode': name, 'kind': kind, 'bytes': enc.hex(' '),
                                   'llvm': want, 'libdtrace': got,
                                   'llvm_text': text.value.decode(errors='replace').strip()})
    report[name] = {f'{k}:{v}': n for (k, v), n in sorted(counts.items())}
    print(name, json.dumps(report[name]), flush=True)

(out / 'results.json').write_text(json.dumps({'report': report, 'mismatches': mismatches},
                                             indent=2) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (binary, LLVM, Path(__file__).resolve())}, 'oracle': 'libLLVM 19 LLVMDisasmInstruction'},
    indent=2) + '\n')
total = sum(n for r in report.values() for k, n in r.items() if k.endswith(':MISMATCH'))
for m in mismatches[:40]:
    print(json.dumps(m))
if total:
    raise SystemExit(f'{total} length mismatches against LLVM; see results.json')
print('PASS: no length mismatches;', {k: sum(n for kk, n in r.items() if kk.endswith(':agree'))
                                      for k, r in report.items()}, 'agreeing encodings')
