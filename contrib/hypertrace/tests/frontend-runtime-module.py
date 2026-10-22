#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Kernel module objects, symbols and CTF (dt_module.c) offline.

The driver builds synthetic kernel-module objects with cc, ctfconvert and
ctfmerge (64-bit and 32-bit relocatable objects, a shared object, objects
without or with corrupt CTF, a CTF child of a parent module, a non-ELF file
and objects with crafted section headers).  frontend-runtime-shim.so makes
kldnext/kldstat/kldfirstmod/modnext/modstat report exactly these files, so
dtrace_update() builds its module list from them instead of the running
kernel.  Expected section addresses and symbol values are computed here by
an independent ELF reader following the layout rule documented in
dt_module_update(): allocated sections are placed in file order from the
load address, each aligned to sh_addralign (0 or 1: no constraint); symbols
of relocatable objects are offset by their section's address, symbols of
other objects by load address - first PT_LOAD p_vaddr.  Types are checked
against the C declarations compiled into the objects.
"""
from pathlib import Path
import shutil
import struct
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import frontend_runtime_common as F

out, obj = F.setup('frontend-runtime-module')
src = F.TESTS / 'frontend-runtime-module.c'
shim_src = F.TESTS / 'frontend-runtime-shim.c'
m = out / 'modules'
m.mkdir()

A_C = r'''
struct foo { int a; long b; };
struct fwd;
struct foo gfoo;
struct fwd *fwdp;
static int slocal = 3;
int gdata = 7;
int __attribute__((weak)) wfunc(int x) { return x + slocal; }
int f(int x) { return x + slocal + gdata; }
extern int alias_f(int) __attribute__((alias("f")));
__attribute__((section(".info"))) int info[4] = { 1, 0, 0, 0 };
/* Symbols sharing f's address, one per tie-break rule: a weak alias, a
 * sized untyped alias and an unsized alias. */
extern int walias(int) __attribute__((weak, alias("f")));
__asm__(".globl ntsized\n.set ntsized, f\n.size ntsized, 4\n"
    ".globl zalias\n.set zalias, f\n"
    ".globl abs_sym\n.set abs_sym, 0x1234\n");
extern int undefined_ext(const char *);
int g(int x) { return undefined_ext("a string literal") + x; }
static int resolved(int x) { return x; }
static void *resolver(void) { return (void *)resolved; }
int ifn(int) __attribute__((ifunc("resolver")));
'''
B_C = r'''
struct fwd { int z; char c; };
struct fwd gfwd;
int bfunc(void) { return gfwd.z; }
'''
C_C = r'''
int cvar;
'''
log = []


def sh(*cmd, cwd=m, env=None):
    r = subprocess.run(list(map(str, cmd)), cwd=cwd, capture_output=True, text=True, env=env)
    log.append(' '.join(map(str, cmd)) + '\n' + r.stdout + r.stderr)
    if r.returncode:
        (out / 'objects.log').write_text('\n'.join(log))
        raise SystemExit(f'object build failed: {cmd}')


for name, text in (('a.c', A_C), ('b.c', B_C), ('c.c', C_C)):
    (m / name).write_text(text)
ctf = ['ctfconvert', '-L', 'VERSION']
sh('cc', '-g', '-O0', '-c', 'a.c', '-o', 'm64rel.ko'); sh(*ctf, 'm64rel.ko')
sh('cc', '-g', '-O0', '-fPIC', '-shared', 'a.c', '-o', 'm64dyn.ko'); sh(*ctf, 'm64dyn.ko')
sh('cc', '-m32', '-g', '-O0', '-c', 'a.c', '-o', 'm32rel.ko'); sh(*ctf, 'm32rel.ko')
# No 32-bit runtime is installed: link the 32-bit shared object directly.
sh('cc', '-m32', '-g', '-O0', '-fPIC', '-c', 'a.c', '-o', 'a32pic.o')
sh('ld', '-m', 'elf_i386_fbsd', '-shared', 'a32pic.o', '-o', 'm32dyn.ko'); sh(*ctf, 'm32dyn.ko')
sh('cc', '-O0', '-fPIC', '-shared', 'a.c', '-o', 'nosym.so')
sh('strip', '-o', 'stripped.ko', 'nosym.so')
shutil.copy(m / 'm64rel.ko', m / 'genunix.ko')
shutil.copy(m / 'm64rel.ko', m / 'krtld.ko')
sh('cc', '-O0', '-c', 'a.c', '-o', 'noctf.ko')
sh('cc', '-g', '-O0', '-c', 'b.c', '-o', 'fwdmod.ko'); sh(*ctf, 'fwdmod.ko')
(m / 'garbage.bin').write_bytes(b'\x01not ctf data at all' * 8)
sh('objcopy', '--add-section', '.SUNW_ctf=garbage.bin', 'noctf.ko', 'badctf.ko')
# Child CTF: libctf writes the parent name "PARENT" for a container that
# imported a parent; variants rename it (same length) to an absent module
# and to the child's own module.
MKCHILD = r'''
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <libctf.h>
int main(int argc, char **argv) {
	int err, fd;
	ctf_file_t *p = ctf_open(argv[1], &err), *c = ctf_create(&err);
	ctf_id_t sh, lg, st;
	if (p == NULL || c == NULL || ctf_import(c, p) != 0) return 1;
	sh = ctf_lookup_by_name(p, "struct shared_t");
	lg = ctf_lookup_by_name(p, "long");
	if (sh == CTF_ERR || lg == CTF_ERR) return 2;
	st = ctf_add_struct(c, CTF_ADD_ROOT, "child_t");
	if (st == CTF_ERR || ctf_add_member(c, st, "cs", sh) != 0 ||
	    ctf_add_member(c, st, "extra", lg) != 0 || ctf_update(c) != 0)
		return 3;
	fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
	return (fd < 0 || ctf_write(c, fd) != 0);
}
'''
P_C = r'''
struct shared_t { int s1; int s2; };
long plong;
struct shared_t pshared;
'''
(m / 'p.c').write_text(P_C)
sh('cc', '-g', '-O0', '-c', 'p.c', '-o', 'parentmod.ko'); sh(*ctf, 'parentmod.ko')
(m / 'mkchild.c').write_text(MKCHILD)
sh('cc', *F.cflags(obj), 'mkchild.c', '-L' + str(obj / 'cddl/lib/libctf'), '-lctf', '-lpthread', '-o', 'mkchild')
sh(m / 'mkchild', 'parentmod.ko', 'child.ctf', env=F.env_for(obj))
sh('cc', '-O0', '-c', 'c.c', '-o', 'plain.o')
child = (m / 'child.ctf').read_bytes()
assert child.count(b'\0PARENT\0') == 1, 'child CTF parent name'
for file, parent in (('childmod.ko', b'PARENT'), ('orphan.ko', b'NOPRNT'),
                     ('selfpa.ko', b'SELFPA')):
    (m / (file + '.ctf')).write_bytes(child.replace(b'\0PARENT\0', b'\0' + parent + b'\0'))
    sh('objcopy', '--add-section', f'.SUNW_ctf={file}.ctf', 'plain.o', file)
(m / 'notelf.ko').write_text('this is not an ELF object\n')
# User processes for pid<N> type lookups: one with CTF, one without.  Each
# writes one byte to descriptor 3 once running, then waits to be killed.
(m / 'target.c').write_text(r'''
#include <unistd.h>
struct tfoo { int a; long b; char c[3]; };
struct tfoo tvar;
int main(void) { (void)write(3, "r", 1); for (;;) pause(); }
''')
sh('cc', '-g', '-O0', '-c', 'target.c', '-o', 'target.o'); sh(*ctf, 'target.o')
sh('cc', 'target.o', '-o', 'target'); sh('ctfmerge', '-L', 'VERSION', '-o', 'target', 'target.o')
sh('cc', '-O0', 'target.c', '-o', 'target_noctf')


class Elf:
    def __init__(self, data):
        self.d = data
        self.c64 = data[4] == 2
        if self.c64:
            (self.type, _, _, _, self.phoff, self.shoff, _, _, self.phentsize, self.phnum,
             self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        else:
            (self.type, _, _, _, self.phoff, self.shoff, _, _, self.phentsize, self.phnum,
             self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
        self.secs = []
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            if self.c64:
                n, t, fl, addr, off, size, link, info, al, es = struct.unpack_from('<IIQQQQIIQQ', data, o)
            else:
                n, t, fl, addr, off, size, link, info, al, es = struct.unpack_from('<IIIIIIIIII', data, o)
            self.secs.append(dict(name=n, type=t, flags=fl, addr=addr, off=off, size=size,
                                  link=link, align=al, entsize=es, hdr=o))
        st = self.secs[self.shstrndx] if self.secs else None
        for s in self.secs:
            s['sname'] = self.cstr(st['off'] + s['name'])

    def cstr(self, o):
        if o >= len(self.d):
            return '?'          # name offset outside the file
        return self.d[o:self.d.index(b'\0', o)].decode()

    def phdrs(self):
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            if self.c64:
                t, fl, off, va = struct.unpack_from('<IIQQ', self.d, o)
            else:
                t, off, va = struct.unpack_from('<III', self.d, o)
            yield t, va

    def symbols(self):
        for s in self.secs:
            if s['type'] != 2 or s['sname'] != '.symtab':
                continue
            strs = self.secs[s['link']]
            n = s['size'] // s['entsize']
            for i in range(n):
                o = s['off'] + i * s['entsize']
                if self.c64:
                    name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', self.d, o)
                else:
                    name, value, size, info, other, shndx = struct.unpack_from('<IIIBBH', self.d, o)
                yield dict(name=self.cstr(strs['off'] + name) if name else '', value=value,
                           size=size, type=info & 15, bind=info >> 4, shndx=shndx)


def layout(e, address):
    """Section addresses and module ranges per dt_module_update()."""
    mapbase, secaddr, rng = address, {}, {}
    for i, s in enumerate(e.secs):
        if i == 0 or s['type'] == 0:
            continue
        if s['size'] == 0:
            if s['flags'] & 2:
                secaddr[i] = mapbase   # empty allocated section: current base
            continue
        if s['flags'] & 2:
            al = s['align'] if s['align'] > 1 else 1
            mapbase = (mapbase + al - 1) & ~(al - 1)
            secaddr[i] = mapbase
            mapbase += s['size']
        if s['sname'] in ('.text', '.data', '.bss'):
            rng[s['sname']] = (secaddr.get(i, s['addr']), s['size'])
    return secaddr, rng


def expect(e, name, address, lines, mask):
    secaddr, rng = layout(e, address)
    text_va, text_size = rng.get('.text', (0, 0))
    data_va, data_size = rng.get('.data', (0, 0))
    # .text is extended to the start of .data when .data follows it.
    if data_va > text_va:
        text_size = data_va - text_va
    bss_va, bss_size = rng.get('.bss', (0, 0))
    info = next((s for s in e.secs if s['sname'] == '.info' and s['size']), None)
    # dt_module copies MIN(sh_size, sizeof (objfs_info_t)) bytes.
    primary = info is not None and int.from_bytes(
        e.d[info['off']:info['off'] + min(info['size'], 4)], 'little') != 0
    lines.append(f'obj {name} {text_va:#x} {text_size:#x} '
                 f'{data_va:#x} {data_size:#x} {bss_va:#x} {bss_size:#x} {int(primary)}')
    reloc = 0
    if e.type != 1:
        reloc = next((address - va for t, va in e.phdrs() if t == 1), 0)
    spans = []
    for s in e.symbols():
        if s['type'] >= 7 or s['type'] == 3 or not s['name']:
            continue
        v = s['value']
        if s['bind'] != 0 or s['size']:
            v += reloc
            if e.type == 1 and 0 < s['shndx'] < e.shnum:
                v += secaddr.get(s['shndx'], 0)
        lines.append(f"sym {name} {s['name']} {v & mask:#x} {s['size']:#x} {s['type']} {s['bind']}")
        if s['bind'] != 0 or s['size']:
            spans.append((v & mask, max(s['size'], 1)))
    # Lowest and highest address-mapped symbols (binary-search ends).
    inr = [(v, n) for v, n in spans if
           any(a <= v < a + sz for a, sz in ((text_va, text_size), (data_va, data_size),
                                              (bss_va, bss_size)) if sz)]
    if inr:
        lines.append(f'edge {name} {min(inr)[0]:#x} {max(inr)[0]:#x}')
    # An address inside the module's text range that no address-mapped
    # symbol covers (alignment padding), at or after the first symbol.
    if spans and text_size:
        lo = min(v for v, n in spans if text_va <= v < text_va + text_size) \
            if any(text_va <= v < text_va + text_size for v, n in spans) else None
        for a in range(text_va, text_va + text_size) if lo is not None else ():
            if a >= lo and not any(v <= a < v + n for v, n in spans):
                lines.append(f'gap {name} {a:#x}')
                break


# Crafted objects (patched copies of m64rel.ko):
data = (m / 'm64rel.ko').read_bytes()
e = Elf(data)
# .data with sh_addralign = 0 (ELF: no alignment constraint).
b = bytearray(data)
ds = next(s for s in e.secs if s['sname'] == '.data')
struct.pack_into('<Q', b, ds['hdr'] + 48, 0)
(m / 'align0.ko').write_bytes(b)
# Unknown ELF class.
b = bytearray(data)
b[4] = 0
(m / 'classnone.ko').write_bytes(b)
# Malformed sections: .comment becomes SHT_NULL and another non-allocated
# section gets a name offset outside the section name table.
b = bytearray(data)
cs = next(s for s in e.secs if s['sname'] == '.comment')
struct.pack_into('<I', b, cs['hdr'] + 4, 0)
ns = next(s for s in e.secs if s['sname'] not in ('.text', '.data', '.bss', '.info', '.symtab',
          '.strtab', '.shstrtab', '.SUNW_ctf', '.comment', '') and not s['flags'] & 2)
struct.pack_into('<I', b, ns['hdr'], 0x7fffff00)
(m / 'malformed.ko').write_bytes(b)
# 32-bit tie-break object: symbols sharing f's address that differ in one
# preference rule each (zalias unsized, ntsized untyped, walias weak).
d32 = (m / 'm32rel.ko').read_bytes()
e32 = Elf(d32)
b = bytearray(d32)
st = next(s for s in e32.secs if s['type'] == 2 and s['sname'] == '.symtab')
for i, sy in enumerate(e32.symbols()):
    o = st['off'] + i * st['entsize']
    if sy['name'] == 'zalias':
        struct.pack_into('<I', b, o + 8, 0)                     # st_size
    elif sy['name'] == 'ntsized':
        b[o + 12] = (b[o + 12] & 0xf0) | 0                      # STT_NOTYPE
(m / 'm32tie.ko').write_bytes(b)


def tie_variant(src, dst, c64, reverse):
    """Patch the f-address aliases (zalias unsized, ntsized untyped) and
    optionally reverse the order of the global symbols, so that the sort
    compares each tie in both directions.  Only the symbol table is read
    by dt_module.c; relocations are not applied."""
    d = (m / src).read_bytes()
    el = Elf(d)
    b = bytearray(d)
    st = next(s for s in el.secs if s['type'] == 2 and s['sname'] == '.symtab')
    syms = list(el.symbols())
    for i, sy in enumerate(syms):
        o = st['off'] + i * st['entsize']
        if sy['name'] == 'zalias':
            struct.pack_into('<Q' if c64 else '<I', b, o + (16 if c64 else 8), 0)
        elif sy['name'] == 'ntsized':
            io = o + (4 if c64 else 12)
            b[io] &= 0xf0
    if reverse:
        first = next(i for i, sy in enumerate(syms) if sy['bind'] != 0)
        n, es, base = len(syms), st['entsize'], st['off']
        ents = [bytes(b[base + i * es:base + (i + 1) * es]) for i in range(first, n)]
        for j, ent in enumerate(reversed(ents)):
            b[base + (first + j) * es:base + (first + j + 1) * es] = ent
    (m / dst).write_bytes(b)


tie_variant('m32rel.ko', 'm32tierev.ko', False, True)
tie_variant('m64rel.ko', 'm64tie.ko', True, False)
tie_variant('m64rel.ko', 'm64tierev.ko', True, True)
# An ELF header with no section headers at all.
hd = bytearray((m / 'm64rel.ko').read_bytes()[:64])
struct.pack_into('<Q', hd, 40, 0)          # e_shoff
struct.pack_into('<HHH', hd, 58, 0, 0, 0)  # e_shentsize, e_shnum, e_shstrndx
(m / 'nosect.ko').write_bytes(hd)
sh('strip', '-o', 'm32nosym.ko', 'm32rel.ko')
# Without the absolute symbol, the lowest address-mapped symbol of the
# 32-bit module lies inside the module (first entry of the address map).
sh('objcopy', '--strip-symbol=abs_sym', 'm32rel.ko', 'm32noabs.ko')
# Small objects whose lowest symbol is an unsized label at the start of
# .text (first address-map entry; MAX(st_size, 1) covers its own address)
# and whose .info section is shorter than objfs_info_t.
(m / 'small.c').write_text(r'''
__asm__(".text\n.globl lonelabel\nlonelabel:\n\tnop\n");
int lone(void) { return 1; }
int lone2 = 5;
__attribute__((section(".info"))) char info[2] = { 1, 0 };
''')
sh('cc', '-O0', '-c', 'small.c', '-o', 'm64small.ko')
sh('cc', '-m32', '-O0', '-c', 'small.c', '-o', 'm32small.ko')

ADDR64, ADDR32 = 0xffffffff82000000, 0xc1000000
mods = [('m64rel', 'm64rel.ko', ADDR64), ('fwdmod', 'fwdmod.ko', ADDR64 + 0x100000),
        ('m64dyn', 'm64dyn.ko', ADDR64 + 0x200000), ('m32rel', 'm32rel.ko', ADDR32),
        ('noctf', 'noctf.ko', ADDR64 + 0x400000), ('badctf', 'badctf.ko', ADDR64 + 0x500000),
        ('PARENT', 'parentmod.ko', ADDR64 + 0x600000),
        ('childmod', 'childmod.ko', ADDR64 + 0x700000),
        ('align0', 'align0.ko', ADDR64 + 0x800000),
        ('m32dyn', 'm32dyn.ko', ADDR32 + 0x100000),
        ('stripped', 'stripped.ko', ADDR64 + 0xb00000),
        ('malformed', 'malformed.ko', ADDR64 + 0xc00000),
        ('m32tie', 'm32tie.ko', ADDR32 + 0x200000),
        ('m32nosym', 'm32nosym.ko', ADDR32 + 0x300000),
        ('m32tierev', 'm32tierev.ko', ADDR32 + 0x400000),
        ('m64tie', 'm64tie.ko', ADDR64 + 0xd00000),
        ('m64tierev', 'm64tierev.ko', ADDR64 + 0xe00000),
        ('nosect', 'nosect.ko', ADDR64 + 0xf00000),
        ('m32noabs', 'm32noabs.ko', ADDR32 + 0x500000),
        ('m64small', 'm64small.ko', ADDR64 + 0x1000000),
        ('m32small', 'm32small.ko', ADDR32 + 0x600000)]
lines = []
for name, file, addr in mods:
    ee = Elf((m / file).read_bytes())
    expect(ee, name, addr, lines, 0xffffffffffffffff if ee.c64 else 0xffffffff)
(out / 'expect.txt').write_text('\n'.join(lines) + '\n')
(out / 'objects.log').write_text('\n'.join(log))

shim = F.build(out, obj, shim_src, out / 'frontend-runtime-shim.so', ['-g', '-O1'],
               shared=True, libs=())
results = {}
for name, flags in (('asan', F.SANITIZE), ('faults', F.FAULTS)):
    exe = F.build(out, obj, src, out / f'frontend-runtime-module-{name}', flags,
                  libs=('-ldtrace', '-lctf', '-lelf'))
    results[name] = F.run(out, exe, F.env_for(obj, shim), args=[m, out / 'expect.txt'],
                          timeout=3000)
F.finish(out, obj, results, [src, shim_src, F.TESTS / 'frontend-runtime-shim.h',
         F.TESTS / 'frontend-faults.h'],
         'dt_module.c over synthetic module objects; kernel linker enumeration scripted by a shim')
