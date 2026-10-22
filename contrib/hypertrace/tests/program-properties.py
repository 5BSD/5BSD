#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Program construction, DOF generation, analysis and hash map properties.

Builds program-properties.c twice against the libdtrace under test (ASan and
UBSan for the contract cases; an uninstrumented build with malloc, calloc,
dt_alloc and dt_zalloc interposed for allocation-failure cases) and the
existing vprog-transform.c verifier/transform cases, then checks the files
the harness writes with oracles that do not use libdtrace:

  hashmap.log      MurmurHash3_x86_32 (seed 0xFEEDFACE), linear probing and
                   backward-shift deletion (Knuth 6.4 Algorithm R), plus a
                   dict model of the map's contents and the probe invariant;
  dof-*.bin        an independent DOF decoder applying the dof_hdr_t,
                   dof_sec_t and section-link rules of the kernel loader
                   (dtrace_dof_slurp/_ecbdesc/_difo/_relocate), compared with
                   the program's own statement list (dof-programs.json);
  dof-options.bin  dtrace_getopt_dof() option descriptors.

usage: program-properties.py /usr/obj/new-output /usr/obj/.../amd64.amd64
NODEV/NOSYS or dtrace_vopen() model vectors; no device, daemon or guest.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: program-properties.py /usr/obj/new-output '
                     '/usr/obj/.../amd64.amd64')
root = Path(__file__).resolve().parents[3]
out, obj = (Path(a).resolve() for a in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output and an existing object tree')
out.mkdir(parents=True)
lib = obj / 'cddl/lib/libdtrace'
library = lib / 'libdtrace.so.2'
tests = root / 'contrib/hypertrace/tests'
source = tests / 'program-properties.c'
vprog_source = tests / 'vprog-transform.c'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])
cflags = subprocess.run(
    ['make', '-C', str(root / 'cddl/lib/libdtrace'), '-m', str(root / 'share/mk'),
     'SRCTOP=' + str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
     '-V', 'CFLAGS'], env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)},
    capture_output=True, text=True, check=True).stdout.split()
keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
warn = ['-Wall', '-Wextra', '-Werror', '-Wno-unknown-pragmas',
        '-Wno-unused-parameter', '-Wno-unused-function', '-Wno-string-concatenation']
link = [str(library), '-Wl,-rpath,' + str(lib)]
builds = {
    'program-properties': ['cc', *keep, '-g', '-O1', '-fsanitize=address,undefined',
                           '-fno-sanitize-recover=undefined', *warn, str(source),
                           *link, '-o', str(out / 'program-properties')],
    'program-properties-fault': ['cc', *keep, '-g', '-O0', '-DPP_FAULT', *warn,
                                 str(source), *link, '-o',
                                 str(out / 'program-properties-fault')],
    # The existing transform/verifier cases, with the include set they use.
    'vprog-transform': ['cc', '-std=gnu17', '-g', '-O1', '-fsanitize=address,undefined',
                        '-Wall', '-Wextra', '-Werror', '-Wno-unknown-pragmas',
                        *[f for f in keep if f.startswith('-I') and 'openzfs' not in f
                          and 'libspl' not in f],
                        str(vprog_source), *link, '-o', str(out / 'vprog-transform')],
}
log = []
for name, command in builds.items():
    r = subprocess.run(command, capture_output=True, text=True)
    log.append(' '.join(command) + '\n' + r.stdout + r.stderr)
    if r.returncode:
        (out / 'build.log').write_text('\n'.join(log))
        raise SystemExit(name + ' compilation failed; inspect build.log')
(out / 'build.log').write_text('\n'.join(log))

env = os.environ.copy()
env['LD_LIBRARY_PATH'] = ':'.join(str(obj / p) for p in
    ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc', 'lib/librtld_db'))
env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=0'
env['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1'
results = []


def record(name, ok, detail=None):
    results.append({'case': name, 'passed': bool(ok), 'detail': detail})


runs = {}
for name in ('program-properties', 'program-properties-fault', 'vprog-transform'):
    r = subprocess.run([str(out / name)], cwd=out, env=env, capture_output=True,
                       text=True, timeout=1200)
    (out / (name + '.log')).write_text(r.stdout + r.stderr)
    runs[name] = r
    for line in r.stdout.splitlines():
        m = re.match(r'(PASS|FAIL) ([^:\s]+)', line)
        if m and name != 'vprog-transform':
            record(m.group(2), m.group(1) == 'PASS',
                   None if m.group(1) == 'PASS' else line)
    record(name + '-exit', r.returncode == 0 and 'LLVM Profile Error' not in r.stderr,
           r.returncode)

# ----------------------------------------------------------------------
# Header constants, read from the system headers (not from libdtrace).

H = {}
for header in (root / 'sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h',):
    for m in re.finditer(r'^#define\s+((?:DOF|DTRACEACT|DTRACEAGG|DTRACEOPT|DIF_TYPE|'
                         r'DIF_VERSION|DIF_DIR|DIF_DTR|DIF_OP|DTRACE_D)_?\w*)\s+(.+?)\s*(?:/\*.*)?$',
                         header.read_text(), re.M):
        H[m.group(1)] = m.group(2)


def const(name):
    expr = H[name]
    expr = re.sub(r'\b([A-Z][A-Z0-9_]+)\b', lambda m: str(const(m.group(1))), expr)
    expr = re.sub(r'(\d+)[uUlL]+\b', r'\1', expr)
    return eval(expr, {})


# ----------------------------------------------------------------------
# dt_hashmap reference model.

def murmur3_32(data, seed=0xFEEDFACE):
    c1, c2, mask = 0xcc9e2d51, 0x1b873593, 0xffffffff
    rotl = lambda x, r: ((x << r) | (x >> (32 - r))) & mask
    h = seed
    n = len(data) // 4
    for i in range(n):
        k = int.from_bytes(data[4 * i:4 * i + 4], 'little')
        k = rotl((k * c1) & mask, 15) * c2 & mask
        h = (rotl(h ^ k, 13) * 5 + 0xe6546b64) & mask
    tail = data[4 * n:]
    if tail:
        k = int.from_bytes(tail, 'little')
        k = rotl((k * c1) & mask, 15) * c2 & mask
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = h * 0x85ebca6b & mask
    h ^= h >> 13
    h = h * 0xc2b2ae35 & mask
    return h ^ (h >> 16)


# Published MurmurHash3_x86_32 vectors (seeded), guarding the model itself.
assert murmur3_32(b'', 0) == 0 and murmur3_32(b'', 1) == 0x514E28B7
assert murmur3_32(b'\xff\xff\xff\xff', 0) == 0x76293B50
assert murmur3_32(b'\x21\x43\x65\x87', 0) == 0xF55B516B
assert murmur3_32(b'\x21\x43\x65', 0) == 0x7E4A8634
assert murmur3_32(b'\x21', 0) == 0x72661CF4


def check_hashmap():
    lines = (out / 'hashmap.log').read_text().splitlines()
    problems, maps, ops = [], 0, 0
    size = table = contents = None
    for n, line in enumerate(lines):
        f = line.split()
        if f[0] == 'MAP':
            size = int(f[1])
            table, contents, maps = [None] * size, {}, maps + 1
            continue
        if f[0] == 'T':
            got = {}
            for item in f[1:-1]:
                idx, key, data, *rest = item.split(':')
                got[int(idx)] = (bytes.fromhex(key), int(data))
                if rest:
                    problems.append((n, 'unmanaged key was copied'))
            want = {i: (b[0], b[1]) for i, b in enumerate(table) if b}
            if got != want or int(f[-1][2:]) != len(contents):
                problems.append((n, 'layout', got, want))
            if {k: d for k, d in want.values()} != contents:
                problems.append((n, 'model contents'))
            # Every key is reachable from its home slot without a hole.
            for i, b in want.items():
                j = murmur3_32(b[0]) % size
                while j != i:
                    if table[j] is None:
                        problems.append((n, 'unreachable key'))
                        break
                    j = (j + 1) % size
            continue
        ops += 1
        key = bytes.fromhex(f[1])
        idx = murmur3_32(key) % size
        i = 0
        while i < size and table[idx] is not None and table[idx][0] != key:
            idx, i = (idx + 1) % size, i + 1
        found = i < size and table[idx] is not None
        if f[0] == 'I':
            want = 28 if i == size else 0  # ENOSPC
            if i < size and table[idx] is None:
                table[idx] = (key, int(f[2]))
                contents[key] = int(f[2])
            if int(f[3]) != want:
                problems.append((n, 'insert rc', f[3], want))
        elif f[0] == 'L':
            want = table[idx][1] if found else 0
            if int(f[2]) != want:
                problems.append((n, 'lookup', f[2], want))
        elif f[0] == 'D':
            want = table[idx][1] if found else 0
            if int(f[2]) != want:
                problems.append((n, 'delete', f[2], want))
            if found:
                del contents[key]
                table[idx] = None
                hole, scan = idx, (idx + 1) % size
                while table[scan] is not None:
                    home = murmur3_32(table[scan][0]) % size
                    # Algorithm R: move unless home lies cyclically in
                    # (hole, scan].
                    if not ((hole < home <= scan) if hole <= scan else
                            (home > hole or home <= scan)):
                        table[hole], table[scan], hole = table[scan], None, scan
                    scan = (scan + 1) % size
    record('hashmap-reference-model', not problems and maps == 7 and ops > 2000,
           {'maps': maps, 'ops': ops, 'problems': [repr(p)[:400] for p in problems[:10]]})


# ----------------------------------------------------------------------
# Independent DOF decoder.

SECT = {k[9:]: const(k) for k in H if k.startswith('DOF_SECT_')}
SECIDX_NONE = 0xffffffff


class Dof:
    def __init__(self, data):
        self.d = data
        ident = data[:16]
        assert ident[:4] == b'\x7fDOF', 'magic'
        (self.flags, self.hdrsize, self.secsize, self.secnum, self.secoff,
         self.loadsz, self.filesz, pad) = struct.unpack_from('<IIIIQQQQ', data, 16)
        self.ident = ident
        assert pad == 0 and self.hdrsize == 64 and self.secsize == 32
        assert self.secoff == 64 and self.filesz == len(data)
        assert self.loadsz <= self.filesz
        assert self.secoff + self.secnum * self.secsize <= self.loadsz
        self.secs = []
        for i in range(self.secnum):
            t, al, fl, es, off, sz = struct.unpack_from('<IIIIQQ', data,
                                                          self.secoff + 32 * i)
            assert al and al & (al - 1) == 0 and off % al == 0, ('align', i)
            assert off + sz <= self.filesz, ('bounds', i)
            if fl & const('DOF_SECF_LOAD'):
                assert off + sz <= self.loadsz, ('load bounds', i)
            else:
                assert off >= self.loadsz, ('unloaded section in load', i)
            assert not es or sz % es == 0, ('entsize', i)
            self.secs.append({'type': t, 'align': al, 'flags': fl, 'entsize': es,
                              'off': off, 'size': sz})

    def sec(self, i, *types):
        assert i < self.secnum, ('link', i)
        s = self.secs[i]
        assert s['type'] in [SECT[t] for t in types], ('type', i, s['type'], types)
        return s

    def body(self, s):
        return self.d[s['off']:s['off'] + s['size']]

    def string(self, strsec, off):
        s = self.sec(strsec, 'STRTAB')
        b = self.body(s)
        assert off < len(b), 'string offset'
        end = b.index(b'\0', off)
        return b[off:end].decode()

    def difo(self, i):
        s = self.sec(i, 'DIFOHDR')
        b = self.body(s)
        kind, ckind, flags, pad, size = struct.unpack_from('<BBBBI', b, 0)
        r = {'rtype': [kind, ckind, flags, size], 'buf': [], 'int': [], 'str': [],
             'var': [], 'krel': 0, 'urel': 0, 'xl': 0, 'xlm': [], 'links': []}

        for (link,) in struct.iter_unpack('<I', b[8:]):
            t = self.secs[link]['type']
            body = self.body(self.secs[link])
            r['links'].append(t)
            if t == SECT['DIF']:
                r['buf'] = [x for (x,) in struct.iter_unpack('<I', body)]
            elif t == SECT['INTTAB']:
                r['int'] = [x for (x,) in struct.iter_unpack('<Q', body)]
            elif t == SECT['STRTAB']:
                r['str'] = list(body)
            elif t == SECT['VARTAB']:
                assert self.secs[link]['entsize'] == 20
                r['var'] = [[a, b_, c, d, e, f, g, h, i_, j] for
                            (a, b_, c, d, e, f, g, h, i_, j) in
                            struct.iter_unpack('<IIBBHBBBBI', body)]
            elif t == SECT['XLTAB']:
                r['xl'] = len(body) // 12
                # Each reference names an imported translator and the
                # index of the member within its (referenced-only) list.
                r['xlm'] = []
                for xlator, member, argn in struct.iter_unpack('<III', body):
                    xs = self.sec(xlator, 'XLIMPORT')
                    mem, xst, argv, argc, typ, attr = struct.unpack_from(
                        '<6I', self.d, xs['off'])
                    ms = self.sec(mem, 'XLMEMBERS')
                    ents = list(struct.iter_unpack('<IIBBBBI', self.body(ms)))
                    assert member < len(ents) and argc == 1
                    assert all(m[0] == SECIDX_NONE for m in ents)
                    r['xlm'].append([self.string(xst, ents[member][1]),
                                     argn if argn < 2 ** 31 else argn - 2 ** 32])
                    r.setdefault('xlimports', []).append(
                        (self.string(xst, argv), self.string(xst, typ),
                         [self.string(xst, m[1]) for m in ents]))
            else:
                raise AssertionError(('difo link type', t))
        # Relocation headers whose target is this DIFO's integer table.
        r['kr'], r['ur'] = [], []
        ints = [l for l in struct.unpack_from('<%dI' % ((len(b) - 8) // 4), b, 8)
                if self.secs[l]['type'] == SECT['INTTAB']]
        for h in self.secs:
            if h['type'] not in (SECT['KRELHDR'], SECT['URELHDR']):
                continue
            st, rel, tgt = struct.unpack_from('<III', self.d, h['off'])
            if ints and tgt == ints[0]:
                rs = self.sec(rel, 'RELTAB')
                assert rs['entsize'] == 24
                key = 'kr' if h['type'] == SECT['KRELHDR'] else 'ur'
                for name, typ, off, data in struct.iter_unpack('<IIQQ', self.body(rs)):
                    self.string(st, name)	# names resolve in the DIFO strtab
                    r[key].append([name, typ, off, data])
        r['krel'], r['urel'] = len(r['kr']), len(r['ur'])
        return r

    def ecbs(self):
        res = []
        for s in self.secs:
            if s['type'] != SECT['ECBDESC']:
                continue
            probes, pred, acts, pad, uarg = struct.unpack_from('<IIIIQ', self.d, s['off'])
            assert pad == 0
            ps = self.sec(probes, 'PROBEDESC')
            st, pv, md, fn, nm, pid, vmid = struct.unpack_from('<IIIIIIH', self.d, ps['off'])
            e = {'probe': [self.string(st, x) for x in (pv, md, fn, nm)], 'id': pid,
                 'vmid': vmid, 'uarg': uarg,
                 'pred': None if pred == SECIDX_NONE else self.difo(pred), 'actions': []}
            if acts != SECIDX_NONE:
                a = self.sec(acts, 'ACTDESC')
                assert a['entsize'] == 32
                for off in range(a['off'], a['off'] + a['size'], 32):
                    difo, strtab, kind, ntuple, arg, auarg = struct.unpack_from(
                        '<IIIIQQ', self.d, off)
                    e['actions'].append({
                        'kind': kind, 'ntuple': ntuple, 'uarg': auarg,
                        'arg': None if strtab != SECIDX_NONE else arg,
                        'fmt': self.string(strtab, arg) if strtab != SECIDX_NONE else None,
                        'difo': None if difo == SECIDX_NONE else self.difo(difo)})
            res.append(e)
        return res


CONV = re.compile(r'%([-#0 +\'@]*)(\*|\d+)?(?:\.(\*|\d+))?'
                  r'(hh|h|ll|l|j|z|t|L)?([diouxXs%])')


def fmt_class(f):
    """A format with integer conversions reduced to their class.

    The library re-renders a validated format (dtrace_printf_format), so
    %d may come back as %i and an aggregation's %@d with the length of its
    64-bit value; both denote the same signed/unsigned integer conversion.
    """
    def norm(m):
        flags, width, prec, length, conv = m.groups()
        if conv in 'diu':
            conv = 'I'
        return '%' + flags + (width or '') + ('.' + prec if prec else '') + conv
    return None if f is None else CONV.sub(norm, f)


def strip_links(e):
    if isinstance(e, dict):
        return {k: strip_links(v) for k, v in e.items() if k not in ('links', 'xlimports')}
    if isinstance(e, list):
        return [strip_links(v) for v in e]
    return e


def check_dof():
    manifest = {}
    for line in (out / 'dof.manifest').read_text().splitlines():
        name, kind, rest = line.split(' ', 2)
        manifest[name] = (kind, rest)
    programs = [json.loads(l) for l in (out / 'dof-programs.json').read_text().splitlines()]
    uts = os.uname()
    for prog in programs:
        # dtrace_geterr_dof() always builds unstripped DOF.
        for variant in ('',) if prog['case'] == 'errprog' else ('', '-strip'):
            name = prog['case'] + variant
            kind, path = manifest.get(name, ('missing', ''))
            if kind != 'file':
                record('dof-' + name, False, path)
                continue
            try:
                d = Dof((out / path).read_bytes())
                ident = d.ident
                assert ident[const('DOF_ID_MODEL')] == const('DOF_MODEL_LP64')
                assert ident[const('DOF_ID_ENCODING')] == const('DOF_ENCODE_LSB')
                assert ident[const('DOF_ID_VERSION')] == const('DOF_VERSION_1')
                assert ident[const('DOF_ID_DIFVERS')] == const('DIF_VERSION')
                assert ident[const('DOF_ID_DIFIREG')] == const('DIF_DIR_NREGS')
                assert ident[const('DOF_ID_DIFTREG')] == const('DIF_DTR_NREGS')
                assert d.secs[0]['type'] == SECT['STRTAB']
                assert d.body(d.secs[0])[:1] == b'\0'
                # Actions with a string carry it instead of dtad_arg.
                want = prog['ecbs']
                # The kernel has no TYPECAST (a HyperTrace linker
                # annotation): the DOF carries a nop in its place.
                tc, nop = const('DIF_OP_TYPECAST'), const('DIF_OP_NOP') << 24
                for e in want:
                    for difo in [e['pred']] + [a['difo'] for a in e['actions']]:
                        if difo is not None:
                            difo['buf'] = [nop if x >> 24 == tc else x
                                           for x in difo['buf']]
                    for a in e['actions']:
                        if a['fmt'] is not None:
                            a['arg'] = None
                got = strip_links(d.ecbs())
                for e in want + got:
                    for a in e['actions']:
                        a['fmt'] = fmt_class(a['fmt'])
                assert got == want, ('ecbs', got, want)
                types = [s['type'] for s in d.secs]
                unloaded = [t for t in types if t in (SECT['COMMENTS'], SECT['UTSNAME'])]
                if variant:
                    assert not unloaded and d.loadsz == d.filesz
                else:
                    assert sorted(unloaded) == sorted([SECT['COMMENTS'], SECT['UTSNAME']])
                    c = d.body(d.secs[types.index(SECT['COMMENTS'])])
                    assert c.startswith(b'Sun D ') and c.endswith(b'\0')
                    u = d.body(d.secs[types.index(SECT['UTSNAME'])])
                    assert u[:len(uts.sysname)].decode() == uts.sysname
                    assert d.loadsz < d.filesz
                record('dof-' + name, True)
            except (AssertionError, ValueError, KeyError, IndexError, struct.error) as e:
                record('dof-' + name, False, repr(e)[:3000])
    # Option DOF: exactly the options that are set, one OPTDESC section.
    try:
        d = Dof((out / 'dof-options.bin').read_bytes())
        assert d.secnum == 1 and d.secs[0]['type'] == SECT['OPTDESC']
        assert d.secs[0]['entsize'] == 16
        opts = {o: v for (o, st, v) in struct.iter_unpack('<IIQ', d.body(d.secs[0]))
                if st == SECIDX_NONE}
        assert len(opts) == d.secs[0]['size'] // 16
        assert opts[const('DTRACEOPT_BUFSIZE')] == 4 << 20
        assert const('DTRACEOPT_QUIET') in opts
        assert all(v != 2 ** 63 - 1 and v != 0xffffffffffffffff for v in opts.values())
        record('dof-options', True, {str(k): v for k, v in opts.items()})
    except (AssertionError, ValueError, KeyError, IndexError, struct.error) as e:
        record('dof-options', False, repr(e))


def check_providers():
    manifest = {}
    for line in (out / 'dof.manifest').read_text().splitlines():
        name, kind, rest = line.split(' ', 2)
        manifest[name] = (kind, rest)
    args = {'ent-ry': ['int', 'char *'], 'empty': [], 'three': ['int', 'long', 'char']}
    for case in ('provider-full', 'provider-plain', 'provider-impl', 'provider-xlate',
                 'provider-static'):
        try:
            kind, path = manifest[case]
            assert kind == 'file', path
            d = Dof((out / path).read_bytes())
            inst = [l.split() for l in (out / (case + '.instances')).read_text().splitlines()]
            provs = [i for i, s in enumerate(d.secs) if s['type'] == SECT['PROVIDER']]
            if case == 'provider-xlate':
                # 'other' (one probe) shares the translator export.
                assert len(provs) == 2, ('providers', len(provs))
                po2 = struct.unpack_from('<11I', d.d, d.secs[provs[1]]['off'])
                assert d.string(po2[0], po2[4]) == 'other'
                prex2 = [x for (x,) in struct.iter_unpack('<I', d.body(
                    [s for s in d.secs if s['type'] == SECT['PREXPORT']][1]))]
                provs = provs[:1]
            else:
                assert len(provs) == 1, ('providers', len(provs))
            pv = struct.unpack_from('<11I', d.d, d.secs[provs[0]]['off'])
            strtab, probes, prargs, proffs, name = pv[:5]
            prenoffs = pv[10]
            assert d.string(strtab, name) == 'my'
            ps = d.sec(probes, 'PROBES')
            assert ps['entsize'] == 48
            pa = d.body(d.sec(prargs, 'PRARGS'))
            po = [x for (x,) in struct.iter_unpack('<I', d.body(d.sec(proffs, 'PROFFS')))]
            with_enabled = any(i[3] == '1' for i in inst)
            if with_enabled:
                pe = [x for (x,) in struct.iter_unpack('<I', d.body(d.sec(prenoffs, 'PRENOFFS')))]
            else:
                assert prenoffs == SECT['NONE'], prenoffs
                pe = []
            got = {}
            entries = []
            for k, off in enumerate(range(ps['off'], ps['off'] + ps['size'], 48)):
                (addr, func, pname, nargv, xargv, argidx, offidx, nargc, xargc, noffs,
                 enoffidx, nenoffs, pad1, pad2) = struct.unpack_from('<QIIIIIIBBHIHHI', d.d, off)
                assert addr == 0 and pad1 == 0 and pad2 == 0
                pn, fn = d.string(strtab, pname), d.string(strtab, func)
                strings = d.body(d.secs[strtab])

                def strlist(start, n):
                    res, at = [], start
                    for _ in range(n):
                        e = strings.index(b'\0', at)
                        res.append(strings[at:e].decode())
                        at = e + 1
                    return res
                want_n = args[pn]
                xl = case in ('provider-xlate', 'provider-static') and pn == 'ent-ry'
                want_x = ['struct xx'] if xl else want_n
                if xl:
                    want_n = ['int']
                assert strlist(nargv, nargc) == want_n, (pn, strlist(nargv, nargc))
                assert strlist(xargv, xargc) == want_x, (pn, strlist(xargv, xargc))
                assert list(pa[argidx:argidx + xargc]) == list(range(xargc))
                got[(pn, fn)] = (sorted(po[offidx:offidx + noffs]),
                                 sorted(pe[enoffidx:enoffidx + nenoffs]))
                entries.append(fn)
            want = {}
            for pn, fn, o, en in inst:
                a, b = want.setdefault((pn, fn), ([], []))
                (b if en == '1' else a).append(int(o))
            want = {k: (sorted(a), sorted(b)) for k, (a, b) in want.items()}
            assert got == want, (got, want)
            # One DOFREL relocation per instance, naming its function and
            # pointing at that dof_probe_t (dtrace_helper_provide_one).
            urel = [s for s in d.secs if s['type'] == SECT['URELHDR']]
            assert len(urel) == (2 if case == 'provider-xlate' else 1)
            rs, rr, rt = struct.unpack_from('<III', d.d, urel[0]['off'])
            assert rs == strtab and rt == probes
            rel = d.sec(rr, 'RELTAB')
            relos = list(struct.iter_unpack('<IIQQ', d.body(rel)))
            assert [(d.string(strtab, n), t, o, x) for n, t, o, x in relos] == \
                [(fn, const('DOF_RELO_DOFREL'), 48 * k, 0) for k, fn in enumerate(entries)]
            prex = [s for s in d.secs if s['type'] == SECT['PREXPORT']]
            if case == 'provider-xlate':
                assert len(prex) == 2
                # Both providers name the single exported translator.
                assert len([s for s in d.secs if s['type'] == SECT['XLEXPORT']]) == 1
                assert prex2[1] == [x for (x,) in struct.iter_unpack('<I', d.body(prex[0]))][1]
                ids = [x for (x,) in struct.iter_unpack('<I', d.body(prex[0]))]
                assert ids[0] == provs[0] and len(ids) == 2
                xl = d.sec(ids[1], 'XLEXPORT')
                mem, xst, argv, argc, typ, attr = struct.unpack_from('<6I', d.d, xl['off'])
                assert argc == 1 and d.string(xst, argv) == 'int'
                assert d.string(xst, typ) == 'struct xx'
                ms = d.sec(mem, 'XLMEMBERS')
                members = []
                for (difo, mname, tk, tck, tfl, tpad, tsz) in struct.iter_unpack(
                        '<IIBBBBI', d.body(ms)):
                    dd = d.difo(difo)
                    members.append((d.string(xst, mname), tk, tsz, len(dd['buf']) > 0))
                assert members == [('a', const('DIF_TYPE_CTF'), 4, True),
                                   ('b', const('DIF_TYPE_CTF'), 4, True)], members
            else:
                assert not prex
            record('dof-' + case, True)
        except (AssertionError, ValueError, KeyError, IndexError, struct.error,
                OSError) as e:
            record('dof-' + case, False, repr(e)[:3000])


# DOF_SECF_LOAD and friends are defined with parentheses in the header.
try:
    check_hashmap()
except (OSError, ValueError, IndexError) as e:
    record('hashmap-reference-model', False, repr(e))
try:
    check_dof()
    check_providers()
except (OSError, ValueError) as e:
    record('dof-decode', False, repr(e))

(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (library, source, vprog_source, Path(__file__).resolve())},
    'scope': 'dt_program/dt_dof/dt_analysis/dt_hashmap contracts; NODEV/NOSYS and '
             'dtrace_vopen model vectors; no device, daemon or guest'},
    indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r)[:1500])
if failed or not results:
    raise SystemExit('program properties failed; inspect results.json')
print('PASS:', len(results), 'program, DOF, analysis and hash map cases')
