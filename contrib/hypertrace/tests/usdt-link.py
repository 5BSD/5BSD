#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""USDT provider linking (dtrace -G) checked against independent oracles.

dtrace -G rewrites the probe call sites of the input objects and emits an
object carrying the providers' DOF.  The oracles never come from libdtrace:

  * call sites: the relocations against __dtrace_<prov>___<probe> and
    __dtraceenabled_<prov>___<probe> in a copy of each object taken before
    the link (llvm-readelf), located in their functions with the symbol
    table;
  * rewriting: LLVM's disassembly of each rewritten site must be no-ops
    (or a ret first, where the call was a tail-call jmp), and an is-enabled
    site must zero %rax/%eax; no relocation may still bind those symbols;
  * DOF: parsed here from the sys/dtrace.h layouts.  Each provider and probe
    of usdt-link.d must appear with its native argument types; each probe's
    function relocation and offsets must match the call sites, is-enabled
    offsets pointing past the zeroing instruction (3 bytes on LP64, 2 on
    ILP32);
  * the objects then link into an executable with no unresolved probe
    symbols; linking the rewritten objects again gives the same DOF.

32-bit objects are linked with -32 (ELF32 output, .rel relocations).
Refusals are checked against the messages in dt_link.c.  No process runs;
dtrace(1) is forced to NODEV|NOSYS.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: usdt-link.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
out, obj = (Path(a).resolve() for a in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output and an existing object tree')
out.mkdir(parents=True)
tests = Path(__file__).resolve().parent
CC, CXX = '/usr/bin/cc', '/usr/bin/c++'
dtrace = obj / 'cddl/usr.sbin/dtrace/dtrace'
drti = obj / 'cddl/lib/drti'
checks = []


def check(name, ok, detail=''):
    checks.append({'check': name, 'passed': bool(ok), 'detail': detail})


def run(cmd, ok=True, **kw):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    if ok and r.returncode:
        raise SystemExit(' '.join(map(str, cmd)) + '\n' + r.stdout + r.stderr)
    return r


(out / 'nodev.c').write_text("""#include <dlfcn.h>
#include <stdlib.h>
void *dtrace_open(int version, int flags, int *errp) {
    void *(*real_open)(int, int, int *) = dlsym(RTLD_NEXT, "dtrace_open");
    if (!real_open) abort();
    return real_open(version, flags | 3, errp);
}
""")
run([CC, '-shared', '-fPIC', '-o', out / 'nodev.so', out / 'nodev.c'])
env = os.environ | {'LD_PRELOAD': str(out / 'nodev.so'), 'LD_LIBRARY_PATH': ':'.join(
    str(obj / p) for p in ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc',
                           'lib/librtld_db'))}
prov = tests / 'usdt-link.d'


def dtrace_g(output, objs, *extra):
    return run([dtrace, *extra, '-G', '-x', 'nolibs', '-x', f'syslibdir={drti}', '-s', prov,
                '-o', output, *objs], ok=False, env=env, cwd=out)


run([dtrace, '-h', '-x', 'nolibs', '-s', prov, '-o', out / 'usdt-link.h'], env=env, cwd=out)

# Provider definitions, parsed from the .d file (the expected DOF content).
want_providers = {}
for name, body in re.findall(r'provider\s+(\w+)\s*\{(.*?)\};', prov.read_text(), re.S):
    want_providers[name] = {
        p.replace('__', '-'): [a.strip() for a in args.split(',') if a.strip()]
        for p, args in re.findall(r'probe\s+(\w+)\((.*?)\);', body)}


# --- ELF helpers -----------------------------------------------------------

def elf_info(path):
    data = path.read_bytes()
    cls = data[4]
    return data, cls


def sections(path):
    r = run(['llvm-readelf', '-SW', path]).stdout
    secs = {}
    for line in r.splitlines():
        m = re.match(r'\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)',
                     line)
        if m:
            secs[m.group(2)] = {'index': int(m.group(1)), 'type': m.group(3),
                                'off': int(m.group(5), 16), 'size': int(m.group(6), 16)}
    return secs


def symbols(path):
    syms = []
    section = None
    for line in run(['llvm-readelf', '-sW', path]).stdout.splitlines():
        m = re.match(r"Symbol table '([^']+)'", line)
        if m:
            section = m.group(1)
            continue
        f = line.split()
        if section == '.symtab' and len(f) >= 8 and f[0][:-1].isdigit() and f[0].endswith(':'):
            syms.append({'value': int(f[1], 16), 'size': int(f[2], 0), 'type': f[3],
                         'bind': f[4], 'ndx': f[6], 'name': f[7]})
    return syms


def relocs(path):
    """{section name: [(offset, type, symbol)]} from llvm-readelf -r."""
    rel, cur = {}, None
    for line in run(['llvm-readelf', '-rW', path]).stdout.splitlines():
        m = re.match(r"Relocation section '([^']+)'", line)
        if m:
            cur = rel.setdefault(m.group(1), [])
            continue
        f = line.split()
        if cur is not None and len(f) >= 3 and re.fullmatch(r'[0-9a-f]+', f[0]):
            cur.append((int(f[0], 16), f[2], f[4] if len(f) > 4 else ''))
    return rel


def call_sites(path):
    """Probe call sites of an object: (provider, probe, enabled, func, off, opcode)."""
    funcs = [s for s in symbols(path) if s['type'] == 'FUNC' and s['ndx'] != 'UND']
    text = sections(path)['.text']
    data = path.read_bytes()
    sites = []
    for sec, rows in relocs(path).items():
        if sec not in ('.rela.text', '.rel.text'):
            continue
        for off, typ, sym in rows:
            m = re.fullmatch(r'__dtrace(enabled)?_(\w+?)___(\w+)', sym)
            if not m:
                continue
            site = off - 1
            f = next(f for f in funcs if f['value'] <= site < f['value'] + f['size'])
            sites.append({'provider': m.group(2), 'probe': m.group(3).replace('__', '-'),
                          'enabled': bool(m.group(1)), 'func': f['name'], 'site': site,
                          'offset': site - f['value'], 'type': typ,
                          'opcode': data[text['off'] + site]})
    return sites


def disasm_at(path, addr, length):
    r = run(['llvm-objdump', '-d', '--no-show-raw-insn', '--section=.text',
             f'--start-address={addr:#x}', f'--stop-address={addr + length:#x}', path]).stdout
    return [' '.join(m.group(1).split()) for m in
            re.finditer(r'^\s*[0-9a-f]+:\s+(.*)$', r, re.M)]


# --- DOF parser (sys/dtrace.h) ---------------------------------------------

DOF_SECT = {8: 'strtab', 15: 'provider', 16: 'probes', 17: 'prargs', 18: 'proffs',
            26: 'prenoffs'}


def parse_dof(path):
    secs = sections(path)
    data = path.read_bytes()
    s = secs['.SUNW_dof']
    dof = data[s['off']:s['off'] + s['size']]
    assert dof[:4] == b'\x7fDOF', dof[:4]
    model = dof[4]
    (flags, hdrsize, secsize, secnum, secoff, loadsz, filesz, pad) = \
        struct.unpack_from('<IIIIQQQQ', dof, 16)
    dsecs = [struct.unpack_from('<IIIIQQ', dof, secoff + i * secsize) for i in range(secnum)]

    def body(i):
        t, align, fl, ent, off, size = dsecs[i]
        return dof[off:off + size], off, ent

    # Relocations of dofpr_addr fields, by offset within .SUNW_dof.
    addr_sym = {}
    for name, rows in relocs(path).items():
        if name in ('.rela.SUNW_dof', '.rel.SUNW_dof'):
            for off, typ, sym in rows:
                addr_sym[off] = sym
    providers = {}
    for i, (t, *_rest) in enumerate(dsecs):
        if t != 15:
            continue
        pv, _, _ = body(i)
        (strtab, probes, prargs, proffs, name, *attrs, prenoffs) = struct.unpack_from(
            '<' + 'I' * 11, pv)
        strs, _, _ = body(strtab)
        string = lambda idx: strs[idx:strs.index(b'\0', idx)].decode()
        pdata, poff, pent = body(probes)
        offs = body(proffs)[0]
        enoffs = body(prenoffs)[0] if prenoffs < len(dsecs) else b''   # else DOF_SECIDX_NONE
        u32 = lambda b, i: struct.unpack_from('<I', b, 4 * i)[0]
        plist = []
        for k in range(len(pdata) // pent):
            (addr, func, pname, nargv, xargv, argidx, offidx, nargc, xargc, noffs,
             enoffidx, nenoffs, _p1, _p2) = struct.unpack_from('<QIIIIIIBBHIHHI', pdata,
                                                                k * pent)
            argv, pos = [], nargv
            for _ in range(nargc):
                argv.append(string(pos))
                pos += len(argv[-1]) + 1
            plist.append({'func': string(func), 'name': string(pname), 'argv': argv,
                          'nargc': nargc, 'xargc': xargc,
                          'offs': [u32(offs, offidx + j) for j in range(noffs)],
                          'enoffs': [u32(enoffs, enoffidx + j) for j in range(nenoffs)],
                          # Generated aliases carry a per-link random key.
                          'addr_sym': re.sub(r'^\$dtrace\d+\.', '$dtrace.',
                                             addr_sym.get(poff + k * pent) or '')})
        providers[string(name)] = plist
    return {'model': model, 'providers': providers}


def compare_dof(label, dof, sites, en_skip, model):
    check(f'{label}: DOF data model', dof['model'] == model, dof['model'])
    check(f'{label}: providers', sorted(dof['providers']) == sorted(want_providers),
          sorted(dof['providers']))
    got = {}
    for pname, plist in dof['providers'].items():
        for p in plist:
            got.setdefault((pname, p['name']), []).append(p)
    for pname, probes in want_providers.items():
        for probe, argv in probes.items():
            entries = got.get((pname, probe), [])
            want_sites = [s for s in sites if s['provider'] == pname and s['probe'] == probe]
            by_func = {}
            for s in want_sites:
                by_func.setdefault(s['func'], {'offs': [], 'enoffs': []})
                by_func[s['func']]['enoffs' if s['enabled'] else 'offs'].append(
                    s['offset'] + (en_skip if s['enabled'] else 0))
            got_func = {}
            for e in entries:
                # Static functions are reached through a generated global alias.
                fname = e['func']
                got_func[fname] = {'offs': sorted(e['offs']), 'enoffs': sorted(e['enoffs'])}
                check(f'{label}: {pname}:{probe} in {fname}: arguments and relocation',
                      e['argv'] == argv and e['nargc'] == len(argv) and
                      e['xargc'] == len(argv) and e['addr_sym'] and
                      (e['addr_sym'] == fname or e['addr_sym'].endswith('.' + fname)),
                      e)
            want_func = {f: {'offs': sorted(v['offs']), 'enoffs': sorted(v['enoffs'])}
                         for f, v in by_func.items()}
            check(f'{label}: {pname}:{probe} sites', got_func == want_func,
                  {'got': got_func, 'want': want_func})


# --- 64-bit link -------------------------------------------------------------

def compile_objects(suffix, flags):
    objs = []
    for src, comp in (('usdt-link-a.c', CC), ('usdt-link-b.cc', CXX)):
        o = out / (Path(src).stem + suffix + '.o')
        run([comp, '-O2', '-I', out, *flags, '-c', tests / src, '-o', o])
        objs.append(o)
    return objs


objs = compile_objects('', [])
orig = []
for o in objs:
    shutil.copyfile(o, o.with_suffix('.orig.o'))
    orig.append(o.with_suffix('.orig.o'))
sites = [s | {'object': o.name} for o in orig for s in call_sites(o)]
check('call sites found in both objects', {s['object'] for s in sites} ==
      {o.name for o in orig} and any(s['enabled'] for s in sites) and
      any(s['opcode'] == 0xe9 for s in sites), sites)
gen = out / 'usdt-link-dof.o'
r = dtrace_g(gen, objs)
check('dtrace -G succeeds', r.returncode == 0, r.stderr)
dof = parse_dof(gen)
compare_dof('64', dof, sites, 3, 2)
# Rewritten sites.
for o, src in zip(objs, orig):
    for s in (x for x in sites if x['object'] == src.name):
        insns = disasm_at(o, s['site'], 5)
        mnems = [i.split()[0] for i in insns]
        if s['enabled']:
            ok = insns[:1] == ['xorq %rax, %rax'] and \
                all(m in ('nop', 'ret', 'retq') for m in mnems[1:])
        else:
            first = ('ret', 'retq') if s['opcode'] == 0xe9 else ('nop',)
            ok = mnems[:1] and mnems[0] in first and all(m == 'nop' for m in mnems[1:])
        check(f"rewritten {s['object']}+{s['site']:#x} "
              f"({s['provider']}:{s['probe']}{' enabled' if s['enabled'] else ''})", ok, insns)
    left = [x for rows in relocs(o).values() for x in rows
            if re.match(r'__dtrace', x[2]) and not x[1].endswith('NONE')]
    check(f'{o.name}: no live relocation to probe symbols', not left, left)
# The objects link into an executable without unresolved probe symbols.
main_o = out / 'usdt-link-main.o'
run([CC, '-c', tests / 'usdt-link-main.c', '-o', main_o])
exe = out / 'usdt-link-exe'
r = run([CXX, main_o, *objs, gen, '-o', exe], ok=False)
check('executable links', r.returncode == 0, r.stderr)
if r.returncode == 0:
    und = run(['llvm-nm', '-u', exe]).stdout
    check('no unresolved probe symbols', '__dtrace' not in und, und)
    check('executable carries the DOF', '.SUNW_dof' in sections(exe), '')
# Linking the already rewritten objects again is accepted and gives the same DOF.
gen2 = out / 'usdt-link-dof-again.o'
before = [o.read_bytes() for o in objs]
r = dtrace_g(gen2, objs)
check('relinking rewritten objects succeeds', r.returncode == 0, r.stderr)
if r.returncode == 0:
    check('relink: same DOF', parse_dof(gen2) == dof, '')
    check('relink: objects unchanged', [o.read_bytes() for o in objs] == before, '')

# Lazy loading: the DOF symbol is ___SUNW_dof and drti.o is not linked in;
# without it, __SUNW_dof and drti's constructor are present.
lazy_objs = compile_objects('-lazy', [])
lazy = out / 'usdt-link-dof-lazy.o'
r = dtrace_g(lazy, lazy_objs, '-x', 'lazyload')
check('dtrace -x lazyload -G succeeds', r.returncode == 0, r.stderr)
if r.returncode == 0:
    lazy_syms = {x['name'] for x in symbols(lazy)}
    eager_syms = {x['name'] for x in symbols(gen)}
    check('lazyload: ___SUNW_dof, no drti', '___SUNW_dof' in lazy_syms and
          'dtrace_dof_init' not in lazy_syms, sorted(lazy_syms))
    check('eager: __SUNW_dof and drti constructor', '__SUNW_dof' in eager_syms and
          'dtrace_dof_init' in eager_syms, sorted(eager_syms))
    check('lazyload: same DOF', parse_dof(lazy) == dof, '')

# --- 32-bit link -------------------------------------------------------------

objs32 = compile_objects('-32', ['-m32'])
sites32 = []
for o in objs32:
    shutil.copyfile(o, o.with_suffix('.orig.o'))
    sites32 += [s | {'object': o.name} for s in call_sites(o.with_suffix('.orig.o'))]
gen32 = out / 'usdt-link-dof32.o'
# No 32-bit drti.o exists without a lib32 build, so the 32-bit DOF is linked
# lazily (no drti.o; see the lazyload checks below).
r = dtrace_g(gen32, objs32, '-32', '-x', 'lazyload')
check('dtrace -32 -G succeeds', r.returncode == 0, r.stderr)
if r.returncode == 0:
    check('ELF32 output', gen32.read_bytes()[4] == 1, gen32.read_bytes()[4])
    dof32 = parse_dof(gen32)
    # Only provider ulink has sites in this object; ulinkb is defined but empty.
    compare_dof('32', dof32, sites32, 2, 1)
    for s in sites32:
        insns = disasm_at(out / s['object'], s['site'], 5)
        mnems = [i.split()[0] for i in insns]
        ok = (insns[:1] == ['xorl %eax, %eax'] and all(m in ('nop', 'ret', 'retl')
                                                        for m in mnems[1:])) \
            if s['enabled'] else (mnems[0] in (('ret', 'retl') if s['opcode'] == 0xe9
                                               else ('nop',)) and
                                  all(m == 'nop' for m in mnems[1:]))
        check(f"rewritten 32-bit {s['object']}+{s['site']:#x} ({s['probe']})", ok, insns)

# --- Refusals ----------------------------------------------------------------


def bad_object(name, symbol, flags=()):
    o = out / f'bad-{name}.o'
    run([CC, *flags, f'-DBAD_SYMBOL={symbol}', '-c', tests / 'usdt-link-bad.c', '-o', o])
    return o


refusals = [
    ('no such probe', [bad_object('probe', '__dtrace_ulink___nosuch')], (),
     'no such probe nosuch'),
    ('no such provider', [bad_object('provider', '__dtrace_nosuchprov___x')], (),
     'no such provider nosuchprov'),
    ('probe name too long', [bad_object('long', '__dtrace_ulink___' + 'a' * 80)], (),
     'invalid probe name'),
    ('call through the GOT (-fno-plt)', [bad_object('noplt', '__dtrace_ulink___zero',
                                                    ('-fno-plt', '-fPIC'))], (),
     'an error was encountered while processing'),
    ('64-bit object in a -32 link', [bad_object('class', '__dtrace_ulink___zero')], ('-32',),
     'incorrect ELF class for object file'),
    ('foreign machine', [bad_object('arm64', '__dtrace_ulink___zero',
                                    ('--target=aarch64-unknown-freebsd',))], (),
     'incorrect ELF machine type for object file'),
]
# Every provider declared in the script needs call sites (usdt-link-a only
# has ulink's).
only_a = out / 'usdt-link-a.only.o'
shutil.copyfile(out / 'usdt-link-a.orig.o', only_a)
refusals.append(('declared provider without call sites', [only_a], (),
                 'No probe sites found for declared provider'))
archive = out / 'usdt-link.a'
run(['ar', 'rcs', archive, bad_object('ar', '__dtrace_ulink___zero')])
refusals.append(('archive input', [archive], (), 'archives are not permitted'))
for label, inputs, extra, message in refusals:
    target = out / ('refused-' + re.sub(r'\W+', '-', label) + '.o')
    r = dtrace_g(target, inputs, *extra)
    check('refused: ' + label, r.returncode != 0 and message in r.stderr and
          not target.exists(), {'rc': r.returncode, 'stderr': r.stderr[-400:]})

(out / 'results.json').write_text(json.dumps({'checks': checks, 'sites': sites,
                                              'dof': dof}, indent=2) + '\n')
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in (
    obj / 'cddl/lib/libdtrace/libdtrace.so.2', dtrace, prov, tests / 'usdt-link-a.c',
    tests / 'usdt-link-b.cc', tests / 'usdt-link-main.c', tests / 'usdt-link-bad.c',
    Path(__file__).resolve())}}, indent=2) + '\n')
failed = [c for c in checks if not c['passed']]
for c in failed:
    print(json.dumps(c)[:1500])
if failed or not checks:
    raise SystemExit(f'{len(failed)} of {len(checks)} USDT link checks failed')
print('PASS:', len(checks), 'USDT link checks')
