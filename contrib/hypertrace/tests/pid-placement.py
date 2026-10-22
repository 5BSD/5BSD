#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""pid provider probe placement checked against LLVM's disassembly.

libdtrace decides where entry, return and offset probes go in a stopped
target; pid-placement-shim.so records the FASTTRAPIOC_MAKEPROBE requests on
an inert descriptor.  Expected offsets come from llvm-objdump/llvm-nm of the
same target binary:

  entry    offset 0
  return   every ret, and every direct jmp/jcc whose target lies outside
           the function (tail calls)
  *        entry, return, and every instruction boundary
  :N       exactly N when N is an instruction boundary; refused otherwise

Diagnostics are checked against the messages dt_pid.c documents for each
refusal (bad provider, pid, name, offset, '-' function misuse, failed
MAKEPROBE).  Every successful creation must ask the kernel to re-evaluate
retained enablings with a DTRACEIOC_ENABLE whose DOF pointer is NULL (never a
NULL ioctl argument, which the ioctl layer cannot copy in).

USDT: a target linked with dtrace -G must have its DOF registered through
DTRACEHIOC_ADDDOF with the symbol address from llvm-nm, base 0 for ET_EXEC,
and the object's name; the helper device is replaced by the shim.  A library
dlopen()ed after compilation must get its pid and USDT probes when the
run-time linker reports it, at the base the target itself reports (dladdr).
Argument types of pid probes come from the target's CTF (ctfconvert) and must
match the C declaration.

The targets are created stopped; only the late-load target runs (it loads
the library and exits).  No tracing device or kernel fasttrap is used.
"""
from pathlib import Path
import hashlib
import json
import os
import fnmatch
import re
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: pid-placement.py /usr/obj/new-output /usr/obj/.../amd64.amd64')
root = Path(__file__).resolve().parents[3]
tests = root / 'contrib/hypertrace/tests'
out, obj = (Path(a).resolve() for a in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, obj)) or out.exists():
    raise SystemExit('Use a new /usr/obj output and an existing object tree')
out.mkdir(parents=True)
lib = obj / 'cddl/lib/libdtrace'
prefix = Path(*obj.parts[:obj.parts.index('usr', 3)])


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode:
        raise SystemExit(' '.join(map(str, cmd)) + '\n' + r.stdout + r.stderr)
    return r.stdout


# Targets use the system compiler: never coverage-instrumented, whatever
# compiler wrapper is first in PATH.
CC = '/usr/bin/cc'
target = out / 'pid-target'
run([CC, '-O2', '-fno-jump-tables', '-g', '-c', str(tests / 'pid-target.c'),
     '-o', str(out / 'pid-target.o')])
run([CC, '-O2', '-g', '-c', str(tests / 'pid-target-switch.c'),
     '-o', str(out / 'pid-target-switch.o')])
run([CC, '-c', str(tests / 'pid-target-asm.S'), '-o', str(out / 'pid-target-asm.o')])
run([CC, str(out / 'pid-target.o'), str(out / 'pid-target-switch.o'),
     str(out / 'pid-target-asm.o'), '-o', str(target)])
# The same program with only a dynamic symbol table, and with CTF (made as
# the FreeBSD build does: ctfconvert per object, then ctfmerge).
dyn = out / 'pid-target-dyn'
run([CC, '-rdynamic', str(out / 'pid-target.o'), str(out / 'pid-target-switch.o'),
     '-o', str(dyn)])
run(['strip', str(dyn)])
# The CTF target, and a copy whose name contains '-' (which D scoped type
# names must accept).
ctf_target = out / 'pidtypes'
ctf_dash = out / 'pid-types'
ctf_objs = []
for stem in ('pid-target', 'pid-target-switch'):
    o = out / (stem + '-ctf.o')
    run(['cp', str(out / (stem + '.o')), str(o)])
    run(['ctfconvert', '-L', 'pid-target', str(o)])
    ctf_objs.append(str(o))
run([CC, *ctf_objs, '-o', str(ctf_target)])
run(['ctfmerge', '-L', 'pid-target', '-o', str(ctf_target), *ctf_objs])
if '.SUNW_ctf' not in run(['readelf', '-S', str(ctf_target)]):
    raise SystemExit('ctfmerge produced no .SUNW_ctf section')
run(['cp', str(ctf_target), str(ctf_dash)])
# USDT objects through the instrumented dtrace(1), forced to NODEV|NOSYS.
nodev = out / 'nodev.c'
nodev.write_text("""#include <dlfcn.h>
#include <stdlib.h>
void *dtrace_open(int version, int flags, int *errp) {
    void *(*real_open)(int, int, int *) = dlsym(RTLD_NEXT, "dtrace_open");
    if (!real_open) abort();
    return real_open(version, flags | 3, errp);
}
""")
run(['cc', '-shared', '-fPIC', '-o', str(out / 'nodev.so'), str(nodev)])
dtrace_env = os.environ | {'LD_PRELOAD': str(out / 'nodev.so'), 'LD_LIBRARY_PATH': ':'.join(
    str(obj / p) for p in ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc',
                           'lib/librtld_db'))}
dtrace_bin = obj / 'cddl/usr.sbin/dtrace/dtrace'
drti_dir = obj / 'cddl/lib/drti'


def usdt_object(provider, source, pic):
    stem = source.stem
    run([str(dtrace_bin), '-h', '-x', 'nolibs', '-s', str(tests / provider), '-o',
         str(out / (Path(provider).stem + '.h'))], env=dtrace_env)
    run([CC, '-g', '-I' + str(out), *(['-fPIC'] if pic else []), '-c', str(source),
         '-o', str(out / (stem + '.o'))])
    run([str(dtrace_bin), '-G', '-x', 'nolibs', '-x', 'syslibdir=' + str(drti_dir), '-s',
         str(tests / provider), '-o', str(out / (stem + '-dof.o')), str(out / (stem + '.o'))],
        env=dtrace_env)
    return [str(out / (stem + '.o')), str(out / (stem + '-dof.o'))]


usdt_exe = out / 'pid-usdt-exe'
run([CC, *usdt_object('pid-usdt-exe.d', tests / 'pid-usdt-exe.c', False), '-o',
     str(usdt_exe)])
late_lib = out / 'libhtlate.so'
run([CC, '-shared', *usdt_object('pid-late.d', tests / 'pid-late-lib.c', True), '-o',
     str(late_lib)])
late_target = out / 'pid-late-target'
run([CC, '-g', str(tests / 'pid-late-target.c'), '-o', str(late_target)])
none_lib = out / 'libhtnone.so'
run([CC, '-shared', '-fPIC', '-g', str(tests / 'pid-late-none.c'), '-o', str(none_lib)])
shim = out / 'pid-placement-shim.so'
run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror', '-Wno-unknown-pragmas',
     '-I' + str(root / 'sys/cddl/compat/opensolaris'),
     '-I' + str(root / 'sys/cddl/contrib/opensolaris/uts/intel'),
     '-I' + str(root / 'sys/cddl/contrib/opensolaris/uts/common'),
     '-I' + str(root / 'sys'), str(tests / 'pid-placement-shim.c'), '-o', str(shim)])
cflags = run(['make', '-C', str(root / 'cddl/lib/libdtrace'), '-m', str(root / 'share/mk'),
              'SRCTOP=' + str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
              '-V', 'CFLAGS'], env=os.environ | {'MAKEOBJDIRPREFIX': str(prefix)}).split()
keep = [f for f in cflags if f.startswith(('-I', '-D', '-std='))]
harness = out / 'pid-placement'
run(['cc', *keep, '-I' + str(root / 'lib/libproc'), '-g', '-O1',
     '-fsanitize=undefined', '-Wall', '-Wno-unknown-pragmas',
     str(tests / 'pid-placement.c'), '-L' + str(lib), '-L' + str(obj / 'lib/libproc'),
     '-L' + str(obj / 'cddl/lib/libctf'), '-Wl,-rpath,' + str(lib), '-ldtrace', '-lproc',
     '-lctf', '-o', str(harness)])

# Oracle: function sizes and instructions from LLVM.
sizes = {}
for line in run(['llvm-nm', '-S', '--defined-only', str(target)]).splitlines():
    f = line.split()
    if len(f) == 4 and f[3].startswith('ht_'):
        sizes[f[3]] = (int(f[0], 16), int(f[1], 16))
insns = {name: [] for name in sizes}
PREFIXES = {'lock', 'rep', 'repe', 'repz', 'repne', 'repnz', 'data16', 'addr32', 'cs', 'ds',
            'es', 'fs', 'gs', 'ss', 'notrack', 'xacquire', 'xrelease'}
current = None
for line in run(['llvm-objdump', '-d', '-z', '--no-show-raw-insn', str(target)]).splitlines():
    m = re.match(r'^[0-9a-f]+ <(\w+)>:$', line)
    if m:
        current = m.group(1) if m.group(1) in insns else None
        continue
    m = re.match(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$', line)
    if current and m:
        # objdump prints a lone prefix (lock, rep, ...) on its own line;
        # the prefix belongs to the next instruction.
        if insns[current] and insns[current][-1][1] in PREFIXES and not insns[current][-1][2]:
            addr = insns[current].pop()[0]
            insns[current].append((addr, m.group(2), m.group(3)))
        else:
            insns[current].append((int(m.group(1), 16), m.group(2), m.group(3)))


def expected(name, kind):
    start, size = sizes[name]
    rows = [r for r in insns[name] if start <= r[0] < start + size]
    if kind == 'entry':
        return [0]
    if kind == 'offsets':
        return [a - start for a, _, _ in rows]
    offs = []
    for a, mnem, ops in rows:
        if mnem in ('ret', 'retq'):
            offs.append(a - start)
        elif mnem.startswith('j'):
            t = re.match(r'(0x)?([0-9a-f]+)', ops)
            if t and not (start <= int(t.group(2), 16) < start + size):
                offs.append(a - start)
    return offs


branch_start = sizes['ht_branch'][0]
second = insns['ht_branch'][1][0] - branch_start
first_len = second
misaligned = 1 if first_len > 1 else None
leaf_start, leaf_size = sizes['ht_leaf']
leaf_second = insns['ht_leaf'][1][0] - leaf_start
specs = [':a.out:ht_branch:entry', ':a.out:ht_branch:return', ':a.out:ht_tail:return',
         ':a.out:ht_leaf:*', ':a.out:ht_*:entry', f':a.out:ht_branch:{second:x}',
         ':a.out:ht_unknown:*', ':a.out:ht_switch:return', ':a.out:ht_switch:*']
if misaligned is not None:
    specs.append(f':a.out:ht_branch:{misaligned:x}')
# Refusals, documented in dt_pid.c, and module-name forms.
refusals = {
    ':a.out:ht_leaf:zz': "'zz' is an invalid probe name",
    f':a.out:ht_leaf:{leaf_size:x}': f"offset 0x{leaf_size:x} outside of function 'ht_leaf'",
    ':a.out:ht_nosuch:entry': "failed to lookup 'ht_nosuch' in module",
    ':libc.so.7:-:10': "only the a.out module is valid with the '-' function",
    ':pid-targ*:-:10': "only the a.out module is valid with the '-' function",
    ':a.out:-:*': "only individual addresses may be specified with the '-' function",
    '!1:a.out:ht_leaf:entry': "failed to create entry probe for 'ht_leaf'",
    '!2:a.out:ht_leaf:return': "failed to create return probe for 'ht_leaf'",
    f'!3:a.out:ht_leaf:{leaf_second:x}': f"failed to create probe at 'ht_leaf+0x{leaf_second:x}'",
    '!3:a.out:ht_leaf:*': "failed to create offset probes in 'ht_leaf'",
    '=pid0:a.out:ht_leaf:entry': "'pid0' does not contain a valid pid",
    '=pid99999999999999999999:a.out:ht_leaf:entry':
        "'pid99999999999999999999' does not contain a valid pid",
    '=pid999999:a.out:ht_leaf:entry': 'failed to grab process 999999',
    # Not the pid provider, so only USDT discovery tries to grab it.
    '=htx999999:::go': 'failed to grab process 999999',
}
# Accepted forms: expected (func, type, offsets) requests.
entry_leaf = [('ht_leaf', 'entry', [0])]
accepted = {
    ':LM0`a.out:ht_leaf:entry': entry_leaf,
    ':pid-targ*:ht_leaf:entry': entry_leaf,
    '=pi?PID:a.out:ht_leaf:entry': entry_leaf,
    f':a.out:-:{leaf_start:x}': [('-', 'offsets', [leaf_start])],
    f'::-:{leaf_start:x}': [('-', 'offsets', [leaf_start])],
    ':LMx`a.out:ht_leaf:entry': [],
    ':LM0`a`b:ht_leaf:entry': [],
    ':pid-targ*:ht_nosuch:entry': [],
    ':a.out:ht_nosuch*:entry': [],
    '=htnonePID:::go': [],
    # Explicit names that are not defined functions of non-zero size.
    ':a.out:environ:entry': [],
    ':a.out:_init:entry': [],
}
# Hand-assembled return forms (pid-target-asm.S); offsets from its layout.
rets_returns = [0, 1, 3, 6, 10, 15, 17, 23, 34]
rets_bounds = [0, 1, 3, 6, 10, 15, 17, 23, 25, 27, 33, 34]
accepted.update({
    '@:a.out:ht_rets:return': [('ht_rets', 'return', rets_returns)],
    # Without the original instruction the breakpoint byte cannot be
    # decoded, so libdtrace assumes a jump table: no ret/jmp forms count.
    ':a.out:ht_rets:return': [],
    '@:a.out:ht_rets:1*': [('ht_rets', 'offsets',
                            [o for o in rets_bounds if fnmatch.fnmatchcase(f'{o:x}', '1*')])],
    '@:a.out:ht_rets:?': [('ht_rets', 'offsets',
                           [o for o in rets_bounds if len(f'{o:x}') == 1])],
    ':a.out:ht_jt:return': [('ht_jt', 'return', [1, 3, 8, 12])],
    ':a.out:ht_jt:2': [],
})
specs += list(refusals) + list(accepted) + [':a.out:*:entry', '@:a.out:ht_rets:*',
                                            ':a.out:ht_jt:*']
env = os.environ | {'LD_PRELOAD': str(shim), 'LD_LIBRARY_PATH': ':'.join(
    str(obj / p) for p in ('cddl/lib/libdtrace', 'cddl/lib/libctf', 'lib/libproc',
                           'lib/librtld_db'))}


def harness_run(name, args, timeout=180):
    r = subprocess.run([str(harness), *map(str, args)], env=env, capture_output=True,
                       text=True, timeout=timeout, cwd=out)
    (out / (name + '.log')).write_text(r.stdout + r.stderr)
    return r, [json.loads(line) for line in r.stdout.splitlines() if line.startswith('{')]


r, results = harness_run('run', [target, *specs])
checks = []


def check(name, ok, detail):
    checks.append({'check': name, 'passed': bool(ok), 'detail': detail})


target_pid = next(x['target_pid'] for x in results if 'target_pid' in x)
by_spec = {x['spec']: x for x in results if 'spec' in x}
for func, kind in (('ht_branch', 'entry'), ('ht_branch', 'return'), ('ht_tail', 'return')):
    got = by_spec.get(f':a.out:{func}:{kind}', {'requests': []})['requests']
    want = expected(func, kind)
    check(f'{func}:{kind}', len(got) == 1 and got[0]['type'] == kind and
          got[0]['func'] == func and got[0]['pid'] == target_pid and
          got[0]['size'] == sizes[func][1] and got[0]['offs'] == want,
          {'got': got, 'want': want})
star = by_spec.get(':a.out:ht_leaf:*', {'requests': []})['requests']
want_star = {k: expected('ht_leaf', k) for k in ('entry', 'return', 'offsets')}
got_star = {q['type']: q['offs'] for q in star if q['func'] == 'ht_leaf'}
check('ht_leaf:*', got_star == want_star, {'got': got_star, 'want': want_star})
glob = by_spec.get(':a.out:ht_*:entry', {'requests': []})['requests']
check('ht_*:entry', sorted((q['func'], q['type'], tuple(q['offs'])) for q in glob) ==
      sorted((f, 'entry', (0,)) for f in sizes), glob)
aligned = by_spec.get(f':a.out:ht_branch:{second:x}', {'requests': []})['requests']
check('ht_branch:aligned-offset', len(aligned) == 1 and aligned[0]['type'] == 'offsets' and
      aligned[0]['offs'] == [second], aligned)
if misaligned is not None:
    bad = by_spec.get(f':a.out:ht_branch:{misaligned:x}', {})
    check('ht_branch:misaligned-offset', bad.get('requests') == [] and
          not bad.get('compiled', 1) and 'align' in bad.get('error', ''), bad)
# Undecodable bytes: only the entry probe; no guessed returns or offsets.
unk = by_spec.get(':a.out:ht_unknown:*', {'requests': []})['requests']
check('ht_unknown:* conservative', [(q['type'], q['offs']) for q in unk] ==
      [('entry', [0])], unk)
sw = by_spec.get(':a.out:ht_switch:return', {'requests': []})['requests']
check('ht_switch:return', len(sw) == 1 and sw[0]['offs'] == expected('ht_switch', 'return'),
      {'got': sw, 'want': expected('ht_switch', 'return')})
check('ht_switch dispatches through an indirect jump',
      any(m.startswith('j') and o.startswith('*') for _, m, o in insns['ht_switch']),
      insns['ht_switch'])
swstar = {q['type']: q['offs'] for q in
          by_spec.get(':a.out:ht_switch:*', {'requests': []})['requests']}
want_sw = {k: expected('ht_switch', k) for k in ('entry', 'return', 'offsets')}
check('ht_switch:*', swstar == want_sw, {'got': swstar, 'want': want_sw})

types_by_digit = {'1': 'entry', '2': 'return', '3': 'offsets'}


def triples(reqs):
    return [(q['func'], q['type'], q['offs']) for q in reqs]


for spec, message in refusals.items():
    got = by_spec.get(spec, {})
    # A refused MAKEPROBE of one type leaves the requests already made for
    # other types (entry and return precede the offsets of '*').
    refused = (lambda q: q['type'] == types_by_digit[spec[1]]) if spec[0] == '!' else (
        lambda q: True)
    check('refused ' + spec, got.get('compiled') == 0 and message in got.get('error', '') and
          not any(refused(q) for q in got.get('requests', [])), {'got': got, 'want': message})
for spec, want in accepted.items():
    got = by_spec.get(spec, {})
    check('accepted ' + spec, got.get('compiled') == 1 and
          triples(got.get('requests', [])) == [(f, t, o) for f, t, o in want] and
          all(q['pid'] == target_pid for q in got.get('requests', [])), {'got': got, 'want': want})
# Each successful creation asks for re-evaluation correctly, never with NULL.
created = [x for x in results if x.get('compiled') and x.get('requests') and
           not x['spec'].startswith('=htnone')]
check('retained enablings re-evaluated after creation',
      created and all(x['rematch'] >= 1 for x in created),
      [(x['spec'], x['rematch']) for x in created])
check('no NULL ENABLE argument', all(x.get('rematch_null', 0) == 0 for x in results),
      [(x['spec'], x['rematch_null']) for x in results if x.get('rematch_null')])
# '*' takes every defined function of non-zero size in .symtab, once per
# address (aliases share a probe), except _init and _fini.
groups = {}
section = None
for line in run(['llvm-readelf', '-s', str(target)]).splitlines():
    m = re.match(r"Symbol table '([^']+)'", line)
    if m:
        section = m.group(1)
        continue
    f = line.split()
    if section == '.symtab' and len(f) >= 8 and f[3] == 'FUNC' and f[6] != 'UND' and \
            int(f[2], 0) > 0 and f[7] not in ('_init', '_fini'):
        groups.setdefault((int(f[1], 16), int(f[2], 0)), set()).add(f[7])
everything = by_spec.get(':a.out:*:entry', {})
got_all = everything.get('requests', [])
check(':a.out:*:entry: one entry probe per defined function',
      everything.get('compiled') == 1 and len(got_all) == len(groups) and
      all(q['type'] == 'entry' and q['offs'] == [0] for q in got_all) and
      sorted(next(k for k, names in groups.items() if q['func'] in names) for q in got_all
             if any(q['func'] in n for n in groups.values())) == sorted(groups),
      {'got': sorted(q['func'] for q in got_all), 'want': sorted(map(sorted, groups.values()))})
rstar = by_spec.get('@:a.out:ht_rets:*', {})
check('ht_rets:* (int3 answered by fasttrap)', sorted(triples(rstar.get('requests', []))) ==
      sorted([('ht_rets', 'entry', [0]), ('ht_rets', 'return', rets_returns),
              ('ht_rets', 'offsets', rets_bounds)]) and
      sizes['ht_rets'][0] + 33 in rstar.get('getinstr', []), rstar)
jstar = by_spec.get(':a.out:ht_jt:*', {})
check('ht_jt:* (suspected jump table): entry and epilogue returns, no offsets',
      sorted(triples(jstar.get('requests', []))) ==
      sorted([('ht_jt', 'entry', [0]), ('ht_jt', 'return', [1, 3, 8, 12])]), jstar)
check('asm layout as assembled', [a - sizes['ht_rets'][0] for a, _, _ in insns['ht_rets']] ==
      rets_bounds and sizes['ht_rets'][1] == 35, insns['ht_rets'])
check('readelf shows _init with size 0 and environ as an object',
      re.search(r'\s0\s+FUNC\s+\S+\s+\S+\s+\S+\s+_init$',
                run(['llvm-readelf', '-s', str(target)]), re.M) is not None and
      re.search(r'OBJECT\s+\S+\s+\S+\s+\S+\s+environ$',
                run(['llvm-readelf', '-s', str(target)]), re.M) is not None, '')
# _init/_fini are never matched by a glob (bloated st_size in old binaries).
symtab = run(['llvm-nm', '--defined-only', str(target)]).split()
check('_init present in symtab', '_init' in symtab, '_init')


def elf_type(path):
    return int.from_bytes(path.read_bytes()[16:18], 'little')


def nm_value(path, name, dynamic=False):
    for line in run(['llvm-nm', *(['-D'] if dynamic else []), '--defined-only',
                     str(path)]).splitlines():
        f = line.split()
        if len(f) == 3 and f[2] == name:
            return int(f[0], 16)
    return None


# Stripped target: the dynamic symbol table is the only source of names.
rd, dres = harness_run('run-dyn', [dyn, ':a.out:ht_l*:entry', ':a.out:ht_leaf:entry'])
dyn_pid = next(x['target_pid'] for x in dres if 'target_pid' in x)
dby = {x['spec']: x for x in dres if 'spec' in x}
check('stripped target has no symtab, ht_leaf in dynsym',
      nm_value(dyn, 'ht_leaf') is None and nm_value(dyn, 'ht_leaf', True) is not None,
      run(['llvm-nm', '-D', '--defined-only', str(dyn)])[:400])
for spec in (':a.out:ht_l*:entry', ':a.out:ht_leaf:entry'):
    got = dby.get(spec, {})
    check('dynsym ' + spec, got.get('compiled') == 1 and
          triples(got.get('requests', [])) == entry_leaf and
          got['requests'][0]['pid'] == dyn_pid, got)
r2, gres = harness_run('run-init', [target, ':a.out:_ini?:entry'])
got = next((x for x in gres if x.get('spec') == ':a.out:_ini?:entry'), {})
check('glob never matches _init', got.get('compiled') == 1 and got.get('requests') == [], got)
# Without a fasttrap descriptor, the reason recorded by dtrace_open is reported.
r3, fres = harness_run('no-fasttrap', ['--no-fasttrap', target])
fby = {x['spec']: x for x in fres if 'spec' in x}
check('fasttrap missing (ENOENT)', fby.get('fterr-ENOENT', {}).get('error', '').endswith(
      'pid provider is not installed on this system'), fby.get('fterr-ENOENT'))
check('fasttrap unavailable (EACCES)', fby.get('fterr-EACCES', {}).get('error', '').endswith(
      'pid provider is not available: Permission denied'), fby.get('fterr-EACCES'))
# USDT registration.
r4, ures = harness_run('usdt', ['--usdt', usdt_exe, 'htexe'])
upids = [x['usdt_pid'] for x in ures if 'usdt_pid' in x]
uby = {x['spec']: x for x in ures if 'spec' in x}
dof_sym = nm_value(usdt_exe, '__SUNW_dof')
check('USDT target is ET_EXEC with __SUNW_dof', elf_type(usdt_exe) == 2 and dof_sym,
      {'type': elf_type(usdt_exe), 'dof': dof_sym})
if len(upids) == 3:
    want_helper = lambda pid: [{'mod': 'pid-usdt-exe', 'addr': 0, 'dof': dof_sym, 'pid': pid}]
    m0 = uby.get('usdt-helper-mode-0', {})
    check('USDT: helper device missing is reported', m0.get('compiled') == 0 and
          f'failed to instantiate probes for pid {upids[0]}: No such file or directory'
          in m0.get('error', '') and m0.get('helper_opens') == 1 and m0.get('helpers') == [], m0)
    m1 = uby.get('usdt-helper-mode-1', {})
    check('USDT: DOF registered with symbol address, base 0, module name',
          m1.get('compiled') == 1 and m1.get('helper_opens') == 1 and
          m1.get('helpers') == want_helper(upids[1]), {'got': m1, 'want': want_helper(upids[1])})
    again = uby.get('usdt-again', {})
    check('USDT: registered once per process', again.get('compiled') == 1 and
          again.get('helper_opens') == 0 and again.get('helpers') == [], again)
    m2 = uby.get('usdt-helper-mode-2', {})
    check('USDT: refused DOF does not fail compilation', m2.get('compiled') == 1 and
          m2.get('helpers') == want_helper(upids[2]), m2)
else:
    check('USDT harness', False, r4.stdout[-800:] + r4.stderr[-800:])
# Libraries loaded after compilation: the run-time linker's DLACTIVITY
# events (r_debug_state() with r_debug.r_state RT_CONSISTENT) create the
# pid probes and register the USDT DOF of each newly loaded object, at the
# load base the target itself reports (dladdr).  pid-late-target first loads
# a library with no probes of interest; in cycle mode it unloads and reloads
# the probed library.
lib_dof, lib_func = nm_value(late_lib, '__SUNW_dof'), nm_value(late_lib, 'ht_late')
late_runs = {}
for mode in ('plain', 'cycle'):
    basefile = out / f'late-base-{mode}.txt'
    rl, lres = harness_run('late-' + mode, ['--late', late_target, late_lib, basefile, target,
                                            none_lib, mode])
    late_runs[mode] = rl
    ids = next((x for x in lres if 'late_pid' in x), {})
    lby = {x['spec']: x for x in lres if 'spec' in x}
    try:
        loads = [tuple(int(v, 16) for v in line.split())
                 for line in basefile.read_text().splitlines()]
    except (OSError, ValueError):
        loads = []
    check(f'late {mode}: target reported each load base consistently with llvm-nm',
          len(loads) == (2 if mode == 'cycle' else 1) and
          all(f - b == lib_func for b, f in loads), {'loads': loads, 'nm': lib_func})
    before = lby.get('late-pid-before-load', {})
    check(f'late {mode}: no probes before the library is loaded',
          before.get('compiled') == 1 and before.get('requests') == [], before)
    ub = lby.get('late-usdt-before-load', {})
    check(f'late {mode}: no DOF before the library is loaded',
          ub.get('compiled') == 1 and ub.get('helpers') == [], ub)
    other = lby.get('other-process', {})
    check(f'late {mode}: second process probed at compile time',
          other.get('compiled') == 1 and triples(other.get('requests', [])) == entry_leaf and
          other['requests'][0]['pid'] == ids.get('other_pid'), other)
    after = lby.get('after-load', {})
    want_reqs = [('ht_late', 'entry', [0])] * len(loads)
    want_helpers = [{'mod': 'libhtlate.so', 'addr': b, 'dof': b + (lib_dof or 0),
                     'pid': ids.get('late_pid')} for b, _ in loads]
    check(f'late {mode}: target ran to completion',
          after.get('exited') == 1 and after.get('status') == 0, after)
    check(f'late {mode}: pid probe created in the library at each load, for that process only',
          loads and triples(after.get('requests', [])) == want_reqs and
          all(q['pid'] == ids.get('late_pid') for q in after.get('requests', [])),
          {'got': after.get('requests'), 'want': want_reqs})
    check(f'late {mode}: library DOF registered once per load at its load base',
          loads and after.get('helpers') == want_helpers,
          {'got': after.get('helpers'), 'want': want_helpers})
    check(f'late {mode}: retained enablings re-evaluated',
          after.get('rematch', 0) >= len(loads) and after.get('rematch_null') == 0, after)
    fds = next((x for x in lres if 'fds_before' in x), {})
    check(f'late {mode}: no descriptors leaked by object-list updates',
          fds and fds['fds_before'] == fds['fds_after'], fds)
# Argument types from CTF.
r6, tres = harness_run('types', ['--types', ctf_target, 'ht_types'])
tby = {x['types']: x for x in tres if 'types' in x}
# ht_types(long, const char *, unsigned short) returning short.  D discards
# type qualifiers (dtrace_type_strcompile("const char *") is "char *"), so
# the second argument is char *.
entry_argv = tby.get('entry', {}).get('argv', [])
# The third argument is a scoped multi-word base type
# (pid123`pidtypes`unsigned short).
check('entry argument types from CTF', entry_argv == ['long', 'char *', 'unsigned short'],
      tby.get('entry'))
check('return probe: offset and return value types', tby.get('return', {}).get('argv') ==
      ['int', 'short'], tby.get('return'))
want_entry = ['long', 'char *']
check('offset probe has no typed arguments', tby.get('offset', {}).get('argv') == [],
      tby.get('offset'))
# CTF containers are keyed by plain object names (FreeBSD has only link map
# 0, and the compiler normalizes "LM0`obj" to "obj", see ':LM0`a.out:...'
# above), so a description still carrying a link-map prefix finds no
# container and gets no types; dt_pid_get_types' LM parsing is illumos-only.
for label in ('lm0', 'lm-short', 'lm-prefix', 'lm-number', 'nosuch', 'no-ctf-func'):
    check(f'no argument types: {label}', tby.get(label, {}).get('argv') == [],
          tby.get(label))
r8, nres = harness_run('types-no-ctf', ['--types', target, 'ht_types'])
nby = {x['types']: x for x in nres if 'types' in x}
check('target without CTF: no argument types', nby.get('entry', {}).get('argv') == [] and
      nby.get('return', {}).get('argv') == [], nby)
typed = next((x for x in tres if 'typed_clause' in x), {})
check('CTF-typed arguments usable in D', typed.get('typed_clause') == 1, typed)
# A program whose name contains '-' (pid123`pid-types`long).
r7, dres2 = harness_run('types-dash', ['--types', ctf_dash, 'ht_types'])
dby2 = {x['types']: x for x in dres2 if 'types' in x}
check('argument types for a module name with "-"', dby2.get('entry', {}).get('argv') ==
      ['long', 'char *', 'unsigned short'], dby2.get('entry'))
# Process lifecycle: exit notification, grab of a running process, release.
lc = subprocess.run([str(harness), '--lifecycle', str(target)], env=env,
                    capture_output=True, text=True, timeout=120, cwd=out)
(out / 'lifecycle.log').write_text(lc.stdout + lc.stderr)
for line in lc.stdout.splitlines():
    if line.startswith(('PASS ', 'FAIL ')):
        check('lifecycle: ' + line[5:], line.startswith('PASS '), line)
check('lifecycle harness', lc.returncode == 0 and 'PASS ' in lc.stdout, lc.stdout[-500:])
check('tail call recognised as return', expected('ht_tail', 'return') and
      any(m.startswith('j') for _, m, _ in insns['ht_tail']), insns['ht_tail'])
(out / 'results.json').write_text(json.dumps({'checks': checks, 'raw': results,
    'functions': {k: {'start': hex(v[0]), 'size': v[1]} for k, v in sizes.items()}},
    indent=2) + '\n')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'provenance.json').write_text(json.dumps({'sha256': {str(p): sha(p) for p in
    (lib / 'libdtrace.so.2', obj / 'lib/libproc/libproc.so.5', target,
     tests / 'pid-placement.c', tests / 'pid-placement-shim.c', tests / 'pid-target.c',
     tests / 'pid-target-switch.c', tests / 'pid-target-asm.S', tests / 'pid-usdt-exe.c', tests / 'pid-usdt-exe.d',
     tests / 'pid-late.d', tests / 'pid-late-lib.c', tests / 'pid-late-target.c',
     tests / 'pid-late-none.c',
     dtrace_bin, Path(__file__).resolve()) if p.exists()},
    'oracle': run(['llvm-objdump', '--version']).splitlines()[:2]}, indent=2) + '\n')
failed = [c for c in checks if not c['passed']]
for c in failed:
    print(json.dumps(c)[:1500])
if any(x.returncode for x in (r, rd, r2, r3, r4, r6, r7, r8, *late_runs.values())) or failed or not checks:
    raise SystemExit(f'pid placement failed (harness rc {r.returncode}); inspect run.log')
print('PASS:', len(checks), 'pid probe placement checks against LLVM')
