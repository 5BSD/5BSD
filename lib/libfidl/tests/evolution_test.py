#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run C peers built from two versions of one schema against each other.

evolution/evolution.fidl is compiled at bsd:1 and bsd:2 (--available bsd:N,
the platform every bsd.* library is versioned under). The compiler output
is checked first: every element marked @available(added=2) -- the Added
method, the Announced event, the GREEN/WRITE/square/extra/tint members -- is
absent from the bsd:1 IR and C header and present at bsd:2, so a bsd:1 build
cannot even name them. Each pairing then uses a real native channel between
separate processes and checks unknown table fields, flexible union variants,
flexible enum/bits values, added flexible methods/events and continued
connection use: the wire stays compatible across the version.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
# Host-side builds use their own object root.  Plain make -C would otherwise
# write host-linked objects into the world's object tree, which an
# incremental buildworld then trusts and installs.
os.environ['MAKEOBJDIRPREFIX'] = '/usr/obj/5bsd-fidl-hostobj'

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--src', type=Path, default=Path('/usr/src'))
p.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-fidl-runtime'))
p.add_argument('--tools', type=Path, default=Path('/usr/obj/5bsd-fidl'))
a = p.parse_args()
a.obj.mkdir(parents=True, exist_ok=True)
work = Path(tempfile.mkdtemp(prefix='evolution-tests-', dir=a.obj))
source = a.src / 'lib/libfidl/tests/evolution'
f = a.src / 'contrib/fuchsia'
includes = [a.src / 'lib/libfidl/include', a.src / 'lib/libchannel', a.src / 'sys', f / 'sdk',
            f / 'src/zircon/lib/zircon/include', f / 'zircon/system/public']
includes += [f / 'sdk/lib' / part / 'include'
             for part in ('fidl_base', 'fidl/cpp', 'fidl/cpp/wire', 'fit', 'stdcompat', 'zircon-assert')]
flags = ['-I' + str(i) for i in includes]
sanitized = a.obj.name == 'sanitized'
env = dict(os.environ)
if sanitized:
    flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer',
              '-ftrivial-auto-var-init=pattern']
    env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    channel = a.obj / 'libchannel-sanitized.a'
else:
    channel = Path(subprocess.check_output(
        ['make', '-C', str(a.src / 'lib/libchannel'), '-V', '.OBJDIR'], text=True).strip()) / 'libchannel.a'
libraries = [str(a.obj / 'libfidl_bsd.a'), str(channel), '-lc++', '-lcxxrt', '-lm', '-pthread']

# Elements the schema adds at bsd:2, as (IR declaration, member) and as the
# C identifier generated for them.
ADDED = {
    ('bsd.evolution/Evolve', 'Added'): 'bsd_evolution_Evolve_Added',
    ('bsd.evolution/Evolve', 'Announced'): 'bsd_evolution_Evolve_Announced',
    ('bsd.evolution/Color', 'GREEN'): 'bsd_evolution_Color_GREEN',
    ('bsd.evolution/Perms', 'WRITE'): 'bsd_evolution_Perms_WRITE',
    ('bsd.evolution/Shape', 'square'): 'bsd_evolution_Shape_square_tag',
    ('bsd.evolution/Record', 'extra'): 'has_extra',
    ('bsd.evolution/Record', 'tint'): 'has_tint',
}


def members(ir, declaration):
    """The member names of DECLARATION (methods for a protocol) in IR."""
    for kind in ('protocol', 'enum', 'bits', 'union', 'table'):
        for decl in ir['%s_declarations' % kind]:
            if decl['name'] == declaration:
                return {m['name'] for m in decl.get('methods', decl.get('members', []))}
    raise KeyError(declaration)


def check_available(version, ir_path, header):
    """At bsd:1 nothing added at 2 exists; at bsd:2 everything does."""
    ir = json.loads(ir_path.read_text())
    text = header.read_text()
    for (declaration, member), identifier in ADDED.items():
        present = member in members(ir, declaration)
        if present != (version >= 2):
            raise AssertionError('%s.%s %s at bsd:%d IR' % (
                declaration, member, 'present' if present else 'absent', version))
        if (identifier in text) != (version >= 2):
            raise AssertionError('%s %s in the bsd:%d C header' % (
                identifier, 'present' if identifier in text else 'absent', version))
    return len(ADDED)


jobs = []
checked = 0
for version in (1, 2):
    ir = work / ('v%d.json' % version)
    subprocess.run([str(a.tools / 'fidlc'), '--json', str(ir), '--available', 'bsd:%d' % version,
                    '--files', str(source / 'evolution.fidl')], check=True)
    generated = work / ('gen%d' % version)
    subprocess.run([sys.executable, str(a.src / 'tools/build/fuchsia/generate-bsd.py'),
                    '--json', str(ir),
                    '--root', str(generated), '--c'], check=True)
    base = generated / 'fidl/bsd.evolution'
    checked += check_available(version, ir, base / 'c/bsd.h')
    inputs = [source / 'peer.c', base / 'cpp/natural_types.cc', base / 'cpp/common_types.cc', base / 'c/bsd.cc']
    jobs += [(version, generated, item) for item in inputs]


def compile(job):
    version, generated, item = job
    target = work / ('v%d-%s.o' % (version, item.stem))
    if item.suffix == '.c':
        command = ['cc', '-std=c11', '-pedantic-errors', '-Wall', '-Wextra', '-Werror',
                   '-DEVOLVE_VERSION=%d' % version]
    else:
        command = ['c++', '-std=c++20']
    subprocess.run([*command, *flags, '-I' + str(generated), '-c', str(item), '-o', str(target)], check=True)
    return version, target


with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    objects = list(pool.map(compile, jobs))
peers = {}
for version in (1, 2):
    peers[version] = work / ('peer%d' % version)
    subprocess.run(['cc', *flags, *[str(o) for v, o in objects if v == version], *libraries,
                    '-o', str(peers[version])], check=True)

cases = 0
for local in (1, 2):
    for remote in (1, 2):
        for role in ('call', 'serve'):
            subprocess.run([str(peers[local]), 'launch', role, str(peers[remote]), str(remote)],
                           env=env, check=True, timeout=90)
            cases += 1
print('%d schema evolution pairings (bsd:1/bsd:2 C peers over native channels), '
      '%d added elements absent at bsd:1 and present at bsd:2: PASS; %s'
      % (cases, checked, work), flush=True)
