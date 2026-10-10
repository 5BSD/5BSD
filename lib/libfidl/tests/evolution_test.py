#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run C peers built from two versions of one schema against each other.

evolution/evolution.fidl is compiled at evolve:1 and evolve:2. Each pairing
uses a real native channel between separate processes and checks unknown
table fields, flexible union variants, flexible enum/bits values, added
flexible methods/events and continued connection use.
"""
import argparse
import concurrent.futures
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

jobs = []
for version in (1, 2):
    ir = work / ('v%d.json' % version)
    subprocess.run([str(a.tools / 'fidlc'), '--json', str(ir), '--available', 'evolve:%d' % version,
                    '--files', str(source / 'evolution.fidl')], check=True)
    generated = work / ('gen%d' % version)
    subprocess.run([sys.executable, str(a.src / 'tools/build/fuchsia/generate-bsd.py'),
                    '--fidlgen-cpp', str(a.tools / 'fidlgen_cpp'), '--json', str(ir),
                    '--root', str(generated), '--c'], check=True)
    base = generated / 'fidl/bsd.evolution'
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
print('%d schema evolution pairings (evolve:1/evolve:2 C peers over native channels): PASS; %s'
      % (cases, work), flush=True)
