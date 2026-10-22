#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile current bhyve migration adapters in supported snapshot modes.

Uses the maintained bhyve Makefile flags and freshly generated probe headers.
Optional cross builds require an explicit matching world sysroot. ELF machine
identity is checked for every object. Does not link/install bhyve, open a
tracing device, or operate a VM.
"""
from pathlib import Path
import argparse
import concurrent.futures
import json
import os
import platform
import shlex
import subprocess

root = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=Path)
parser.add_argument('--target', choices=('amd64', 'arm64', 'riscv'))
parser.add_argument('--sysroot', type=Path)
args = parser.parse_args()
if bool(args.target) != bool(args.sysroot):
    parser.error('--target and --sysroot must be supplied together')
if args.sysroot and not (args.sysroot / 'usr/include/sys/param.h').is_file():
    parser.error('sysroot must contain the matching target world headers')
out = args.output.resolve()
architectures = {'amd64': ('amd64', 'amd64', 'x86_64', 62),
                 'arm64': ('aarch64', 'aarch64', 'aarch64', 183),
                 'riscv': ('riscv64', 'riscv', 'riscv64', 243)}
expected_machine = architectures[args.target][3] if args.target else {
    'amd64': 62, 'x86_64': 62, 'arm64': 183, 'aarch64': 183,
    'riscv': 243, 'riscv64': 243}[platform.machine()]
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = root / 'usr.sbin/bhyve'
units = ('migration_session.c', 'migration_receiver.c', 'migration_tls.c',
         'snapshot.c', 'hypertrace.c', 'bhyverun.c', 'vmexit.c', 'ipc.c', 'console.c')
plans = []
configurations = []
for mode in ('yes', 'no'):
    obj = out / ('snapshot-' + mode)
    obj.mkdir(exist_ok=True)
    env = dict(os.environ, MAKEOBJDIR=str(obj))
    make = ['make', '-C', str(source), '-m', str(root / 'share/mk'),
            'SRCTOP=' + str(root), 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
            'MK_BHYVE_SNAPSHOT=' + mode]
    if args.target:
        arch, cpu, triple, _ = architectures[args.target]
        make += ['MACHINE=' + args.target, 'MACHINE_ARCH=' + arch,
                 'MACHINE_CPUARCH=' + cpu]
    variables = ('CC', 'CFLAGS', 'CPPFLAGS', 'SRCS', 'MK_BHYVE_SNAPSHOT',
                 'MK_DTRACE', '.OBJDIR', 'OSREL', 'BROKEN_OPTIONS')
    query = make + [part for var in variables for part in ('-V', '${' + var + '}')]
    values = subprocess.check_output(query, env=env, text=True).splitlines()
    if len(values) != len(variables):
        raise SystemExit('Unexpected Makefile variable output')
    settings = dict(zip(variables, values))
    if mode == 'yes' and 'BHYVE_SNAPSHOT' in shlex.split(settings['BROKEN_OPTIONS']):
        configurations.append({'mode': mode, 'query': query, 'settings': settings,
                               'unsupported': 'BHYVE_SNAPSHOT is in BROKEN_OPTIONS'})
        print('UNSUPPORTED: snapshot=yes (maintained BROKEN_OPTIONS)')
        continue
    if settings['MK_BHYVE_SNAPSHOT'] != mode or Path(settings['.OBJDIR']) != obj:
        raise SystemExit('Build mode or object-directory mismatch')
    configurations.append({'mode': mode, 'query': query, 'settings': settings})
    if settings['MK_DTRACE'] != 'no':
        # -h selects DTRACE_O_NODEV in the maintained dtrace CLI.
        command = ['dtrace', '-h', '-s', str(source / 'vsock_provider.d'),
                   '-o', str(obj / 'vsock_provider.h')]
        with (obj / 'provider.log').open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    present = shlex.split(settings['SRCS'])
    flags = shlex.split(settings['CFLAGS']) + shlex.split(settings['CPPFLAGS'])
    compiler = shlex.split(settings['CC'])
    if args.target:
        compiler += ['--target=' + triple + '-unknown-freebsd' + settings['OSREL'],
                     '--sysroot=' + str(args.sysroot.resolve())]
    for name in units:
        if name not in present:
            continue
        unit = source / name
        if name == 'vmexit.c':
            unit = source / ({62: 'amd64', 183: 'aarch64', 243: 'riscv'}[expected_machine]) / name
        command = compiler + flags + ['-c', str(unit), '-o', str(obj / (name + '.o'))]
        plans.append({'mode': mode, 'source': name, 'command': command,
                      'log': str(obj / (name + '.log')),
                      'object': str(obj / (name + '.o'))})
(out / 'configurations.json').write_text(json.dumps(configurations, indent=2) + '\n')
def compile_one(plan):
    with open(plan['log'], 'w') as log:
        result = subprocess.run(plan['command'], stdout=log, stderr=subprocess.STDOUT)
    machine = None
    status = result.returncode
    if status == 0:
        header = Path(plan['object']).read_bytes()[:20]
        if len(header) != 20 or header[:4] != b'\x7fELF' or header[5] not in (1, 2):
            status = 1
        else:
            machine = int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big')
            if machine != expected_machine:
                status = 1
    return dict(plan, status=status, elf_machine=machine,
                expected_elf_machine=expected_machine)
with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
    results = list(pool.map(compile_one, plans))
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
for result in results:
    print(result['mode'], result['source'], result['status'])
if any(result['status'] for result in results):
    raise SystemExit('Production adapter compilation failed; inspect results.json and logs')
print(f'PASS: {len(results)} production object builds in supported snapshot modes; no link/install/live VM')
