#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Build libvmmapi and a fully linked bhyve for one target and snapshot mode.

Used to produce the ARM64/RISC-V checkpoint build evidence recorded in
contrib/hypertrace/ARCH-SNAPSHOT.5BSD.md.  Cross builds use an existing
target world sysroot only for system headers/libraries; machine headers come
from this source tree through a private "machine" include link, and libvmmapi,
lib9p, libuvmem and libfdt are rebuilt from this tree.  MK_BHYVE_SNAPSHOT is
passed explicitly: for ARM64/RISC-V "yes" is an experimental opt-in that the
maintained configuration still lists in BROKEN_OPTIONS.

Nothing is installed or executed: the script never runs the produced binary,
opens /dev/vmm, loads modules or starts a VM.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[3]
TARGETS = {
    # target: (MACHINE, MACHINE_ARCH, MACHINE_CPUARCH, triple, ELF machine)
    'amd64': ('amd64', 'amd64', 'amd64', 'x86_64', 62),
    'arm64': ('arm64', 'aarch64', 'aarch64', 'aarch64', 183),
    'riscv': ('riscv', 'riscv64', 'riscv', 'riscv64', 243),
}

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=Path)
parser.add_argument('--target', choices=sorted(TARGETS), required=True)
parser.add_argument('--snapshot', choices=('yes', 'no'), required=True)
parser.add_argument('--sysroot', type=Path,
                    help='target world sysroot (required for cross targets)')
parser.add_argument('--dtrace', type=Path,
                    help='target-capable host dtrace for dtrace -G')
parser.add_argument('--native', action='store_true',
                    help='build for the host without --target/--sysroot')
parser.add_argument('--jobs', type=int, default=os.cpu_count())
args = parser.parse_args()

out = args.output.resolve()
if not out.is_relative_to('/usr/obj') or out.is_relative_to('/home'):
    raise SystemExit('Use the /usr/obj object root')
machine, arch, cpuarch, triple, elf_machine = TARGETS[args.target]
if not args.native and args.sysroot is None:
    parser.error('cross builds require --sysroot')
out.mkdir(parents=True, exist_ok=True)
objprefix = out / 'obj'
env = dict(os.environ, MAKEOBJDIRPREFIX=str(objprefix))
env.pop('CFLAGS', None)
env.pop('CXXFLAGS', None)
make = ['make', '-j%d' % args.jobs, '-m', str(ROOT / 'share/mk'),
        'SRCTOP=%s' % ROOT, 'SRCCONF=/dev/null', '__MAKE_CONF=/dev/null',
        'MK_BHYVE_SNAPSHOT=%s' % args.snapshot]
# Machine headers always come from this tree: the installed or sysroot
# machine/vmm_dev.h can describe an older kernel ABI.
includes = out / 'source-includes'
includes.mkdir(exist_ok=True)
link = includes / 'machine'
want = ROOT / 'sys' / machine / 'include'
if link.is_symlink() or link.exists():
    if link.resolve() != want:
        raise SystemExit('stale machine include link: %s' % link)
else:
    link.symlink_to(want)
env['CFLAGS'] = '-O2 -pipe -fno-common -I%s' % includes
if not args.native:
    osrel = subprocess.check_output(['uname', '-r'], text=True).split('-')[0]
    cc = 'cc --target=%s-unknown-freebsd%s --sysroot=%s' % (
        triple, osrel, args.sysroot.resolve())
    env['CC'] = cc
    env['CXX'] = cc.replace('cc ', 'c++ ', 1)
    env['CPP'] = cc.replace('cc ', 'cpp ', 1)
    make += ['MACHINE=%s' % machine, 'MACHINE_ARCH=%s' % arch,
             'MACHINE_CPUARCH=%s' % cpuarch,
             # dtrace -G must embed the target drti.o.  SYSROOT itself is
             # not set: it would make LIBADD resolve libvmmapi (and the
             # other tree libraries) from the old sysroot instead of the
             # freshly built objects.
             '_DTRACE_SYSROOT_FLAG=-x syslibdir=%s/usr/lib/dtrace' %
             args.sysroot.resolve()]
if args.dtrace is not None:
    make.append('DTRACE=%s' % args.dtrace.resolve())

steps = ['lib/libvmmapi', 'lib/lib9p', 'lib/libuvmem']
if args.target != 'amd64':
    steps.append('lib/libfdt')
steps.append('usr.sbin/bhyve')
results = []
status = 0
for step in steps:
    log = out / (step.replace('/', '-') + '.log')
    command = make + ['-C', str(ROOT / step), 'all']
    with log.open('w') as handle:
        result = subprocess.run(command, env=env, stdout=handle,
                                stderr=subprocess.STDOUT)
    results.append({'source': step, 'status': result.returncode,
                    'log': str(log), 'command': command})
    print(step, result.returncode, flush=True)
    if result.returncode != 0:
        status = result.returncode
        break

summary = {'target': args.target, 'snapshot': args.snapshot,
           'native': args.native, 'steps': results, 'status': status,
           'executed': False,
           'sysroot': str(args.sysroot) if args.sysroot else None,
           'sysroot_provenance': None if args.native else
           'Existing /usr/src cross-world sysroot; not a matched world'}
if status == 0:
    objdir = subprocess.check_output(
        make + ['-C', str(ROOT / 'usr.sbin/bhyve'), '-V', '.OBJDIR'],
        env=env, text=True).strip()
    binary = Path(objdir) / 'bhyve'
    data = binary.read_bytes()
    header = data[:20]
    machine_id = int.from_bytes(header[18:20], 'little')
    summary.update({'binary': str(binary), 'elf_machine': machine_id,
                    'expected_elf_machine': elf_machine,
                    'sha256': hashlib.sha256(data).hexdigest(),
                    'size': len(data)})
    if header[:4] != b'\x7fELF' or machine_id != elf_machine:
        summary['status'] = status = 1
(out / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')
print('PASS' if status == 0 else 'FAIL', args.target, 'snapshot=%s' %
      args.snapshot)
raise SystemExit(status)
