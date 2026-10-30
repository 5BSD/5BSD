#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Cold readback of one explicitly selected initialized-state disk in a fresh VM."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from fixture_stage import Fixture
from collect_state_readback import collect, digest
from state_readback import selection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('boot-root', 'world', 'python-prefix', 'objtop', 'fixture-objtop',
                 'work', 'qemu-data', 'initialization', 'input-disk'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--kernconf', required=True)
    parser.add_argument('--cpus', type=int, choices=range(1, 5), default=2)
    parser.add_argument('--memory-mib', type=int, default=2048)
    parser.add_argument('--root-mib', type=int, default=1024)
    parser.add_argument('--case-timeout', type=int, default=1800)
    parser.add_argument('--vm-timeout', type=int, default=2100)
    args = parser.parse_args()
    if not 1 <= args.case_timeout < args.vm_timeout <= 86400:
        parser.error('case timeout must be positive and below VM timeout')
    if not 64 <= args.root_mib <= 16384 or not 512 <= args.memory_mib <= 65536:
        parser.error('invalid root or memory capacity')
    if args.initialization.is_symlink() or not args.initialization.is_file():
        parser.error('initialization must be a regular nonsymlink receipt')
    raw = args.initialization.read_bytes()
    document = json.loads(raw)
    _, initialized = selection(document)
    if not initialized:
        parser.error('requires populated-state initialization evidence')
    expected = document['output_disk_sha256']
    if args.input_disk.is_symlink() or not args.input_disk.is_file() or digest(args.input_disk) != expected:
        parser.error('input disk differs from selected initialization')
    work = args.work.resolve()
    if not work.is_relative_to('/usr/obj/usr/src') or work.exists():
        parser.error('work must be new under /usr/obj/usr/src')
    world, prefix = args.world.resolve(strict=True), args.python_prefix.resolve(strict=True)
    work.mkdir(mode=0o700); extra = work / 'extra'; extra.mkdir(mode=0o700)
    fixture = Fixture(world, prefix, extra)
    fixture.python()
    for name in ('bin/sh', 'sbin/zfs', 'sbin/zpool', 'sbin/kldload', 'sbin/mount', 'sbin/umount', 'sbin/sysctl', 'usr/lib/libarchive.so'):
        fixture.elf(world / name, name, world)
    module = args.objtop / 'sys' / args.kernconf / 'modules/usr/src/sys/modules/zfs/zfs.ko'
    fixture.copy(module, extra / 'boot/kernel/zfs.ko', args.objtop.resolve(strict=True))
    source = Path(__file__).resolve().parent
    fixture.backend_python(source.parents[1] / 'build/capimage')
    fixture.copy(source / 'state_readback.py', extra / 'tests/state_readback.py', source)
    selected = args.initialization.resolve(strict=True)
    fixture.copy(selected, extra / 'tests/state-allocation-result.json', selected.parent)
    if (extra / 'tests/state-allocation-result.json').read_bytes() != raw:
        raise ValueError('selected initialization changed during staging')
    (work / 'fixture-inputs.json').write_text(json.dumps(dict(
        scope='populated-state-cold-readback-fixture', files_sha256=fixture.source_hashes,
        input_disk_sha256=expected, generation_authenticated=False, runtime_qualified=False), indent=2)+'\n')
    command = [sys.executable, '-B', str(source.parent / 'daemon-runtime/run-vm.py'),
        '--root', str(args.boot_root.resolve(strict=True)), '--objtop', str(args.objtop),
        '--fixture-objtop', str(args.fixture_objtop), '--work', str(work / 'vm'),
        '--qemu', args.qemu, '--qemu-data', str(args.qemu_data), '--kernconf', args.kernconf,
        '--input-disk', str(args.input_disk.resolve(strict=True)), '--input-disk-sha256', expected,
        '--extra-root', str(extra), '--root-mib', str(args.root_mib), '--memory-mib', str(args.memory_mib),
        '--cpus', str(args.cpus), '--timeout', str(args.vm_timeout),
        '--atf-case', 'tools/test/construction/construction_vm_test:state_readback',
        '--atf-case-budget', 'tools/test/construction/construction_vm_test:state_readback='+str(args.case_timeout)]
    subprocess.run(command, check=True)
    for name, sha in fixture.source_hashes.items():
        if digest(Path(name)) != sha:
            raise ValueError('readback source changed: ' + name)
    report = collect(work / 'vm', args.initialization, args.input_disk)
    with (work / 'readback.json').open('x') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')


if __name__ == '__main__':
    main()
