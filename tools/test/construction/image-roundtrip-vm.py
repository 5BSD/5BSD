#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify explicit makefs with a fresh metadata round-trip VM."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from fixture_stage import Fixture
from export_image import collect


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('boot-root', 'world', 'python-prefix', 'objtop', 'fixture-objtop',
                 'work', 'qemu-data', 'makefs'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--kernconf', required=True)
    parser.add_argument('--test-case', choices=('image_roundtrip', 'unmount_order', 'seed_readback'), default='image_roundtrip')
    parser.add_argument('--input-disk', type=Path)
    parser.add_argument('--seed-receipt', type=Path)
    parser.add_argument('--input-disk-sha256')
    parser.add_argument('--output-disk-mib', type=int)
    parser.add_argument('--seed-dataset-tests', action='store_true')
    parser.add_argument('--scratch-disk-mib', type=int, default=256)
    parser.add_argument('--root-mib', type=int, default=512)
    parser.add_argument('--memory-mib', type=int, default=1024)
    parser.add_argument('--vm-timeout', type=int, default=240)
    parser.add_argument('--export-bundle', action='store_true')
    parser.add_argument('--boot-transport-image', type=Path)
    parser.add_argument('--boot-transport-stage', type=Path)
    args = parser.parse_args()
    if (args.boot_transport_image is None) != (args.boot_transport_stage is None):
        parser.error('boot transport read-back requires image and stage receipt')
    if args.test_case != 'image_roundtrip' and (args.output_disk_mib is not None or args.boot_transport_image is not None):
        parser.error('image export and boot transport require image_roundtrip')
    if args.seed_dataset_tests and (args.test_case != 'image_roundtrip' or args.input_disk is not None or args.output_disk_mib is not None):
        parser.error('seed dataset tests require image_roundtrip and a private scratch disk')
    if args.export_bundle and args.output_disk_mib is None:
        parser.error('bundle export requires explicit output capacity and input disk')
    readback = args.test_case == 'seed_readback'
    if readback != (args.seed_receipt is not None):
        parser.error('seed_readback requires an explicit seed receipt, used only by that case')
    if readback and (args.input_disk is None or args.input_disk_sha256 is None or args.output_disk_mib is not None):
        parser.error('seed readback requires an explicit read-only input disk/hash')
    export_options = () if readback else (args.input_disk, args.input_disk_sha256, args.output_disk_mib)
    if any(value is not None for value in export_options) and not all(value is not None for value in export_options):
        parser.error('export requires an explicit input disk/hash and output capacity')
    if args.output_disk_mib is not None and not 16 <= args.output_disk_mib <= 16384:
        parser.error('invalid output capacity')
    if not 64 <= args.root_mib <= 16384 or not 512 <= args.memory_mib <= 65536 or not 1 <= args.vm_timeout <= 86400:
        parser.error('invalid explicit VM resource limit')
    work = args.work.resolve()
    if not work.is_relative_to('/usr/obj/usr/src') or work.exists():
        parser.error('work must be new under /usr/obj/usr/src')
    work.mkdir(); extra = work / 'extra'; extra.mkdir()
    world = args.world.resolve(strict=True)
    fixture = Fixture(world, args.python_prefix.resolve(strict=True), extra)
    fixture.python()
    if readback:
        receipt = args.seed_receipt.resolve(strict=True)
        evidence = json.loads(receipt.read_text())
        if evidence['disk_sha256'] != args.input_disk_sha256:
            parser.error('input disk hash differs from retained seed evidence')
        fixture.copy(receipt, extra / 'tests/seed-dataset-evidence.json', receipt.parent)
    if args.boot_transport_image is not None:
        for path, name in ((args.boot_transport_image, 'boot-transport.ufs'), (args.boot_transport_stage, 'boot-transport.json')):
            path = path.resolve(strict=True)
            fixture.copy(path, extra / 'tests' / name, path.parent)
    for name in ('sbin/mount', 'sbin/umount', 'sbin/sysctl', 'sbin/mdconfig', 'usr/bin/tar', 'usr/lib/libarchive.so'):
        fixture.elf(world / name, name, world)
    if args.output_disk_mib is not None:
        fixture.elf(world / 'usr/sbin/diskinfo', 'usr/sbin/diskinfo', world)
    makefs = args.makefs.resolve(strict=True)
    fixture.elf(makefs, 'tests/makefs', makefs.parent)
    source = Path(__file__).resolve().parent
    backend = source.parents[1] / 'build/capimage'
    for path in sorted(backend.glob('*.py')):
        fixture.copy(path, extra / 'tests' / path.name, backend)
    fixture.copy(source / 'image_roundtrip.py', extra / 'tests/image_roundtrip.py', source)
    if args.output_disk_mib is not None:
        fixture.copy(source / 'export_image.py', extra / 'tests/export_image.py', source)
        fixture.copy(source / 'export_bundle.py', extra / 'tests/export_bundle.py', source)
        (extra / 'tests/image-export-settings.json').write_text(json.dumps({'capacity_mib': args.output_disk_mib, 'bundle': args.export_bundle}) + '\n')
    (work / 'fixture-inputs.json').write_text(json.dumps(dict(
        scope='UFS metadata/content round trip; not full system boot',
        files_sha256=fixture.source_hashes), indent=2) + '\n')
    command = [sys.executable, '-B', str(source.parent / 'daemon-runtime/run-vm.py'),
        '--root', str(args.boot_root.resolve(strict=True)), '--objtop', str(args.objtop),
        '--fixture-objtop', str(args.fixture_objtop), '--work', str(work / 'vm'),
        '--qemu', args.qemu, '--qemu-data', str(args.qemu_data), '--kernconf', args.kernconf,
        '--extra-root', str(extra), '--root-mib', str(args.root_mib), '--memory-mib', str(args.memory_mib),
        '--timeout', str(args.vm_timeout), '--atf-case', 'tools/test/construction/image_vm_test:' + args.test_case]
    if args.output_disk_mib is not None:
        command.extend(['--input-disk', str(args.input_disk), '--input-disk-sha256', args.input_disk_sha256,
                        '--output-disk-mib', str(args.output_disk_mib)])
    if args.seed_dataset_tests:
        command.extend(['--zfs', '--scratch-disk-mib', str(args.scratch_disk_mib)])
    if readback:
        command.extend(['--zfs', '--input-disk', str(args.input_disk), '--input-disk-sha256', args.input_disk_sha256])
    result = subprocess.run(command)
    for name, expected in fixture.source_hashes.items():
        with Path(name).open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError('fixture input changed: ' + name)
    if args.seed_dataset_tests and (work / 'vm/result.json').exists():
        vm = json.loads((work / 'vm/result.json').read_text())
        serial = (work / 'vm/serial.log').read_bytes()
        if hashlib.sha256(serial).hexdigest() != vm['serial_sha256']:
            raise ValueError('retained VM serial differs')
        prefix = 'SEED_DATASET_OBSERVATION '
        rows = [line[len(prefix):] for line in serial.decode().splitlines() if line.startswith(prefix)]
        if len(rows) == 1:
            evidence = json.loads(rows[0])
            with (work / 'vm/scratch.img').open('rb') as stream:
                disk_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
            evidence.update(format=1, scope='retained-seed-dataset-test-evidence',
                disk_sha256=disk_hash, serial_sha256=vm['serial_sha256'],
                provisioning_vm_result=vm['result'], generation_authenticated=False,
                activation_authorized=False)
            (work / 'seed-dataset-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    result.check_returncode()
    if args.output_disk_mib is not None:
        collect(work)


if __name__ == '__main__':
    main()
