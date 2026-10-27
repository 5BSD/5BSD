#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Fresh verifier VM for an explicitly hashed retained builder disk."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys
from fixture_stage import Fixture
from export_image import collect
from verify_retained import collect_verification, verify_layout_receipt_binding


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('boot-root', 'world', 'python-prefix', 'objtop', 'fixture-objtop',
                 'work', 'qemu-data', 'sqlite', 'input-disk'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('qemu', 'kernconf', 'input-disk-sha256', 'retained-work'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--input-partition', type=int, required=True)
    parser.add_argument('--input-mount-directory', default='/mnt/retained-input', help='pre-created guest mountpoint on the fixture root filesystem')
    parser.add_argument('--image-work-directory', help='explicit new guest directory on the private verifier root disk')
    parser.add_argument('--image-makefs', type=Path, help='build and export an image after retained verification')
    parser.add_argument('--output-disk-mib', type=int, help='explicit new output disk capacity for image export')
    parser.add_argument('--expect-incomplete', action='store_true',
                        help='negative test: require missing success receipt refusal, never candidate acceptance')
    parser.add_argument('--vm-timeout', type=int, default=2100)
    parser.add_argument('--root-mib', type=int, default=512)
    parser.add_argument('--memory-mib', type=int, default=4096)
    parser.add_argument('--cpus', type=int, choices=range(1, 5), default=4,
                        help='guest vCPUs passed to the runtime runner (default 4)')
    parser.add_argument('--boot-archive', action='store_true', help='export image and complete boot archive together')
    parser.add_argument('--storage-layout-policy', type=Path)
    parser.add_argument('--storage-bindings', type=Path)
    parser.add_argument('--capsule-validator', type=Path)
    parser.add_argument('--capsule-validator-sha256')
    parser.add_argument('--state-allocation', type=Path)
    parser.add_argument('--state-disk', type=Path)
    parser.add_argument('--state-disk-sha256')
    parser.add_argument('--state-work-directory')
    parser.add_argument('--state-case-timeout', type=int, help='explicit initialization harness budget; declared ATF limit remains recorded')
    args = parser.parse_args()
    value = args.input_mount_directory
    if (not value.startswith('/') or value == '/' or
            any(part in ('', '.', '..') for part in value.split('/')[1:]) or
            any(ord(c) < 32 or ord(c) == 127 for c in value)):
        parser.error('input mount directory must be a canonical absolute guest path')
    state_values = (args.state_allocation, args.state_disk, args.state_disk_sha256, args.state_work_directory)
    initialize_state = any(value is not None for value in state_values)
    if initialize_state:
        if (not all(value is not None for value in state_values) or args.storage_layout_policy is None or
                args.expect_incomplete or args.image_makefs is not None or args.image_work_directory is not None or
                args.output_disk_mib is None or not 16 <= args.output_disk_mib <= 16384):
            parser.error('state initialization requires allocation, disk/hash, work directory, layout and output capacity without image export')
        budget = args.state_case_timeout if args.state_case_timeout is not None else 3600
        if not 1 <= budget <= 86400 or args.vm_timeout <= budget:
            parser.error('state initialization requires a valid case budget below the VM budget')
        value = args.state_work_directory
        if not value.startswith('/') or value == '/' or any(part in ('', '.', '..') for part in value.split('/')[1:]) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            parser.error('state work directory must be a canonical absolute guest path')
        if (args.state_disk.is_symlink() or not args.state_disk.is_file() or
                args.state_disk.stat().st_size != args.output_disk_mib * 1024 * 1024 or
                digest(args.state_disk) != args.state_disk_sha256):
            parser.error('state source disk size or hash differs')
    if args.state_case_timeout is not None and not initialize_state:
        parser.error('state-case-timeout requires state initialization')
    split_image = args.storage_layout_policy is not None and args.image_makefs is not None
    binding_values = (args.storage_bindings, args.capsule_validator, args.capsule_validator_sha256)
    if split_image or any(value is not None for value in binding_values):
        if (not split_image or not all(value is not None for value in binding_values) or
                not re.fullmatch('[0-9a-f]{64}', args.capsule_validator_sha256 or '')):
            parser.error('split image requires layout, storage bindings and selected validator/hash')
    if args.storage_layout_policy is not None and args.expect_incomplete:
        parser.error('storage layout review requires positive verification')
    if (args.image_makefs is None) != (args.image_work_directory is None):
        parser.error('image export requires --image-work-directory on the private guest root disk')
    if args.image_work_directory is not None:
        value = args.image_work_directory
        if (not value.startswith('/') or value == '/' or
                any(part in ('', '.', '..') for part in value.split('/')[1:]) or
                any(ord(c) < 32 or ord(c) == 127 for c in value)):
            parser.error('image work directory must be a canonical absolute guest path')
    if args.boot_archive and args.image_makefs is None:
        parser.error('boot archive requires image construction')
    if not initialize_state and (args.image_makefs is None) != (args.output_disk_mib is None):
        parser.error('image export requires both makefs and output capacity')
    if args.image_makefs is not None and (args.expect_incomplete or not 16 <= args.output_disk_mib <= 16384):
        parser.error('image export requires positive verification and capacity 16..16384 MiB')
    if not 1 <= args.input_partition <= 128 or not 1 <= args.vm_timeout <= 86400:
        parser.error('invalid partition or VM time limit')
    if not 64 <= args.root_mib <= 16384 or not 512 <= args.memory_mib <= 65536:
        parser.error('root-mib must be 64..16384 and memory-mib 512..65536')
    work = args.work.resolve()
    if not work.is_relative_to('/usr/obj/usr/src') or work.exists():
        parser.error('work must be new under /usr/obj/usr/src')
    if args.input_disk.is_symlink() or not args.input_disk.is_file() or digest(args.input_disk) != args.input_disk_sha256:
        parser.error('input must be a regular disk matching the explicit hash')
    world, prefix = args.world.resolve(strict=True), args.python_prefix.resolve(strict=True)
    work.mkdir(mode=0o700); extra = work / 'extra'; extra.mkdir()
    fixture = Fixture(world, prefix, extra)
    fixture.python()
    for name in ('sbin/mount', 'sbin/umount', 'sbin/sysctl', 'usr/lib/libarchive.so'):
        fixture.elf(world / name, name, world)
    if args.image_makefs is not None:
        for name in ('sbin/mdconfig', 'usr/sbin/diskinfo'):
            fixture.elf(world / name, name, world)
        makefs = args.image_makefs.resolve(strict=True)
        fixture.elf(makefs, 'tests/makefs', makefs.parent)
    if split_image:
        validator = args.capsule_validator.resolve(strict=True)
        if digest(validator) != args.capsule_validator_sha256:
            raise ValueError('selected Capsule validator hash differs')
        fixture.elf(validator, 'tests/capsule-validator', validator.parent)
        bindings = args.storage_bindings.resolve(strict=True)
        fixture.copy(bindings, extra / 'tests/storage-bindings.json', bindings.parent)
    if initialize_state:
        for name in ('bin/sh', 'sbin/zfs', 'sbin/zpool', 'sbin/kldload', 'usr/bin/tar'):
            fixture.elf(world / name, name, world)
        module = args.objtop / 'sys' / args.kernconf / 'modules/usr/src/sys/modules/zfs/zfs.ko'
        fixture.copy(module, extra / 'boot/kernel/zfs.ko', args.objtop.resolve(strict=True))
        allocation = args.state_allocation.resolve(strict=True)
        fixture.copy(allocation, extra / 'tests/state-allocation-result.json', allocation.parent)
    sqlite = args.sqlite.resolve(strict=True)
    fixture.elf(sqlite, 'usr/local/bin/sqlite3', sqlite.parent)
    source = Path(__file__).resolve().parent
    backend = source.parents[1] / 'build/capimage'
    fixture.backend_python(backend)
    for name in ('verify_retained.py', 'verify_retained_vm.py', 'export_image.py', 'export_bundle.py', 'export_layout.py', 'builder_storage.py', 'installation_transport.py', 'state_initialization.py'):
        fixture.copy(source / name, extra / 'tests' / name, source)
    if args.storage_layout_policy is not None:
        policy = args.storage_layout_policy.resolve(strict=True)
        fixture.copy(policy, extra / 'tests/storage-layout-policy.json', policy.parent)
    (extra / args.input_mount_directory.lstrip('/')).mkdir(mode=0o700, parents=True)
    (extra / 'tests/retained-verification.json').write_text(json.dumps(
        {'input_mount_directory': args.input_mount_directory, 'split_image': split_image, 'capsule_validator_sha256': args.capsule_validator_sha256, 'partition': args.input_partition, 'work': args.retained_work, 'state_work_directory': args.state_work_directory, 'output_disk_mib': args.output_disk_mib, 'boot_archive': args.boot_archive, 'image_work_directory': args.image_work_directory}) + '\n')
    (work / 'fixture-inputs.json').write_text(json.dumps({
        'scope': 'retained-builder-post-shutdown-consistency-fixture',
        'expect_incomplete': args.expect_incomplete, 'generation_authenticated': False,
        'input_disk_sha256': args.input_disk_sha256, 'input_partition': args.input_partition,
        'retained_work': args.retained_work, 'image_work_directory': args.image_work_directory, 'root_mib': args.root_mib, 'memory_mib': args.memory_mib, 'guest_cpus': args.cpus,
        'files_sha256': fixture.source_hashes}, indent=2) + '\n')
    case = 'retained_state_initialize' if initialize_state else 'retained_incomplete' if args.expect_incomplete else 'retained_image' if args.image_makefs is not None else 'retained_verify'
    command = [sys.executable, '-B', str(source.parent / 'daemon-runtime/run-vm.py'),
        '--root', str(args.boot_root.resolve(strict=True)), '--objtop', str(args.objtop),
        '--fixture-objtop', str(args.fixture_objtop), '--work', str(work / 'vm'),
        '--qemu', args.qemu, '--qemu-data', str(args.qemu_data), '--kernconf', args.kernconf,
        '--input-disk', str(args.input_disk.resolve(strict=True)), '--input-disk-sha256', args.input_disk_sha256,
        '--extra-root', str(extra), '--root-mib', str(args.root_mib), '--memory-mib', str(args.memory_mib),
        '--cpus', str(args.cpus), '--timeout', str(args.vm_timeout), '--atf-case', 'tools/test/construction/construction_vm_test:' + case]
    if args.image_makefs is not None:
        command.extend(['--output-disk-mib', str(args.output_disk_mib)])
    if initialize_state:
        command.extend(['--output-disk-mib', str(args.output_disk_mib),
            '--output-disk-source', str(args.state_disk.resolve(strict=True)),
            '--output-disk-source-sha256', args.state_disk_sha256, '--retain-disk-writes'])
    if initialize_state and args.state_case_timeout is not None:
        command.extend(['--atf-case-budget', 'tools/test/construction/construction_vm_test:retained_state_initialize=' + str(args.state_case_timeout)])
    subprocess.run(command, check=True)
    for name, expected in fixture.source_hashes.items():
        if digest(Path(name)) != expected:
            raise ValueError('verifier input changed: ' + name)
    if not args.expect_incomplete:
        evidence = collect_verification(work)
        if initialize_state:
            result = json.loads((work / 'vm/result.json').read_text())
            initialized = evidence['report'].get('state_initialization', {})
            if (result.get('output_disk_source_unchanged') is not True or
                    initialized.get('result') != 'PASS' or initialized.get('pool_exported') is not True or
                    initialized.get('scope') != 'ordinary-state-initialization'):
                raise ValueError('state initialization or source isolation failed')
            (work / 'state-initialization.json').write_text(json.dumps(dict(
                format=1, scope='initialized-state-vm-transport',
                output_disk_sha256=result['output_disk_sha256'],
                allocation_sha256=digest(args.state_allocation),
                verification_sha256=digest(work / 'verification.json'),
                report=initialized, generation_authenticated=False, runtime_qualified=False), indent=2) + '\n')
    if args.image_makefs is not None:
        collect(work)
        if split_image:
            verify_layout_receipt_binding(work / 'layout/receipt.json',
                evidence['report'].get('image_receipt'))


if __name__ == '__main__':
    main()
