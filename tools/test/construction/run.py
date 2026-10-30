#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify the trusted-builder constructor in a disposable VM, not a BIP updater."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from fixture_stage import Fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--caroot-package', type=Path, required=True, help='explicit certificate source archive')
    parser.add_argument('--certificate-policy', type=Path, required=True, help='explicit fixture selection policy')
    parser.add_argument('--ldconfig', type=Path, help='explicit strict library-hints generator for the execution case')
    parser.add_argument('--kldxref', type=Path, required=True, help='explicit module-hints generator')
    parser.add_argument('--module', type=Path, required=True, help='real module for hints qualification')
    parser.add_argument('--certctl', type=Path, required=True, help='explicit certificate utility to qualify')
    parser.add_argument('--runtime-package', type=Path, required=True, help='explicit runtime archive with construction declarations')
    parser.add_argument('--system-certificate-policy', type=Path, help='explicit certificate policy for the full selected filesystem')
    parser.add_argument('--system-module-policy', type=Path, help='explicit module policy for the full selected filesystem')
    parser.add_argument('--system-library-policy', type=Path, help='explicit protected library hints policy')
    parser.add_argument('--system-installation-policy', type=Path, help='explicit package configuration replacements and source inputs')
    parser.add_argument('--system-storage-layout-policy', type=Path, help='explicit classification required after complete filesystem construction')
    parser.add_argument('--system-work-directory', help='explicit new disk-backed guest workspace; retain the private VM disk')
    parser.add_argument('--system-layout', type=Path, help='explicit root layout for full selected filesystem construction')
    parser.add_argument('--system-inventory', type=Path, help='explicit full selected archive inventory for separate database VM case')
    parser.add_argument('--constructor-timeout', type=int, default=300)
    parser.add_argument('--case-timeout', type=int, help='explicit full-filesystem ATF harness budget; recorded separately from the declared deadline')
    parser.add_argument('--vm-timeout', type=int, default=360)
    parser.add_argument('--memory-mib', type=int)
    parser.add_argument('--cpus', type=int, choices=range(1, 5), default=4,
                        help='guest vCPUs passed to the runtime runner (default 4)')
    parser.add_argument('--database-contract', type=Path, help='explicit format-3 constructor fixture contract')
    parser.add_argument('--sqlite', type=Path, help='explicit SQLite verifier for database construction')
    parser.add_argument('--pkg-abi')
    parser.add_argument('--pkg-osversion', type=int)
    parser.add_argument('--pkg-install-epoch', type=int, help='explicit database construction timestamp')
    parser.add_argument('--pkg-registration', type=Path, help='explicit static pkg executable for jailed registration controls')
    parser.add_argument('--builder-storage', action='store_true', help='qualify retained disk-backed builder workspace setup')
    parser.add_argument('--builder-work-directory', help='explicit new absolute guest path for builder storage qualification')
    parser.add_argument('--boot-environments', action='store_true',
                        help='run real private ZFS clone/removal tests; not BIP authorization')
    parser.add_argument('--root-mib', type=int, default=256, help='explicit fixture filesystem capacity')
    parser.add_argument('--world', type=Path, required=True)
    parser.add_argument('--python-prefix', type=Path, required=True)
    parser.add_argument('--objtop', type=Path, required=True)
    parser.add_argument('--fixture-objtop', type=Path,
                        help='explicit static runner/test snapshot under /usr/obj/usr/src')
    parser.add_argument('--kernconf', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--qemu-data', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.constructor_timeout <= 86400 or not 1 <= args.vm_timeout <= 86400:
        parser.error('timeouts must be between 1 and 86400 seconds')
    if args.case_timeout is not None and (args.system_layout is None or
            not 1 <= args.case_timeout <= 86400 or args.case_timeout >= args.vm_timeout):
        parser.error('case-timeout requires full filesystem construction and 1..86400 seconds below vm-timeout')
    if args.memory_mib is not None and not 512 <= args.memory_mib <= 65536:
        parser.error('memory-mib must be between 512 and 65536')
    if (args.system_certificate_policy is not None or args.system_module_policy is not None or args.system_library_policy is not None or args.system_installation_policy is not None or args.system_storage_layout_policy is not None) and args.system_layout is None:
        parser.error('system construction policies require --system-layout')
    if args.system_work_directory is not None and args.system_layout is None:
        parser.error('system work directory requires --system-layout')
    if args.system_layout is not None and args.system_inventory is None:
        parser.error('system layout requires full system inventory')
    if args.system_inventory is not None and args.database_contract is None:
        parser.error('system inventory requires explicit database contract and verifier')
    if not 64 <= args.root_mib <= 16384:
        parser.error('root-mib must be between 64 and 16384')
    if (args.database_contract is None) != (args.sqlite is None) or (args.database_contract is not None and args.pkg_registration is None):
        parser.error('database construction requires registration mode and both --database-contract and --sqlite')
    if args.pkg_registration is not None and (not args.pkg_abi or args.pkg_osversion is None):
        parser.error('registration requires explicit --pkg-abi and --pkg-osversion')
    if args.pkg_registration is None and (args.pkg_abi is not None or args.pkg_osversion is not None or args.pkg_install_epoch is not None):
        parser.error('pkg identity requires --pkg-registration')
    if args.pkg_registration is not None and (args.pkg_install_epoch is None or
            not 0 <= args.pkg_install_epoch <= 2**63 - 1):
        parser.error('pkg registration requires an explicit valid --pkg-install-epoch')
    if args.builder_storage != (args.builder_work_directory is not None):
        parser.error('builder storage requires an explicit --builder-work-directory')
    if args.builder_storage and (args.pkg_registration is not None or args.boot_environments):
        parser.error('select one qualification case')
    if args.pkg_registration is not None and args.boot_environments:
        parser.error('select one qualification case')
    if args.ldconfig is not None and (args.builder_storage or args.pkg_registration is not None or args.boot_environments or args.system_inventory is not None):
        parser.error('--ldconfig requires the execution qualification case')
    world, prefix, obj, work = (p.resolve() for p in
        (args.world, args.python_prefix, args.objtop, args.work))
    if not work.is_relative_to('/usr/obj/usr/src') or work.exists():
        parser.error('work must be a new directory under /usr/obj/usr/src')
    if not obj.is_relative_to('/usr/obj/usr/src'):
        parser.error('objects must be under /usr/obj/usr/src')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', args.kernconf):
        parser.error('invalid kernel configuration')
    kernel = obj / 'sys' / args.kernconf / 'kernel'
    # Installation inputs may contain instance secrets; protect all artifacts.
    work.mkdir(mode=0o700)
    extra, root = work / 'extra', work / 'boot-root'
    extra.mkdir(); root.mkdir()
    fixture = Fixture(world, prefix, extra)
    source_hashes, dependencies = fixture.source_hashes, fixture.dependencies
    copy, elf = fixture.copy, fixture.elf

    if args.pkg_registration is not None:
        (extra / 'tests').mkdir(parents=True, exist_ok=True)
        (extra / 'tests/pkg-identity.json').write_text(json.dumps(
            {'abi': args.pkg_abi, 'osversion': args.pkg_osversion, 'install_epoch': args.pkg_install_epoch}) + '\n')
        program = args.pkg_registration.resolve(strict=True)
        dynamic = subprocess.check_output(['readelf', '-d', str(program)], text=True)
        if '(NEEDED)' in dynamic:
            raise ValueError('registration fixture requires a static pkg executable')
        copy(program, extra / 'tests/pkg-static', program.parent)
        (extra / 'tests/pkg-static').chmod(0o555)
        if args.database_contract is not None:
            contract = args.database_contract.resolve(strict=True)
            copy(contract, extra / 'tests/database-contract.json', contract.parent)
            sqlite = args.sqlite.resolve(strict=True)
            elf(sqlite, 'usr/local/bin/sqlite3', sqlite.parent)
            elf(world / 'usr/bin/readelf', 'usr/bin/readelf', world)
        elf(world / 'usr/bin/env', 'usr/bin/env', world)
        elf(world / 'bin/sh', 'bin/sh', world)
        elf(world / 'sbin/sysctl', 'sbin/sysctl', world)
        closure, pending = set(), ['bin/sh']
        while pending:
            item = pending.pop()
            if item not in closure:
                closure.add(item); pending.extend(dependencies[item])
        (extra / 'tests/shell-closure.json').write_text(json.dumps(
            {'files': ['/' + item for item in sorted(closure)]}) + '\n')
        source = Path(__file__).resolve().parent
        copy(source / 'pkg_registration.py', extra / 'tests/pkg_registration.py', source)
    if args.boot_environments:
        helper = Path(__file__).resolve().parent.parent / 'daemon-runtime/zfs_fixture.py'
        zspec = importlib.util.spec_from_file_location('zfs_fixture', helper)
        zfs_fixture = importlib.util.module_from_spec(zspec)
        zspec.loader.exec_module(zfs_fixture)
        source_hashes.update(zfs_fixture.stage_zfs(world, kernel.parent, extra))
        source_hashes[str(helper)] = hashlib.file_digest(helper.open('rb'), 'sha256').hexdigest()
        for relative in ('sbin/bectl', 'sbin/kldload', 'sbin/sysctl', 'sbin/mount'):
            elf(world / relative, relative, world)
        source = Path(__file__).resolve().parents[3]
        copy(source / 'usr.sbin/bsd-build/tests/be_vm_test.py',
             extra / 'tests/be_vm_test.py', source)
        for name in ('deploy.py', 'package_closure.py'):
            copy(source / 'tools/build/capimage' / name, extra / 'tests' / name, source)
        (extra / 'etc').mkdir(parents=True, exist_ok=True)
        (extra / 'etc/fstab').write_text('# No persistent mount declarations in this fixture.\n')

    if args.builder_storage or args.system_work_directory is not None:
        sources = Path(__file__).resolve().parent
        for name in ('builder_storage.py', 'builder_storage_test.py', 'retained_system.py'):
            copy(sources / name, extra / 'tests' / name, sources)
        for relative in ('sbin/mount', 'sbin/sysctl'):
            elf(world / relative, relative, world)
        (extra / 'tests/builder-work.json').write_text(json.dumps({'work': args.system_work_directory or args.builder_work_directory}) + '\n')

    fixture.python()
    for relative in ('usr/sbin/jail', 'usr/sbin/jexec', 'usr/sbin/jls', 'usr/bin/tar', 'usr/lib/libarchive.so'):
        elf(world / relative, relative, world)
    hints_tool = args.kldxref.resolve(strict=True)
    elf(hints_tool, 'usr/sbin/kldxref', hints_tool.parent)
    hints_module = args.module.resolve(strict=True)
    copy(hints_module, extra / 'tests/selected.ko', hints_module.parent)
    closure, pending = set(), ['usr/sbin/kldxref']
    while pending:
        item = pending.pop()
        if item not in closure:
            closure.add(item); pending.extend(dependencies[item])
    (extra / 'tests/module-executable.json').write_text(json.dumps(
        {'files': ['/' + item for item in sorted(closure)]}) + '\n')
    certificate_tool = args.certctl.resolve(strict=True)
    elf(certificate_tool, 'usr/sbin/certctl', certificate_tool.parent)
    elf(world / 'usr/bin/openssl', 'usr/bin/openssl', world)
    sources = Path(__file__).resolve().parent
    if args.ldconfig is not None:
        hints = args.ldconfig.resolve(strict=True)
        elf(hints, 'sbin/ldconfig', hints.parent)
        closure, pending = set(), ['sbin/ldconfig']
        while pending:
            item = pending.pop()
            if item not in closure:
                closure.add(item); pending.extend(dependencies[item])
        (extra / 'tests').mkdir(exist_ok=True)
        (extra / 'tests/library-executable.json').write_text(json.dumps(
            {'files': ['/' + item for item in sorted(closure)]}) + '\n')
        copy(sources / 'library_construction.py', extra / 'tests/library_construction.py', sources)
        copy(sources / 'audit-ldconfig.py', extra / 'tests/audit-ldconfig.py', sources)
        (extra / 'tests/library-hints-settings.json').write_text(json.dumps(
            {'program': '/sbin/ldconfig', 'directory': '/usr/lib'}) + '\n')
    backend = sources.parents[1] / 'build/capimage'
    installation_tests = sources.parents[2] / 'usr.sbin/bsd-build/tests/installation_policy_test.py'
    copy(installation_tests, extra / 'tests/installation_policy_test.py', installation_tests.parent)
    fixture.backend_python(backend)
    spec = importlib.util.spec_from_file_location('package_inventory', backend / 'package_inventory.py')
    inventory_reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory_reader)
    if args.system_inventory is not None:
        inventory_input = args.system_inventory.resolve(strict=True)
        original = json.loads(inventory_input.read_bytes(), object_pairs_hook=inventory_reader.unique_object,
                              parse_constant=inventory_reader.invalid_constant)
        if original.get('format') != 1 or original.get('scope') != 'package-payload-inventory' or not original.get('packages'):
            raise ValueError('requires an explicit selected package inventory')
        source_hashes[str(inventory_input)] = hashlib.sha256(inventory_input.read_bytes()).hexdigest()
        if args.system_installation_policy is not None:
            spec = importlib.util.spec_from_file_location('construction', backend / 'construction.py')
            constructor = importlib.util.module_from_spec(spec); spec.loader.exec_module(constructor)
            initial, _ = constructor.generation.read_json(args.system_layout)
            installation = constructor.modules.read_policy(args.system_installation_policy, constructor.pkg)
            # This host-side expected-graph check does not attest a guest root.
            # Guest installation rechecks transported inputs and the real tree.
            constructor.installations.preflight(original, initial, installation,
                args.work.resolve(), constructor._construction_context())
        selected_archives = []
        for index, package in enumerate(original['packages']):
            archive = Path(package['archive'])
            if not archive.is_absolute() or archive.is_symlink():
                raise ValueError('system archive reference must be absolute and nonsymlink')
            archive = archive.resolve(strict=True)
            if hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() != package['archive_sha256']:
                raise ValueError('selected system archive changed')
            guest = '/tests/system-archives/' + str(index) + '.pkg'
            copy(archive, extra / guest.lstrip('/'), archive.parent)
            selected_archives.append(dict(archive=guest, archive_sha256=package['archive_sha256']))
        (extra / 'tests/system-inventory.json').write_text(json.dumps(dict(format=1,
            scope='package-payload-inventory', packages=selected_archives)) + '\n')
        (extra / 'tests/system-database-settings.json').write_text(json.dumps(dict(
            osversion=args.pkg_osversion, timeout=args.constructor_timeout,
            filesystem_construction=args.system_layout is not None,
            certificate_policy=args.system_certificate_policy is not None,
            module_policy=args.system_module_policy is not None,
            library_policy=args.system_library_policy is not None,
            installation_policy=args.system_installation_policy is not None,
            storage_layout_policy=args.system_storage_layout_policy is not None)) + '\n')
        if args.system_layout is not None:
            layout = args.system_layout.resolve(strict=True)
            copy(layout, extra / 'tests/system-layout.json', layout.parent)
            copy(backend / 'database-output-policy.json', extra / 'tests/database-output-policy.json', backend)
            for policy_input, name in ((args.system_certificate_policy, 'system-certificate-policy.json'),
                                       (args.system_module_policy, 'system-module-policy.json'),
                                       (args.system_library_policy, 'system-library-policy.json'),
                                       (args.system_storage_layout_policy, 'system-storage-layout-policy.json')):
                if policy_input is not None:
                    policy = policy_input.resolve(strict=True)
                    copy(policy, extra / 'tests' / name, policy.parent)
        if args.system_installation_policy is not None:
            transport_path = sources / 'installation_transport.py'
            spec = importlib.util.spec_from_file_location('installation_transport', transport_path)
            transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)
            copy(transport_path, extra / 'tests/installation_transport.py', sources)
            transport.stage(args.system_installation_policy, fixture)
        copy(sources / 'system_database.py', extra / 'tests/system_database.py', sources)
    # The fixture enumerates the actual certificate archive, never a list of
    # selected certificate names. Prefix roles are an explicit, hashed input.
    policy_source = args.certificate_policy.resolve(strict=True)
    copy(policy_source, extra / 'tests/certificate-policy.json', policy_source.parent)
    policy = json.loads((extra / 'tests/certificate-policy.json').read_text(),
                        object_pairs_hook=inventory_reader.unique_object,
                        parse_constant=inventory_reader.invalid_constant)
    if (not isinstance(policy, dict) or set(policy) != {'format', 'selections'} or
            type(policy['format']) is not int or policy['format'] != 1 or
            not isinstance(policy['selections'], list) or not 1 <= len(policy['selections']) <= 64):
        raise ValueError('invalid certificate fixture policy')
    for selection in policy['selections']:
        if (not isinstance(selection, dict) or set(selection) != {'role', 'prefix'} or
                selection['role'] not in ('trusted', 'untrusted') or
                inventory_reader.canonical_path(selection['prefix']) != selection['prefix'] or
                selection['prefix'] == '/'):
            raise ValueError('invalid certificate fixture selection')
    certificate_archive = args.caroot_package.resolve(strict=True)
    certificates = inventory_reader.inventory_packages([certificate_archive])['packages'][0]
    source_hashes[str(certificate_archive)] = certificates['archive_sha256']
    names = subprocess.check_output(['tar', '-tf', str(certificate_archive)], text=True).splitlines()
    certificate_inputs = []
    for path, entry in sorted(certificates['entries'].items()):
        if entry['type'] == 'directory':
            continue
        matching = [s for s in policy['selections'] if path.startswith(s['prefix'] + '/')]
        if entry['type'] != 'file' or len(matching) != 1:
            raise ValueError('certificate fixture payload is unclassified or ambiguous: ' + path)
        headers = [n for n in names if not n.startswith('+') and inventory_reader.canonical_path(n) == path]
        if len(headers) != 1:
            raise ValueError('ambiguous certificate archive header: ' + path)
        data = subprocess.check_output(['tar', '-xOf', str(certificate_archive), '--', headers[0]])
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError('certificate extraction differs from package payload')
        target = extra / 'tests/certificate-payload' / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        certificate_inputs.append({'path': path, 'role': matching[0]['role'], 'sha256': entry['sha256']})
    if not certificate_inputs:
        raise ValueError('empty certificate fixture inventory')
    (extra / 'tests/certificate-inputs.json').write_text(json.dumps({
        'archive_sha256': certificates['archive_sha256'],
        'policy_sha256': source_hashes[str(policy_source)],
        'inputs': certificate_inputs}, indent=2) + '\n')
    closure, pending = set(), ['usr/sbin/certctl']
    while pending:
        path = pending.pop()
        if path not in closure:
            closure.add(path)
            pending.extend(dependencies[path])
    (extra / 'tests/certificate-executable.json').write_text(json.dumps({
        'files': ['/' + path for path in sorted(closure)]}, indent=2) + '\n')
    copy(sources / 'module_construction.py', extra / 'tests/module_construction.py', sources)
    copy(sources / 'certificate_construction.py', extra / 'tests/certificate_construction.py', sources)
    copy(sources / 'certificate_fixture.py', extra / 'tests/certificate_fixture.py', sources)
    runtime_archive = args.runtime_package.resolve(strict=True)
    runtime = inventory_reader.inventory_packages([runtime_archive])
    package = runtime['packages'][0]
    source_hashes[str(runtime_archive)] = package['archive_sha256']
    actions = runtime['construction']['actions']
    if not actions:
        raise ValueError('runtime package has no construction actions')
    # Extract only archive-bound executable inputs, verifying exact bytes.
    # Their ELF closure comes from the explicit world/Python roots above.
    names = subprocess.check_output(['tar', '-tf', str(runtime_archive)], text=True).splitlines()
    program_paths = set()
    for action in actions:
        program = action['argv'][0]
        binding = action['executable_payload']
        headers = [n for n in names if not n.startswith('+') and inventory_reader.canonical_path(n) == binding['path']]
        if len(headers) != 1:
            raise ValueError('ambiguous executable archive header: ' + program)
        data = subprocess.check_output(['tar', '-xOf', str(runtime_archive), '--', headers[0]])
        if hashlib.sha256(data).hexdigest() != binding['sha256']:
            raise ValueError('extracted generator differs from package payload')
        source = work / 'packaged-programs' / program.lstrip('/')
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(data)
        relative = program.lstrip('/')
        elf(source, relative, work)
        if hashlib.file_digest((extra / relative).open('rb'), 'sha256').hexdigest() != binding['sha256']:
            raise ValueError('staged generator conflicts with package payload')
        program_paths.add(relative)
    closure, pending = set(), list(program_paths)
    while pending:
        path = pending.pop()
        if path not in closure:
            closure.add(path)
            pending.extend(dependencies[path])
    (extra / 'tests').mkdir(exist_ok=True)
    (extra / 'tests/runtime-declarations.json').write_text(json.dumps({
        'archive_sha256': package['archive_sha256'], 'package': package['name'],
        'declaration': package['manifest']['annotations']['5bsd.construction'],
        'files': ['/' + path for path in sorted(closure)]}, indent=2) + '\n')
    copy(sources / 'runtime_fixture.py', extra / 'tests/runtime_fixture.py', sources)
    certificate_tests = sources.parents[2] / 'usr.sbin/certctl/tests'
    copy(certificate_tests / 'failure_test.py', extra / 'tests/certctl_failure_test.py', certificate_tests)
    copy(sources / 'media_hints_fixture.py', extra / 'tests/media_hints_fixture.py', sources)
    copy(sources.parents[2] / 'release/scripts/hardware-packages.py',
         extra / 'usr/src/release/scripts/hardware-packages.py', sources.parents[2])
    copy(sources.parents[2] / 'tools/build/capimage/package_closure.py',
         extra / 'usr/src/tools/build/capimage/package_closure.py', sources.parents[2])
    copy(sources / 'audit-module-inputs.py', extra / 'tests/audit-module-inputs.py', sources)
    copy(sources / 'audit-pnp.py', extra / 'tests/audit-pnp.py', sources)
    for case in range(9):
        copy(obj / 'tools/test/construction' / f'pnp-{case}.ko',
             extra / 'tests/pnp' / f'pnp-{case}.ko', obj)
    copy(sources / 'audit-kldxref.py', extra / 'tests/audit-kldxref.py', sources)
    copy(sources / 'construction_vm.py', extra / 'tests/construction_vm.py', sources)
    for name in ('cap_mkdb', 'jail_probe', 'runtime_reader'):
        binary = obj / 'tools/test/construction' / name
        if 'statically linked' not in subprocess.check_output(['file', str(binary)], text=True):
            raise ValueError('construction fixture must be static: ' + str(binary))
        copy(binary, extra / 'tests' / name, obj)
    shutil.copytree(world / 'boot', root / 'boot', ignore=shutil.ignore_patterns(
        'kernel', 'modules', 'dtb', 'firmware', 'loader.conf', 'loader.conf.local', 'loader.conf.d', 'zfs'))
    copy(world / 'boot/defaults/loader.conf', root / 'boot/defaults/loader.conf', world)
    copy(kernel, root / 'boot/kernel/kernel', obj)
    (work / 'fixture-inputs.json').write_text(json.dumps({'scope': 'trusted-builder-construction-fixture',
        'secure_boot': False, 'runtime_bip': False, 'whole_system_upgrade': False,
        'boot_environment_mechanics': args.boot_environments,
        'library_hints_strict': args.ldconfig is not None,
        'builder_storage': args.builder_storage,
        'builder_work_directory': args.builder_work_directory,
        'system_work_directory': args.system_work_directory,
        'requested_case_timeout': args.case_timeout,
        'guest_cpus': args.cpus,
        'pkg_registration_controls': args.pkg_registration is not None,
        'database_construction': args.database_contract is not None,
        'filesystem_construction': args.system_layout is not None,
        'system_certificate_policy': args.system_certificate_policy is not None,
        'system_module_policy': args.system_module_policy is not None,
        'system_library_policy': args.system_library_policy is not None,
        'system_installation_policy': args.system_installation_policy is not None,
        'system_storage_layout_policy': args.system_storage_layout_policy is not None,
        'world': str(world), 'python_prefix': str(prefix), 'files_sha256': source_hashes}, indent=2) + '\n')
    command = [sys.executable, str(sources.parent / 'daemon-runtime/run-vm.py'),
        '--root', str(root), '--objtop', str(obj), '--kernconf', args.kernconf,
        '--cpus', str(args.cpus),
        '--extra-root', str(extra), '--work', str(work / 'vm'), '--qemu', args.qemu,
        '--qemu-data', str(args.qemu_data), '--timeout', str(args.vm_timeout), '--root-mib', str(args.root_mib),
        '--atf-case', 'tools/test/construction/construction_vm_test:' +
        ('builder_storage' if args.builder_storage else
         'retained_system_filesystem' if args.system_work_directory is not None else
         'system_filesystem' if args.system_layout is not None else
         'system_database' if args.system_inventory is not None else
         'pkg_registration' if args.pkg_registration is not None else
         'boot_environments' if args.boot_environments else 'execution')]
    if args.case_timeout is not None:
        command.extend(['--atf-case-budget', command[-1] + '=' + str(args.case_timeout)])
    if args.builder_storage or args.system_work_directory is not None:
        command.append('--retain-disk-writes')
    if args.fixture_objtop:
        command.extend(['--fixture-objtop', str(args.fixture_objtop.resolve(strict=True))])
    command.extend(['--memory-mib', str(args.memory_mib or (2048 if args.boot_environments else 1024))])
    result = subprocess.run(command)
    if result.returncode:
        raise SystemExit(result.returncode)
    for name, expected in source_hashes.items():
        if hashlib.file_digest(Path(name).open('rb'), 'sha256').hexdigest() != expected:
            raise ValueError('fixture source changed during qualification: ' + name)


if __name__ == '__main__':
    main()
