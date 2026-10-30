#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Mount a hash-bound artifact read-only and run verifier-side consistency checks."""
import argparse
import errno
import importlib.util
import logging
import json
import os
from pathlib import Path
import subprocess
import uuid


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--verify', action='store_true')
    mode.add_argument('--image', action='store_true')
    mode.add_argument('--initialize-state', action='store_true')
    mode.add_argument('--expect-incomplete', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or subprocess.check_output(
            ['/sbin/sysctl', '-n', 'kern.vm_guest'], text=True).strip() in ('', 'none'):
        raise ValueError('requires root in the disposable verifier VM')
    settings = json.loads(Path('/tests/retained-verification.json').read_text())
    partition = settings['partition']
    if type(partition) is not int or not 1 <= partition <= 128:
        raise ValueError('explicit GPT partition required')
    if Path('/tests/input-device').read_text() != '/dev/vtbd1\n':
        raise ValueError('unexpected read-only artifact device slot')
    spec = importlib.util.spec_from_file_location('verify_retained', Path('/tests/verify_retained.py'))
    verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
    # Use a pre-created mountpoint on the fixture root, not a nested tmpfs.
    # Nested mount/unmount WITNESS coverage remains a separate required test.
    root = Path(settings['input_mount_directory'])
    if (not root.is_absolute() or root == Path('/') or root.is_symlink() or
            root.resolve(strict=True) != root or not root.is_dir() or
            root.stat().st_dev != Path('/').stat().st_dev or any(root.iterdir())):
        raise ValueError('retained input mountpoint must be empty on the fixture root filesystem')
    mounted = False
    try:
        subprocess.run(['/sbin/mount', '-t', 'ufs', '-o', 'ro',
                        '/dev/vtbd1p' + str(partition), str(root)], check=True)
        mounted = True
        if not os.statvfs(root).f_flag & os.ST_RDONLY:
            raise ValueError('artifact mount is writable')
        try:
            with (root / ('write-refusal-' + uuid.uuid4().hex)).open('xb'):
                pass
        except OSError as error:
            if error.errno != errno.EROFS:
                raise
        else:
            raise ValueError('artifact mount allowed file creation')
        # JSON escaping keeps artifact log text from becoming serial PASS markers.
        print('RETAINED_DIAGNOSTICS ' + json.dumps(
            verifier.construction_diagnostics(root, settings['work']), sort_keys=True), flush=True)
        if args.expect_incomplete:
            workspace = verifier.rooted(root, settings['work'], directory=True)
            missing = workspace / 'retained-builder.json'
            try:
                verifier.verify(root, settings['work'], Path('/tests'), Path('/usr/local/bin/sqlite3'))
            except FileNotFoundError as error:
                if error.filename != str(missing):
                    raise
            else:
                raise ValueError('incomplete artifact was accepted')
            report = {'result': 'PASS', 'scope': 'retained-incomplete-artifact-refusal',
                      'readonly_mount_verified': True, 'file_creation_refused': True,
                      'missing_success_receipt_refused': True, 'candidate_verified': False}
        elif args.initialize_state:
            report, objects, inventory = verifier.verify(root, settings['work'], Path('/tests'),
                Path('/usr/local/bin/sqlite3'), with_inventory=True,
                storage_layout_policy=Path('/tests/storage-layout-policy.json'))
            modules = {}
            for name in ('state_storage', 'state_initialization', 'builder_storage'):
                selected = importlib.util.spec_from_file_location(name, Path('/tests') / (name + '.py'))
                module = importlib.util.module_from_spec(selected); selected.loader.exec_module(module)
                modules[name] = module
            state, initializer = modules['state_storage'], modules['state_initialization']
            policy, _ = state.image.construction.generation.read_json(Path('/tests/storage-layout-policy.json'))
            allocation, allocation_hash = state.image.construction.generation.read_json(Path('/tests/state-allocation-result.json'))
            layout, projections = state.image.partitions(inventory, objects, policy)
            candidate = verifier.rooted(root, settings['work'] + '/construction/candidate', directory=True)
            private_work = settings['state_work_directory']
            modules['builder_storage'].prepare(private_work, Path('/sbin/mount'), Path('/sbin/sysctl'))
            tools = {name: Path('/sbin') / name for name in ('zfs', 'zpool', 'mount')}
            tools['tar'] = Path('/usr/bin/tar')
            if Path('/tests/output-device').read_text() != '/dev/vtbd2\n':
                raise ValueError('state initialization requires the private output slot')
            def run(*argv):
                result = subprocess.run(argv, capture_output=True, text=True,
                    timeout=120, stdin=subprocess.DEVNULL, env=state.image.construction.ENVIRONMENT)
                with (Path(private_work) / 'pool-commands.log').open('a') as log:
                    log.write(result.stdout + result.stderr)
                result.check_returncode()
                return result.stdout.strip()
            initialized = initializer.initialize(candidate, projections, allocation, tools,
                Path(private_work) / 'initialization', state, run, device='/dev/vtbd2', timeout=900)
            initialized.update(allocation_sha256=allocation_hash,
                filesystem_sha256=report['filesystem_sha256'], inventory_sha256=report['inventory_sha256'])
            report['state_initialization'] = initialized
        elif args.image:
            split_image = settings.get('split_image', False)
            report, objects, inventory = verifier.verify(root, settings['work'], Path('/tests'),
                Path('/usr/local/bin/sqlite3'), with_inventory=True,
                storage_layout_policy=Path('/tests/storage-layout-policy.json') if split_image else None)
            modules = {}
            for name in ('generation_image', 'export_image'):
                module_spec = importlib.util.spec_from_file_location(name, Path('/tests') / (name + '.py'))
                module = importlib.util.module_from_spec(module_spec); module_spec.loader.exec_module(module)
                modules[name] = module
            generation_image, export_image = modules['generation_image'], modules['export_image']
            candidate = verifier.rooted(root, settings['work'] + '/construction/candidate', directory=True)
            # Keep full image/archive copies off the fixture's /tmp tmpfs.
            # This helper only remounts the disposable verifier's own UFS root;
            # the retained candidate remains a separate read-only input mount.
            storage_spec = importlib.util.spec_from_file_location(
                'builder_storage', '/tests/builder_storage.py')
            storage = importlib.util.module_from_spec(storage_spec)
            storage_spec.loader.exec_module(storage)
            image_work = settings.get('image_work_directory')
            if not isinstance(image_work, str):
                raise ValueError('explicit disk-backed image work directory required')
            storage_report = storage.prepare(image_work,
                Path('/sbin/mount'), Path('/sbin/sysctl'))
            print('IMAGE_STORAGE_RESULT ' + json.dumps(storage_report, sort_keys=True), flush=True)
            output = Path(image_work) / 'image'
            if not os.statvfs(root).f_flag & os.ST_RDONLY:
                raise ValueError('retained input became writable during storage preparation')
            tools = {'makefs': Path('/tests/makefs'), 'mdconfig': Path('/sbin/mdconfig'),
                     'mount': Path('/sbin/mount'), 'umount': Path('/sbin/umount')}
            input_bindings = {'retained_record_sha256': report['retained_record_sha256'],
                              'verified_filesystem_sha256': report['filesystem_sha256']}
            if split_image:
                read = generation_image.construction.generation.read_json
                policy, policy_hash = read(Path('/tests/storage-layout-policy.json'))
                input_bindings.update(storage_layout_policy_file_sha256=policy_hash)
                built = generation_image.materialize_layout(candidate, objects, inventory,
                    policy, tools, output, input_bindings,
                    export_boot=settings.get('boot_archive', False))
                layout_spec = importlib.util.spec_from_file_location('export_layout', '/tests/export_layout.py')
                layout_transport = importlib.util.module_from_spec(layout_spec)
                layout_spec.loader.exec_module(layout_transport)
                transported = layout_transport.create(output, Path(image_work) / 'layout.tar')
                exported = export_image.export(Path(image_work) / 'layout.tar', transported,
                    settings['output_disk_mib'], kind='layout')
            else:
                built = generation_image.materialize(candidate, objects, tools, output,
                    export_boot=settings.get('boot_archive', False), input_bindings=input_bindings)
            if not split_image and settings.get('boot_archive', False):
                bundle_spec = importlib.util.spec_from_file_location('export_bundle', '/tests/export_bundle.py')
                export_bundle = importlib.util.module_from_spec(bundle_spec); bundle_spec.loader.exec_module(export_bundle)
                bundled = export_bundle.create(output / 'system.ufs', output / 'boot.tar',
                    built, output / 'generation.tar')
                exported = export_image.export(output / 'generation.tar', bundled,
                    settings['output_disk_mib'], kind='bundle')
            elif not split_image:
                exported = export_image.export(output / 'system.ufs', built, settings['output_disk_mib'])
            print('IMAGE_EXPORT_RESULT ' + json.dumps(exported, sort_keys=True), flush=True)
            if split_image:
                report['image_receipt'] = verifier.layout_receipt_binding(
                    output / 'receipt.json', expected=built)
            else:
                report['image'] = built
            report['image_export'] = exported
        else:
            report = verifier.verify(root, settings['work'], Path('/tests'), Path('/usr/local/bin/sqlite3'),
                storage_layout_policy=(Path('/tests/storage-layout-policy.json')
                    if Path('/tests/storage-layout-policy.json').exists() else None))
        print('RETAINED_VERIFICATION_RESULT ' + json.dumps(report, sort_keys=True), flush=True)
    finally:
        if mounted:
            subprocess.run(['/sbin/umount', str(root)], check=True)


if __name__ == '__main__':
    main()
