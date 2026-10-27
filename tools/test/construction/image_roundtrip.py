#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Real UFS image metadata round trip in a disposable VM; not boot acceptance."""
import errno
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def run(*argv):
    return subprocess.check_output(argv, text=True, timeout=120).strip()


def unmount_order():
    """Minimal UFS-on-tmpfs lifecycle, independent of generation construction."""
    if os.geteuid() != 0 or run('/sbin/sysctl', '-n', 'kern.vm_guest') in ('', 'none'):
        raise ValueError('requires root in a disposable VM')
    work = Path('/tmp/unmount-order'); work.mkdir()
    source = work / 'source'; source.mkdir()
    (source / 'payload').write_bytes(b'unmount ordering fixture\n')
    image = work / 'image.ufs'
    mountpoint = work / 'mounted'; mountpoint.mkdir()
    run('/tests/makefs', '-t', 'ffs', '-s', '16m', '-o', 'version=2', str(image), str(source))
    device = run('/sbin/mdconfig', '-a', '-t', 'vnode', '-o', 'readonly', '-f', str(image))
    if not re.fullmatch(r'md[0-9]+', device):
        raise ValueError('unexpected memory disk identity')
    mounted = False
    try:
        run('/sbin/mount', '-t', 'ufs', '-o', 'ro', '/dev/' + device, str(mountpoint))
        mounted = True
        if (mountpoint / 'payload').read_bytes() != b'unmount ordering fixture\n':
            raise ValueError('mounted image content differs')
    finally:
        if mounted:
            run('/sbin/umount', str(mountpoint))
        run('/sbin/mdconfig', '-d', '-u', device[2:])
    print('UNMOUNT_ORDER_IMAGE_CLEANED shutdown-still-required', flush=True)


def seed_readback():
    if os.geteuid() != 0 or run('/sbin/sysctl', '-n', 'kern.vm_guest') in ('', 'none'):
        raise ValueError('requires root in a disposable VM')
    evidence = json.loads(Path('/tests/seed-dataset-evidence.json').read_text())
    receipt, expected = evidence['receipt'], evidence['observations']
    spec = importlib.util.spec_from_file_location('seed_dataset', '/tests/seed_dataset.py')
    dataset = importlib.util.module_from_spec(spec); spec.loader.exec_module(dataset)
    name = dataset.dataset_name(receipt['dataset'])
    pool, parent = name.split('/')[0], name.rsplit('/', 1)[0]
    if (receipt['result'] != 'PASS' or receipt.get('pool_synced') is not True or
            dataset.image.construction.digest(expected) != receipt['source_observation_sha256']):
        raise ValueError('invalid retained seed observation')
    for field in ('pool_guid', 'parent_guid', 'dataset_guid'):
        value = receipt[field]
        if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]*', value) or int(value) >= 2**64:
            raise ValueError('invalid retained storage identity')
    device = Path('/tests/input-device').read_text().strip()
    run('/sbin/zpool', 'import', '-N', '-d', device, '-o', 'readonly=on',
        '-o', 'cachefile=none', receipt['pool_guid'])
    mounted = False
    target = Path('/tmp/persistent-state'); target.mkdir()
    try:
        for program, obj, field in (('/sbin/zpool', pool, 'pool_guid'),
                                     ('/sbin/zfs', parent, 'parent_guid'),
                                     ('/sbin/zfs', name, 'dataset_guid')):
            if run(program, 'get', '-Hp', '-o', 'value', 'guid', obj) != receipt[field]:
                raise ValueError('cold-boot storage identity differs: ' + field)
        run('/sbin/mount', '-t', 'zfs', '-o', 'ro', name, str(target)); mounted = True
        if not os.statvfs(target).f_flag & os.ST_RDONLY:
            raise ValueError('cold-boot readback mount is writable')
        if dataset.image.construction.generation.scan(target) != expected:
            raise ValueError('cold-boot seed state differs')
        print('SEED_DATASET_COLD_BOOT_PASS pool-parent-dataset-guids exact-state readonly', flush=True)
    finally:
        if mounted:
            run('/sbin/umount', str(target))
        run('/sbin/zpool', 'export', pool)


def main():
    started = time.monotonic()
    def progress(phase):
        print('IMAGE_ROUNDTRIP_PROGRESS ' + json.dumps(dict(
            phase=phase, elapsed_seconds=round(time.monotonic() - started, 3))), flush=True)
    progress('start')
    if os.geteuid() != 0 or run('/sbin/sysctl', '-n', 'kern.vm_guest') in ('', 'none'):
        raise ValueError('requires root in a disposable VM')
    spec = importlib.util.spec_from_file_location('generation', '/tests/generation_check.py')
    generation = importlib.util.module_from_spec(spec); spec.loader.exec_module(generation)
    work = Path('/tmp/image-roundtrip'); work.mkdir(mode=0o700)
    source = work / 'source'; source.mkdir(mode=0o750)
    nested = source / 'directory with spaces'; nested.mkdir(mode=0o710)
    payload = nested / 'payload'; payload.write_bytes(b'full filesystem image fixture\n')
    os.chown(nested, 1234, 2345)
    os.chown(payload, 1234, 2345); payload.chmod(0o640)
    os.link(payload, source / 'hardlink')
    (source / 'relative link').symlink_to('directory with spaces/payload')
    (source / 'absolute link').symlink_to('/directory with spaces/payload')
    protected = source / 'immutable'; protected.write_bytes(b'protected payload\n')
    protected.chmod(0o444)
    boot = source / 'boot'; boot.mkdir()
    os.link(protected, boot / 'kernel')
    (boot / 'kernel-link').symlink_to('/boot/kernel')
    # Explicit nanosecond timestamps expose format conversions and truncation.
    for path in (payload, protected, nested, source, source / 'relative link', source / 'absolute link'):
        os.utime(path, ns=(1700000000123456789, 1700000000987654321), follow_symlinks=False)
    os.chflags(protected, 0x20000)  # SF_IMMUTABLE; real inode metadata.
    before = generation.scan(source)
    for version in (1, 2):
        image = work / ('system-' + str(version) + '.ufs')
        run('/tests/makefs', '-t', 'ffs', '-s', '16m', '-o', 'version=' + str(version), str(image), str(source))
        if generation.scan(source) != before:
            raise ValueError('image construction changed source metadata/content')
        mountpoint = work / ('mounted-' + str(version)); mountpoint.mkdir()
        device = run('/sbin/mdconfig', '-a', '-t', 'vnode', '-o', 'readonly', '-f', str(image))
        if not re.fullmatch(r'md[0-9]+', device):
            raise ValueError('unexpected newly allocated memory disk identity')
        mounted = False
        try:
            run('/sbin/mount', '-t', 'ufs', '-o', 'ro', '/dev/' + device, str(mountpoint))
            mounted = True
            if not os.statvfs(mountpoint).f_flag & os.ST_RDONLY:
                raise ValueError('image mount is writable')
            after = generation.scan(mountpoint)
            if after != before:
                differences = {p: {'source': before.get(p), 'image': after.get(p)}
                               for p in set(before) | set(after) if before.get(p) != after.get(p)}
                raise ValueError('image changed filesystem observations: ' + json.dumps(differences, sort_keys=True))
            try:
                (mountpoint / 'unauthorized').write_bytes(b'write must fail')
            except OSError as error:
                if error.errno != errno.EROFS:
                    raise
            else:
                raise ValueError('read-only image accepted mutation')
            print('IMAGE_ROUNDTRIP_RESULT ' + json.dumps(dict(result='PASS', ffs_version=version, objects=len(before),
                readonly_write_refused=True, scope='UFS metadata/content round trip',
                generation_authenticated=False, normal_boot_verified=False)), flush=True)
        finally:
            if mounted:
                run('/sbin/umount', str(mountpoint))
            run('/sbin/mdconfig', '-d', '-u', device[2:])
        progress('ufs-' + str(version) + '-cleanup-complete')

    spec = importlib.util.spec_from_file_location('generation_image', '/tests/generation_image.py')
    builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    tools = {'makefs': Path('/tests/makefs'), 'mdconfig': Path('/sbin/mdconfig'),
             'mount': Path('/sbin/mount'), 'umount': Path('/sbin/umount')}
    changed = dict(before)
    changed['/'] = dict(before['/'], mode=0)
    rejected = work / 'changed-source'
    try:
        builder.materialize(source, changed, tools, rejected)
    except ValueError as error:
        if 'generation changed before image creation' not in str(error):
            raise
    else:
        raise ValueError('image builder accepted stale source observation')
    if rejected.exists():
        raise ValueError('stale source refusal created an output')
    progress('materialize-start')
    report = builder.materialize(source, before, tools, work / 'accepted-image', export_boot=True)
    progress('materialize-complete')
    if report['boot_archive']['entries'] != {n:v for n,v in before.items()
            if n == '/boot' or n.startswith('/boot/')}:
        raise ValueError('boot transport omitted generation observations')
    if report['boot_archive']['entries']['/boot/kernel']['flags_set'] != 0x20000:
        raise ValueError('boot transport lost immutable metadata binding')
    if report['result'] != 'PASS' or report['generation_authenticated'] or report['activation_authorized']:
        raise ValueError('image materializer reported incorrect scope')
    print('GENERATION_IMAGE_RESULT ' + json.dumps(report, sort_keys=True), flush=True)
    # Exercise real partition images, including original mutable-root ownership,
    # hardlinks, escaped names and exact immutable attachment placeholders.
    state = source / 'state with spaces'; state.mkdir(mode=0o770)
    os.chown(state, 1234, 2345)
    seed = state / 'initial value'; seed.write_bytes(b'preserved initial state\n')
    seed.chmod(0o640)
    os.link(seed, state / 'alias')
    (state / 'relative link').symlink_to('initial value')
    protected_state = source / 'protected-state'; protected_state.mkdir()
    (protected_state / 'config').write_bytes(b'security input\n')
    before_partition = generation.scan(source)
    policy = dict(format=1, boundaries=[
        dict(path='/state with spaces', content='ordinary'),
        dict(path='/protected-state', content='protected')])
    progress('partition-images-start')
    partition = builder.materialize_layout(source, before_partition, {'packages': []},
        policy, tools, work / 'partition-images', export_boot=True)
    if partition['result'] != 'PASS' or len(partition['images']) != 3:
        raise ValueError('partition images incomplete')
    base = partition['images'][0]['observations']
    if any(n.startswith('/state with spaces/') or n.startswith('/protected-state/') for n in base):
        raise ValueError('mutable seed leaked into immutable image')
    ordinary = next(i for i in partition['images'] if i['content'] == 'ordinary')['observations']
    if ordinary['/']['uid'] != 1234 or ordinary['/']['gid'] != 2345:
        raise ValueError('seed root ownership changed')
    if base['/state with spaces']['uid'] != 0 or base['/state with spaces']['mode'] != 0o755:
        raise ValueError('attachment slot metadata is unsafe')
    if ordinary['/initial value']['hardlinks'] != ['/alias', '/initial value']:
        raise ValueError('seed hardlinks lost or not rebased')
    if generation.scan(source) != before_partition:
        raise ValueError('partition construction changed source')
    print('STORAGE_IMAGE_ROUNDTRIP_PASS base-and-two-seeds metadata hardlinks unchanged-source', flush=True)
    spec = importlib.util.spec_from_file_location('seed_initialize', '/tests/seed_initialize.py')
    initializer = importlib.util.module_from_spec(spec); spec.loader.exec_module(initializer)
    seed_entry = next(i for i in partition['images'] if i['content'] == 'ordinary')
    seed_image = work / 'partition-images' / seed_entry['directory'] / 'system.ufs'
    seed_mount = work / 'seed-source'; seed_mount.mkdir()
    seed_target = work / 'new-state'; seed_target.mkdir()
    device = run('/sbin/mdconfig', '-a', '-t', 'vnode', '-o', 'readonly', '-f', str(seed_image))
    if not re.fullmatch(r'md[0-9]+', device):
        raise ValueError('unexpected seed memory disk identity')
    mounted = False
    try:
        run('/sbin/mount', '-t', 'ufs', '-o', 'ro', '/dev/' + device, str(seed_mount)); mounted = True
        initialized = initializer.initialize(seed_mount, seed_target, seed_entry['observations'],
            Path('/usr/bin/tar'), work / 'seed-initialization')
        if initialized['result'] != 'PASS' or initialized['dataset_identity_verified']:
            raise ValueError('incorrect seed initialization scope')
        before_retry = generation.scan(seed_target)
        try:
            initializer.initialize(seed_mount, seed_target, seed_entry['observations'],
                Path('/usr/bin/tar'), work / 'seed-retry')
        except ValueError as error:
            if 'existing state' not in str(error):
                raise
        else:
            raise ValueError('seed initialization overwrote existing state')
        if generation.scan(seed_target) != before_retry or (work / 'seed-retry').exists():
            raise ValueError('refused seed initialization modified state')
        print('SEED_INITIALIZATION_PASS metadata hardlinks existing-state-refused', flush=True)
        scratch = Path('/tests/scratch-device')
        if scratch.exists():
            spec = importlib.util.spec_from_file_location('seed_dataset', '/tests/seed_dataset.py')
            dataset = importlib.util.module_from_spec(spec); spec.loader.exec_module(dataset)
            pool = 'seedfixture'
            device_path = scratch.read_text().strip()
            run('/sbin/zpool', 'create', '-o', 'cachefile=none', '-O', 'mountpoint=none', pool, device_path)
            try:
                run('/sbin/zfs', 'create', '-o', 'mountpoint=none', pool + '/state')
                pool_guid = run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'guid', pool)
                parent_guid = run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'guid', pool + '/state')
                provision_tools = dict(zfs=Path('/sbin/zfs'), zpool=Path('/sbin/zpool'),
                                       mount=Path('/sbin/mount'), tar=Path('/usr/bin/tar'))
                result = dataset.provision(seed_mount, seed_entry['observations'], pool + '/state/service',
                    pool_guid, parent_guid, provision_tools, work / 'dataset-initialization')
                if result['result'] != 'PASS' or not result['dataset_identity_verified']:
                    raise ValueError('dataset provisioning did not verify identity')
                for name, selected_pool in ((pool + '/state/service', pool_guid),
                                            (pool + '/state/wrong-pool', str(int(pool_guid) ^ 1))):
                    try:
                        dataset.provision(seed_mount, seed_entry['observations'], name,
                            selected_pool, parent_guid, provision_tools, work / ('reject-' + name.rsplit('/', 1)[1]))
                    except ValueError as error:
                        if not any(word in str(error) for word in ('existing dataset', 'identity differs')):
                            raise
                    else:
                        raise ValueError('unsafe dataset provisioning accepted')
                mounted_state = work / 'dataset-readback'; mounted_state.mkdir()
                run('/sbin/mount', '-t', 'zfs', pool + '/state/service', str(mounted_state))
                try:
                    if generation.scan(mounted_state) != seed_entry['observations']:
                        raise ValueError('seed did not persist after dataset remount')
                finally:
                    run('/sbin/umount', str(mounted_state))
                print('SEED_DATASET_PASS guid-bound existing-refused wrong-pool-refused persisted-remount', flush=True)
                protected_entry = next(i for i in partition['images'] if i['content'] == 'protected')
                def selected_file(path):
                    return dict(path=str(path), sha256=dataset.image.file_hash(path))

                def state_command(plan, output):
                    plan_path = work / (output.name + '-plan.json')
                    plan_path.write_text(json.dumps(plan, sort_keys=True) + '\n')
                    subprocess.run([sys.executable, '-B', '/tests/state_storage.py',
                        '--plan', str(plan_path), '--output', str(output)],
                        check=True, timeout=180)
                    request = json.loads((output / 'request.json').read_text())
                    if request != dict(format=1,
                            plan_file_sha256=dataset.image.file_hash(plan_path),
                            operation=plan['operation'], generation_authenticated=False,
                            activation_authorized=False):
                        raise ValueError('state command receipt does not bind selected plan')
                    return json.loads((output / 'receipt.json').read_text())

                allocation_work = work / 'protected-dataset-allocation'
                allocation = state_command(dict(format=1, operation='allocate', timeout=120,
                    dataset=pool + '/state/protected', pool_guid=pool_guid, parent_guid=parent_guid,
                    tools={k: selected_file(v) for k, v in provision_tools.items() if k != 'tar'}),
                    allocation_work)
                wrong_allocation = dict(allocation, dataset_guid=str(int(allocation['dataset_guid']) ^ 1))
                try:
                    dataset.initialize_allocated(source / 'protected-state', protected_entry['observations'],
                        wrong_allocation, provision_tools, work / 'wrong-allocation')
                except ValueError as error:
                    if 'identity differs' not in str(error):
                        raise
                else:
                    raise ValueError('wrong allocated dataset GUID accepted')
                observation_path = work / 'protected-seed-observation.json'
                observation_path.write_text(json.dumps(protected_entry['observations'], sort_keys=True) + '\n')
                protected_result = state_command(dict(format=1, operation='initialize', timeout=120,
                    source=str(source / 'protected-state'), observation=selected_file(observation_path),
                    allocation=selected_file(allocation_work / 'receipt.json'),
                    tools={k: selected_file(v) for k, v in provision_tools.items()}),
                    work / 'protected-dataset-initialization')
                if protected_result['dataset_guid'] != allocation['dataset_guid']:
                    raise ValueError('dataset identity changed between allocation and initialization')
                try:
                    dataset.initialize_allocated(source / 'protected-state', protected_entry['observations'],
                        allocation, provision_tools, work / 'reused-allocation')
                except ValueError as error:
                    if 'existing state' not in str(error):
                        raise
                else:
                    raise ValueError('allocation receipt permitted existing-state overwrite')
                print('SEED_ALLOCATION_PASS separate-phases stable-guid wrong-guid-refused reuse-refused command-plans-bound', flush=True)

            finally:
                run('/sbin/zpool', 'export', pool)
            print('SEED_DATASET_OBSERVATION ' + json.dumps(dict(receipt=result, observations=seed_entry['observations']), sort_keys=True), flush=True)

    finally:
        if mounted:
            run('/sbin/umount', str(seed_mount))
        run('/sbin/mdconfig', '-d', '-u', device[2:])
    progress('partition-images-complete')
    staged = Path('/tests/boot-transport.json')
    if staged.exists():
        progress('boot-transport-start')
        expected = json.loads(staged.read_text())['expected_observations']
        mountpoint = work / 'boot-transport'; mountpoint.mkdir()
        device = run('/sbin/mdconfig', '-a', '-t', 'vnode', '-o', 'readonly', '-f', '/tests/boot-transport.ufs')
        if not re.fullmatch(r'md[0-9]+', device):
            raise ValueError('unexpected boot transport memory disk')
        mounted = False
        try:
            run('/sbin/mount', '-t', 'ufs', '-o', 'ro', '/dev/' + device, str(mountpoint))
            mounted = True
            if not os.statvfs(mountpoint).f_flag & os.ST_RDONLY:
                raise ValueError('boot transport mount is writable')
            progress('boot-transport-scan-start')
            actual = generation.scan(mountpoint)
            progress('boot-transport-scan-complete')
            if actual != expected:
                differences = {n: {'expected': expected.get(n), 'actual': actual.get(n)}
                    for n in set(expected) | set(actual) if expected.get(n) != actual.get(n)}
                raise ValueError('boot transport read-back differs: ' + json.dumps(differences, sort_keys=True))
            print('BOOT_TRANSPORT_READBACK_PASS objects=' + str(len(actual)), flush=True)
        finally:
            if mounted:
                run('/sbin/umount', str(mountpoint))
            run('/sbin/mdconfig', '-d', '-u', device[2:])
    settings = Path('/tests/image-export-settings.json')
    if settings.exists():
        spec = importlib.util.spec_from_file_location('export_image', '/tests/export_image.py')
        exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)
        config = json.loads(settings.read_text())
        if config.get('bundle', False):
            bundle_spec = importlib.util.spec_from_file_location('export_bundle', '/tests/export_bundle.py')
            export_bundle = importlib.util.module_from_spec(bundle_spec); bundle_spec.loader.exec_module(export_bundle)
            directory = work / 'accepted-image'
            bundled = export_bundle.create(directory / 'system.ufs', directory / 'boot.tar',
                report, directory / 'generation.tar')
            exported = exporter.export(directory / 'generation.tar', bundled,
                config['capacity_mib'], kind='bundle')
        else:
            exported = exporter.export(work / 'accepted-image/system.ufs', report, config['capacity_mib'])
        print('IMAGE_EXPORT_RESULT ' + json.dumps(exported, sort_keys=True), flush=True)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--unmount-order', action='store_true')
    parser.add_argument('--seed-readback', action='store_true')
    args = parser.parse_args()
    if args.seed_readback:
        seed_readback()
    elif args.unmount_order:
        unmount_order()
    else:
        main()
