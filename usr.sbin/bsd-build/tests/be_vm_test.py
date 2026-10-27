#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Opt-in real ZFS clone checks, only inside an explicitly disposable VM.

Uses one newly created file-backed pool. Only selects or activates datasets in that private pool; never upgrades
or destroys any host/system pool. This tests clone/removal mechanics, not authenticated upgrades or BIP authorization.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import shutil
import shlex
import sys
import tempfile
import uuid


def run(*args):
    argv = list(map(str, args))
    print('BE_VM_COMMAND: ' + shlex.join(argv), flush=True)
    result = subprocess.run(argv, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, end='', flush=True)
        print(result.stderr, end='', file=sys.stderr, flush=True)
    result.check_returncode()
    return result.stdout.strip()


def refuse(*args):
    argv = list(map(str, args))
    print('BE_VM_EXPECT_REFUSAL: ' + shlex.join(argv), flush=True)
    result = subprocess.run(argv, text=True, capture_output=True)
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', file=sys.stderr, flush=True)
    if result.returncode <= 0:
        raise RuntimeError('expected a normal nonzero refusal: ' + shlex.join(argv))


def check_clone(deploy, root, tmp, selector, name, private_paths):
    source = deploy.be_source(selector, root, private_paths=private_paths)
    candidate = deploy.be_create(name, source)
    prefix = candidate['command']
    target = tmp / name
    run(*prefix, 'mount', name, target)
    try:
        deploy.be_check_target(target, source, name)
        assert (target / 'etc/clone-sentinel').read_text() == 'source remains unchanged\n'
        (target / 'etc/clone-sentinel').write_text('candidate only\n')
        assert deploy.zfs_properties(root + '/base')['readonly'] == 'on'
    finally:
        run(*prefix, 'unmount', name)


def check_clone_properties(root, label, altroot=''):
    """Real-pool property assertions; called only by the disposable VM fixture."""
    source = root + '/properties-' + label
    name = 'properties-copy-' + label
    candidate = root + '/' + name
    run('/sbin/zfs', 'create', '-o', 'canmount=noauto', '-o', 'mountpoint=/',
        '-o', 'quota=123456789', '-o', 'refquota=98765432', source)
    for suffix, mountpoint in [('data', '/var/property-test'),
                               ('none', 'none'), ('legacy', 'legacy')]:
        run('/sbin/zfs', 'create', '-o', 'canmount=noauto',
            '-o', 'mountpoint=' + mountpoint, source + '/' + suffix)
    run('/sbin/zfs', 'snapshot', '-r', source + '@properties')
    run('bectl', '-r', root, 'create', '-r', '-e', source + '@properties', name)
    for prop, expected in [('quota', '123456789'), ('refquota', '98765432')]:
        for dataset in (source, candidate):
            assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value', prop, dataset) == expected
    expected_mounts = {'': altroot or '/', '/data': altroot + '/var/property-test',
                       '/none': 'none', '/legacy': 'legacy'}
    for suffix, expected in expected_mounts.items():
        for dataset in (source + suffix, candidate + suffix):
            assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'mountpoint', dataset) == expected
            assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'canmount', dataset) == 'noauto'
    run('bectl', '-r', root, 'destroy', name)
    remaining = run('/sbin/zfs', 'list', '-H', '-o', 'name', '-r', root).splitlines()
    assert not any(path == candidate or path.startswith(candidate + '/') for path in remaining)
    assert all(source + suffix in remaining for suffix in expected_mounts)
    print('BE_VM_PASS: exact quotas and mountpoint properties preserved; recursive clone removed: ' + label)


def check_activation_failure(root, label):
    """A real snapshot conflict must not change the disposable pool's bootfs."""
    pool = root.split('/', 1)[0]
    prior = run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'bootfs', pool)
    assert prior.startswith(root + '/')
    source = root + '/activation-source-' + label
    name = 'activation-copy-' + label
    candidate = root + '/' + name
    run('/sbin/zfs', 'create', '-o', 'canmount=noauto', '-o', 'mountpoint=/', source)
    run('/sbin/zfs', 'snapshot', source + '@conflict')
    run('bectl', '-r', root, 'create', '-e', source + '@conflict', name)
    identity = run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'guid', candidate)
    assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'origin', candidate) == source + '@conflict'
    # Promotion must transfer the origin snapshot name, which now collides
    # with a distinct snapshot of the clone. The kernel rejects the conflict.
    run('/sbin/zfs', 'snapshot', candidate + '@conflict')
    refuse('bectl', '-r', root, 'activate', name)
    assert run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'bootfs', pool) == prior
    assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'guid', candidate) == identity
    assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'origin', candidate) == source + '@conflict'
    run('/sbin/zfs', 'destroy', candidate + '@conflict')
    run('bectl', '-r', root, 'activate', name)
    assert run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'bootfs', pool) == candidate
    assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'origin', candidate) == '-'
    run('bectl', '-r', root, 'activate', prior)
    assert run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'bootfs', pool) == prior
    run('bectl', '-r', root, 'destroy', name)
    remaining = run('/sbin/zfs', 'list', '-H', '-o', 'name', '-r', root).splitlines()
    assert candidate not in remaining and source in remaining and prior in remaining
    print('BE_VM_PASS: failed promotion retains selection; retry, restore and removal succeed: ' + label)


def main():
    if not __debug__:
        raise SystemExit('boot-environment fixture requires Python assertions enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--work-root', type=Path, default=Path('/var/tmp'),
                        help='existing writable guest directory for the private pool backing file')
    args = parser.parse_args()
    if os.geteuid() != 0 or run('sysctl', '-n', 'kern.vm_guest') in ('', 'none'):
        raise SystemExit('requires root inside an explicitly disposable VM')
    spec = importlib.util.spec_from_file_location('deploy', args.helper)
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    pool = 'build_bsd_test_' + uuid.uuid4().hex[:12]
    created = False
    guid = None
    tmp = Path(tempfile.mkdtemp(prefix='build-bsd-zfs-', dir=args.work_root.resolve(strict=True)))
    cleaned = False
    try:
        disk = tmp / 'pool.img'
        with disk.open('xb') as stream:
            stream.truncate(512 * 1024 * 1024)
        try:
            run('/sbin/zpool', 'create', '-m', 'none', '-o', 'cachefile=none',
                pool, disk)
            created = True
            guid = run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'guid', pool)
            root = pool + '/ROOT'
            run('/sbin/zfs', 'create', '-o', 'mountpoint=none', root)
            run('/sbin/zfs', 'create', '-o', 'canmount=noauto',
                '-o', 'mountpoint=/', root + '/base')
            shared = tmp / 'shared'
            run('/sbin/zfs', 'create', '-o', 'mountpoint=' + str(shared),
                pool + '/shared')
            (shared / 'persistent-sentinel').write_bytes(b'persistent user data\n')
            shared_guid = run('/sbin/zfs', 'get', '-Hp', '-o', 'value',
                              'guid', pool + '/shared')
            base = tmp / 'base'
            run('bectl', '-r', root, 'mount', 'base', base)
            private_paths = deploy.deployment_private_paths({'/etc/clone-sentinel': {'type': 'file'}})
            for name in private_paths:
                (base / name).mkdir(parents=True, exist_ok=True)
            (base / 'etc/clone-sentinel').write_text('source remains unchanged\n')
            run('bectl', '-r', root, 'unmount', 'base')
            run('/sbin/zfs', 'snapshot', root + '/base@fixture')
            run('/sbin/zfs', 'set', 'readonly=on', root + '/base')
            for selector, name in [('base', 'from-be'), ('base@fixture', 'from-snapshot')]:
                check_clone(deploy, root, tmp, selector, name, private_paths)
            run('bectl', '-r', root, 'mount', 'base', base)
            try:
                assert (base / 'etc/clone-sentinel').read_text() == 'source remains unchanged\n'
            finally:
                run('bectl', '-r', root, 'unmount', 'base')
            print('BE_VM_PASS: BE and snapshot clones writable; source retained unchanged')
            # Select a default only in this newly created disposable pool.
            # This never changes the VM's running pool or firmware boot order.
            default_guid = run('/sbin/zfs', 'get', '-Hp', '-o', 'value',
                               'guid', root + '/base')
            run('/sbin/zpool', 'set', 'bootfs=' + root + '/base', pool)
            refuse('bectl', '-r', root, 'destroy', 'base')
            assert run('/sbin/zpool', 'get', '-Hp', '-o', 'value',
                       'bootfs', pool) == root + '/base'
            assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value',
                       'guid', root + '/base') == default_guid
            run('bectl', '-r', root, 'mount', 'base', base)
            try:
                assert (base / 'etc/clone-sentinel').read_text() == 'source remains unchanged\n'
            finally:
                run('bectl', '-r', root, 'unmount', 'base')
            print('BE_VM_PASS: default boot selection refuses deletion; identity and contents retained')
            # Exercise removal explicitly, before the whole-pool cleanup. Do
            # not use -F or -o: neither mounted environments nor clone origins
            # should be silently removed by this mechanism test.
            retiring = root + '/from-be'
            retiring_guid = run('/sbin/zfs', 'get', '-Hp', '-o', 'value',
                                'guid', retiring)
            target = tmp / 'from-be'
            run('bectl', '-r', root, 'mount', 'from-be', target)
            try:
                refuse('bectl', '-r', root, 'destroy', 'from-be')
                assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value',
                           'guid', retiring) == retiring_guid
                assert (target / 'etc/clone-sentinel').read_text() == 'candidate only\n'
            finally:
                run('bectl', '-r', root, 'unmount', 'from-be')
            # A real ZFS hold exercises a storage refusal, followed by retry.
            # This does not simulate power loss or authenticated retention policy.
            held = retiring + '@retention-fixture'
            run('/sbin/zfs', 'snapshot', held)
            run('/sbin/zfs', 'hold', 'fixture-retention', held)
            # Explicit snapshot removal must report the hold failure too;
            # the callback historically discarded zfs_destroy's result.
            refuse('bectl', '-r', root, 'destroy', 'from-be@retention-fixture')
            run('/sbin/zfs', 'list', '-H', held)
            refuse('bectl', '-r', root, 'destroy', 'from-be')
            assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value',
                       'guid', retiring) == retiring_guid
            holds = run('/sbin/zfs', 'holds', '-H', held)
            assert any(line.split()[1] == 'fixture-retention'
                       for line in holds.splitlines())
            run('bectl', '-r', root, 'mount', 'from-be', target)
            try:
                assert (target / 'etc/clone-sentinel').read_text() == 'candidate only\n'
            finally:
                run('bectl', '-r', root, 'unmount', 'from-be')
            run('/sbin/zfs', 'release', 'fixture-retention', held)
            run('bectl', '-r', root, 'destroy', 'from-be')
            print('BE_VM_PASS: mounted and held environments refuse deletion; retry succeeds after release')
            # Persist the deletion and reopen only this test pool by GUID.
            # Preserve artifacts if export/import fails: cleanup must still
            # find the same imported pool identity before destroying anything.
            survivor_guids = {
                name: run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'guid', root + '/' + name)
                for name in ('base', 'from-snapshot')
            }
            origin_guid = run('/sbin/zfs', 'get', '-Hp', '-o', 'value',
                              'guid', root + '/base@fixture')
            run('/sbin/zpool', 'sync', pool)
            run('/sbin/zpool', 'export', pool)
            run('/sbin/zpool', 'import', '-N', '-o', 'cachefile=none', '-d', tmp, guid)
            assert run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'guid', pool) == guid
            assert run('/sbin/zpool', 'get', '-Hp', '-o', 'value',
                       'bootfs', pool) == root + '/base'
            run('/sbin/zfs', 'mount', pool + '/shared')
            for name, expected_guid in survivor_guids.items():
                assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value',
                           'guid', root + '/' + name) == expected_guid
            assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value',
                       'guid', root + '/base@fixture') == origin_guid
            datasets = run('/sbin/zfs', 'list', '-H', '-o', 'name', '-r',
                           pool).splitlines()
            assert root + '/from-be' not in datasets
            assert root + '/base' in datasets
            assert root + '/from-snapshot' in datasets
            run('/sbin/zfs', 'list', '-H', root + '/base@fixture')
            assert run('/sbin/zfs', 'get', '-Hp', '-o', 'value', 'guid',
                       pool + '/shared') == shared_guid
            assert (shared / 'persistent-sentinel').read_bytes() == b'persistent user data\n'
            for name, expected in [('base', 'source remains unchanged\n'),
                                   ('from-snapshot', 'candidate only\n')]:
                target = tmp / name
                run('bectl', '-r', root, 'mount', name, target)
                try:
                    assert (target / 'etc/clone-sentinel').read_text() == expected
                finally:
                    run('bectl', '-r', root, 'unmount', name)
            print('BE_VM_PASS: deletion persists after pool export/import; surviving identities, origin and shared data retained')
            check_clone_properties(root, 'normal')
            check_activation_failure(root, 'normal')
            # Reopen only the disposable pool with an alternate root. No
            # automatic mounts are permitted during this import.
            alternate = tmp / 'alternate-root'
            alternate.mkdir()
            run('/sbin/zpool', 'export', pool)
            run('/sbin/zpool', 'import', '-N', '-R', alternate, '-o',
                'cachefile=none', '-d', tmp, guid)
            assert run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'guid', pool) == guid
            check_clone_properties(root, 'alternate', str(alternate))
            check_activation_failure(root, 'alternate')

        finally:
            if created:
                # Never destroy a pool with an unexpected identity. A mismatch
                # deliberately retains artifacts for investigation.
                actual = run('/sbin/zpool', 'get', '-Hp', '-o', 'value', 'guid', pool)
                if guid is None or actual != guid:
                    raise RuntimeError('test pool identity changed; refusing cleanup')
                run('/sbin/zpool', 'destroy', pool)
            cleaned = True
    finally:
        if cleaned:
            shutil.rmtree(tmp)
        else:
            print('Retained test artifacts for diagnosis:', tmp, flush=True)


if __name__ == '__main__':
    main()
