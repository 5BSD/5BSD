#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Opt-in real ZFS clone checks, only inside an explicitly disposable VM.

Uses one newly created file-backed pool. Never selects, activates, upgrades,
or destroys any host/system pool. This tests clone mechanics, not pkg upgrades.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import uuid


def run(*args):
    return subprocess.run(list(map(str, args)), check=True, text=True,
                          capture_output=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    parser.add_argument('--helper', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or run('sysctl', '-n', 'kern.vm_guest') in ('', 'none'):
        raise SystemExit('requires root inside an explicitly disposable VM')
    spec = importlib.util.spec_from_file_location('deploy', args.helper)
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    pool = 'build_bsd_test_' + uuid.uuid4().hex[:12]
    created = False
    guid = None
    tmp = Path(tempfile.mkdtemp(prefix='build-bsd-zfs-', dir='/var/tmp'))
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
            base = tmp / 'base'
            run('bectl', '-r', root, 'mount', 'base', base)
            for name in deploy.BE_PRIVATE_PATHS:
                (base / name).mkdir(parents=True, exist_ok=True)
            (base / 'etc/clone-sentinel').write_text('source remains unchanged\n')
            run('bectl', '-r', root, 'unmount', 'base')
            run('/sbin/zfs', 'snapshot', root + '/base@fixture')
            run('/sbin/zfs', 'set', 'readonly=on', root + '/base')
            for selector, name in [('base', 'from-be'), ('base@fixture', 'from-snapshot')]:
                source = deploy.be_source(selector, root)
                prefix = deploy.be_create(name, source)
                target = tmp / name
                run(*prefix, 'mount', name, target)
                try:
                    deploy.be_check_target(target, source, name)
                    assert (target / 'etc/clone-sentinel').read_text() == 'source remains unchanged\n'
                    (target / 'etc/clone-sentinel').write_text('candidate only\n')
                    assert deploy.zfs_properties(root + '/base')['readonly'] == 'on'
                finally:
                    run(*prefix, 'unmount', name)
            run('bectl', '-r', root, 'mount', 'base', base)
            try:
                assert (base / 'etc/clone-sentinel').read_text() == 'source remains unchanged\n'
            finally:
                run('bectl', '-r', root, 'unmount', 'base')
            print('BE_VM_PASS: BE and snapshot clones writable; source retained unchanged')
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
