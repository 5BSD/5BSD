#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Explicit pkgbase deployment to a new root or inactive boot environment.

Never activates a boot environment or modifies the running root's pkg database.
Package scripts execute inside the target chroot, using the host kernel.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile


RUN_ROOT = Path('/usr/obj/usr/src/build-runs')


def command(*args, capture=False):
    print('+ ' + shlex.join(str(x) for x in args), flush=True)
    return subprocess.run([str(x) for x in args], check=True, text=True,
                          capture_output=capture)


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('expected regular file: ' + str(path))
    return path.resolve(strict=True)


def new_root(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('destination must be an absolute path without traversal')
    if path.exists() or path.is_symlink():
        raise ValueError('destination must not exist')
    parent = path.parent.resolve(strict=True)
    if parent == Path('/') or str(parent).startswith(('/dev/', '/proc/')):
        raise ValueError('use a dedicated destination parent')
    return parent / path.name


def select_packages(names, kernel):
    required = ['5BSD-set-base', '5BSD-kernel-' + kernel.lower().replace('_', '-')]
    missing = set(required) - set(names)
    if missing:
        raise ValueError('repository lacks required packages: ' + ', '.join(sorted(missing)))
    selected = required + sorted(n for n in names if n.startswith(('5BSD-hw-', '5BSD-hardware-abi-')))
    if 'pkg' in names:
        selected.append('pkg')
    return selected


def repository_definition(repository, public):
    return json.dumps({'bsd_build': {'url': repository.as_uri(), 'enabled': True,
        'signature_type': 'pubkey', 'pubkey': str(public), 'mirror_type': 'none'}}) + '\n'


def clean_result(result):
    # pkg may return zero while reporting failed signature verification.
    if result.stderr:
        raise ValueError('pkg verification diagnostic: ' + result.stderr.strip())
    return result.stdout


def load_hardware():
    spec = importlib.util.spec_from_file_location('hardware_packages', '/usr/src/release/scripts/hardware-packages.py')
    hw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hw)
    return hw


# A clone receives its own package database. Shared package/software mounts
# are not silently updated through an inactive root's empty mountpoints.
BE_PRIVATE_PATHS = ('etc', 'usr/local', 'var/db/pkg', 'Capabilities/System')


def be_name(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', value):
        raise ValueError('invalid boot environment name')
    return value


def mount_inventory():
    result = command('/sbin/mount', '-p', capture=True)
    if result.stderr:
        raise ValueError('cannot read mount inventory')
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 6:
            raise ValueError('malformed mount inventory')
        source, target, kind = fields[:3]
        target = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), target)
        rows.append((source, Path(target), kind, fields[3].split(',')))
    return rows


def zfs_properties(dataset):
    result = command('/sbin/zfs', 'get', '-Hp', '-o', 'property,value',
                     'guid,origin,readonly', dataset, capture=True)
    props = dict(line.split('\t', 1) for line in result.stdout.splitlines())
    if result.stderr or set(props) != {'guid', 'origin', 'readonly'} or not props['guid'].isdigit():
        raise ValueError('invalid ZFS identity response')
    return props


def be_source(clone_from=None, be_root=None):
    mounts = mount_inventory()
    active = [row for row in mounts if row[1] == Path('/')]
    if be_root is None:
        if len(active) != 1 or active[0][2] != 'zfs':
            raise ValueError('boot-environment deployment requires a ZFS root')
        be_root, active_name = active[0][0].rsplit('/', 1)
        clone_from = clone_from or active_name
    elif not clone_from:
        raise ValueError('--be-root requires an explicit --clone-from')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:-]*', be_root) or any(x in ('', '.', '..') for x in be_root.split('/')):
        raise ValueError('invalid boot-environment root dataset')
    if clone_from.startswith(be_root + '/'):
        clone_from = clone_from[len(be_root)+1:]
    parts = clone_from.split('@')
    if len(parts) > 2:
        raise ValueError('invalid source snapshot')
    be_name(parts[0])
    if len(parts) == 2 and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', parts[1]):
        raise ValueError('invalid source snapshot')
    source = be_root + '/' + parts[0]
    props = zfs_properties(source)
    # Reject known shared software/database paths. Home/data mounts may remain
    # shared: this operation does not write or migrate them.
    for row in mounts:
        if row[1] == Path('/'):
            continue
        for relative in BE_PRIVATE_PATHS:
            critical = Path('/') / relative
            if row[1] == critical or row[1] in critical.parents or critical in row[1].parents:
                raise ValueError('shared or separately mounted deployment state requires explicit migration: ' + str(row[1]))
    return {'root': be_root, 'selector': clone_from, 'source': source, 'guid': props['guid']}


def be_create(name, source):
    prefix = ['bectl', '-r', source['root']]
    command(*prefix, 'create', '-r', '-e', source['selector'], name)
    target = source['root'] + '/' + name
    props = zfs_properties(target)
    if props['guid'] == source['guid'] or not props['origin'].startswith(source['source'] + '@'):
        raise ValueError('new boot environment does not have an independent clone identity')
    if '@' in source['selector'] and props['origin'] != source['root'] + '/' + source['selector']:
        raise ValueError('new boot environment has the wrong snapshot origin')
    command('/sbin/zfs', 'set', 'readonly=off', target)
    return prefix


def be_check_target(root, source, name):
    rows = mount_inventory()
    matching = [row for row in rows if row[1] == root]
    target = source['root'] + '/' + name
    if len(matching) != 1 or matching[0][0] != target or matching[0][2] != 'zfs' or 'rw' not in matching[0][3]:
        raise ValueError('candidate is not the expected writable ZFS clone')
    root_dev = root.stat().st_dev
    for relative in BE_PRIVATE_PATHS:
        current = root
        for part in Path(relative).parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_dev != root_dev:
                raise ValueError('candidate package/software state is not private to the clone: ' + str(current))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--pkg-public-key', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--root', type=Path)
    target.add_argument('--bootenv')
    parser.add_argument('--kernel', default='GENERIC')
    parser.add_argument('--clone-from', help='source BE or BE@snapshot; defaults to active BE')
    parser.add_argument('--be-root', help='explicit ZFS boot-environment parent dataset')
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--capsign', default='/usr/sbin/capsign')
    parser.add_argument('--elfcache', default='/usr/sbin/elfcache')
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    if not repository.is_dir() or not (repository / 'publication.json').is_file():
        raise ValueError('repository is not a completed combined publication')
    if any(p.is_symlink() for p in repository.rglob('*')):
        raise ValueError('published generation must not contain symlinks')
    pub = regular(args.pkg_public_key)
    codepub = regular(args.public_key)
    regular(args.capsign)
    regular(args.elfcache)
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.kernel):
        raise ValueError('invalid kernel configuration name')
    if args.bootenv and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', args.bootenv):
        raise ValueError('invalid boot environment name')
    if (args.clone_from or args.be_root) and not args.bootenv:
        raise ValueError('--clone-from/--be-root require --bootenv')
    if args.clone_from and any(ord(c) < 32 for c in args.clone_from):
        raise ValueError('invalid source snapshot')
    root = new_root(args.root) if args.root else None
    print('repository=' + str(repository))
    print('target=' + (str(root) if root else 'new inactive boot environment ' + args.bootenv))
    if args.plan:
        print('verify signed pkg catalogue and archive downloads; select base, kernel and matching hardware')
        print('create destination; install using target chroot and isolated pkg database')
        print('verify all signed system bundles and cache with capsign/elfcache; unmount boot environment')
        if args.bootenv:
            print('clone source=' + (args.clone_from or 'current boot environment'))
        print('no boot environment activation or reboot')
        return
    if os.geteuid() != 0:
        raise PermissionError('deployment requires a root shell for chroot, ownership and boot-environment mounts')
    # Verification and downloads happen before any boot environment creation.
    hw = load_hardware()
    info = hw.verify(repository)
    pkg = regular('/usr/local/sbin/pkg-static')
    abi = info['abi']
    host_abi = command(pkg, 'config', 'ABI', capture=True).stdout.strip()
    if abi.split(':')[-1] != host_abi.split(':')[-1]:
        raise ValueError('deployment requires a target-native host; use installer media for a foreign architecture')
    osversion = info.get('osversion')
    if not str(osversion).isdigit():
        raise ValueError('repository lacks target OS version')
    # Retain the work directory, including on failed unmount. An automatic
    # recursive temporary-directory cleanup must never walk a mounted BE.
    scratch = Path(tempfile.mkdtemp(prefix='deploy-', dir=RUN_ROOT))
    repos = scratch / 'repos'
    repos.mkdir()
    (repos / 'build.conf').write_text(repository_definition(repository, pub))
    for name in ('db', 'cache'):
        (scratch / name).mkdir()
    pkgcmd = [pkg, '-C', '/dev/null', '-R', repos, '-o', 'ABI=' + abi,
              '-o', 'OSVERSION=' + str(osversion), '-o', 'ENABLE_PLUGINS=no',
              '-o', 'REPO_AUTOUPDATE=no', '-o', 'PKG_DBDIR=' + str(scratch / 'db'),
              '-o', 'PKG_CACHEDIR=' + str(scratch / 'cache')]
    clean_result(command(*pkgcmd, 'update', '-f', '-r', 'bsd_build', capture=True))
    names = clean_result(command(*pkgcmd, 'rquery', '-U', '-r', 'bsd_build', '%n', capture=True)).splitlines()
    selected = select_packages(names, args.kernel)
    fetched = scratch / 'fetched'
    command(*pkgcmd, 'fetch', '-y', '-d', '-o', fetched, '-r', 'bsd_build', *selected)
    archives = sorted((fetched / 'All').glob('*.pkg'))
    if not archives or any(p.is_symlink() or not p.is_file() for p in archives):
        raise ValueError('invalid fetched package archive set')
    install_names = sorted(hw.manifest(archive)['name'] for archive in archives)
    if len(install_names) != len(set(install_names)):
        raise ValueError('duplicate fetched package identity')
    source = be_source(args.clone_from, args.be_root) if args.bootenv else None
    be_prefix = ['bectl', '-r', source['root']] if source else None
    mounted = False
    mount_attempted = False
    devmounted = False
    created = False
    try:
        if args.bootenv:
            root = scratch / 'root'
            # Existing names cause bectl to fail; never destroy or reuse one.
            # Record creation intent so a failure retains a useful diagnostic.
            # bectl refuses an existing target; no destroy or activation occurs.
            created = True
            be_prefix = be_create(args.bootenv, source)
            mount_attempted = True
            command(*be_prefix, 'mount', args.bootenv, root)
            mounted = True
            be_check_target(root, source, args.bootenv)
        else:
            root.mkdir(mode=0o700)
            created = True
            # Bootstrap only from pkg-verified archives. No target code or
            # package scripts run during extraction. pkg then reinstalls
            # and registers these files inside the complete target chroot.
            for archive in archives:
                command('tar', '-xpf', archive, '-C', root, '--exclude', '+*')
        for directory in ('dev', 'var', 'var/db', 'var/db/pkg', 'bin', 'etc'):
            path = root / directory
            if path.is_symlink() or (path.exists() and not path.is_dir()):
                raise ValueError('unsafe target directory: ' + directory)
            path.mkdir(exist_ok=True)
        command('mount', '-t', 'devfs', 'devfs', root / 'dev')
        devmounted = True
        # Inputs reside directly below the private root, outside shared
        # /var or /tmp datasets. No private signing key is copied.
        inputs = Path(tempfile.mkdtemp(prefix='.bsd-build-', dir=root))
        inside = Path('/') / inputs.name
        shutil.copy2(pkg, inputs / 'pkg-static')
        shutil.copy2(pub, inputs / 'repository.pub')
        (inputs / 'repos').mkdir()
        shutil.copytree(repository, inputs / 'repository', symlinks=False)
        (inputs / 'repos/build.conf').write_text(repository_definition(inside / 'repository', inside / 'repository.pub'))
        targetpkg = ['chroot', root, inside / 'pkg-static', '-C', '/dev/null',
                     '-R', inside / 'repos', '-o', 'ABI=' + abi,
                     '-o', 'OSVERSION=' + str(osversion), '-o', 'ENABLE_PLUGINS=no',
                     '-o', 'REPO_AUTOUPDATE=no', '-o', 'PKG_DBDIR=/var/db/pkg',
                     '-o', 'PKG_CACHEDIR=' + str(inside / 'cache')]
        clean_result(command(*targetpkg, 'update', '-f', '-r', 'bsd_build', capture=True))
        # Re-query the imported catalogue rather than trusting update's status.
        installed_names = clean_result(command(*targetpkg, 'rquery', '-U', '-r', 'bsd_build', '%n', capture=True)).splitlines()
        if sorted(installed_names) != sorted(names):
            raise ValueError('repository catalogue changed during deployment')
        command(*targetpkg, 'install', '-U', '-f', '-y', '-r', 'bsd_build', *install_names)
        command(*targetpkg, 'check', '-s', '-a')
        environment = dict(os.environ, CAPSIGN=args.capsign, ELFCACHE=args.elfcache)
        subprocess.run(['sh', '/usr/src/tools/build/capimage/verify-stage.sh',
                        '-r', str(root), '-p', str(codepub)], env=environment, check=True)
        shutil.rmtree(inputs)
    except BaseException:
        if created:
            print('Deployment incomplete; retained destination for diagnosis: ' + (args.bootenv or str(root)), file=sys.stderr)
        raise
    finally:
        if devmounted:
            command('umount', root / 'dev')
        if mount_attempted:
            command(*be_prefix, 'unmount', args.bootenv)
    if not args.bootenv:
        root.chmod(0o755)
    print('DEPLOYMENT_VERIFIED target=' + (args.bootenv or str(root)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, PermissionError, OSError, subprocess.CalledProcessError) as error:
        print('build-bsd deploy: ' + str(error), file=sys.stderr)
        sys.exit(1)
