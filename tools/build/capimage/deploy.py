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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--pkg-public-key', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--root', type=Path)
    target.add_argument('--bootenv')
    parser.add_argument('--kernel', default='GENERIC')
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
    root = new_root(args.root) if args.root else None
    print('repository=' + str(repository))
    print('target=' + (str(root) if root else 'new inactive boot environment ' + args.bootenv))
    if args.plan:
        print('verify signed pkg catalogue and archive downloads; select base, kernel and matching hardware')
        print('create destination; install using target chroot and isolated pkg database')
        print('verify all signed system bundles and cache with capsign/elfcache; unmount boot environment')
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
    mounted = False
    devmounted = False
    created = False
    try:
        if args.bootenv:
            root = scratch / 'root'
            # Existing names cause bectl to fail; never destroy or reuse one.
            command('bectl', 'create', '-r', args.bootenv)
            created = True
            command('bectl', 'mount', args.bootenv, root)
            mounted = True
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
        if mounted:
            command('bectl', 'unmount', args.bootenv)
    if not args.bootenv:
        root.chmod(0o755)
    print('DEPLOYMENT_VERIFIED target=' + (args.bootenv or str(root)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, PermissionError, OSError, subprocess.CalledProcessError) as error:
        print('build-bsd deploy: ' + str(error), file=sys.stderr)
        sys.exit(1)
