#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Verify a pkgbase snapshot, then explicitly launch the interactive installer."""
import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

RUN_ROOT = Path('/usr/obj/usr/src/build-runs')
INSTALLER = Path('/usr/sbin/bsdinstall')
INSTALLER_SCRIPTS = Path('/usr/libexec/bsdinstall')
PKG = Path('/usr/local/sbin/pkg-static')


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('expected regular file: ' + str(path))
    return path.resolve(strict=True)


def load_hardware():
    spec = importlib.util.spec_from_file_location('hardware_packages',
        '/usr/src/release/scripts/hardware-packages.py')
    hw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hw)
    return hw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--pkg-public-key', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--capsign', type=Path, required=True)
    parser.add_argument('--elfcache', type=Path, required=True)
    parser.add_argument('--kernel', default='GENERIC')
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.kernel):
        raise ValueError("invalid kernel configuration name")
    repository = args.repository.resolve(strict=True)
    if not repository.is_dir():
        raise ValueError('installer requires a completed publication directory')
    regular(repository / 'publication.json')
    pub = regular(args.pkg_public_key)
    codepub = regular(args.public_key)
    capsign = regular(args.capsign)
    elfcache = regular(args.elfcache)
    if args.plan:
        print('verify and snapshot complete signed repository: ' + str(repository))
        print('launch interactive bsdinstall with explicit repository and code-signing trust')
        print('installer selects target disks; no automatic reboot')
        return
    if os.geteuid() != 0:
        raise PermissionError('installer launch requires a root shell for disk setup and installation')
    if not sys.stdin.isatty():
        raise ValueError('interactive installer requires a terminal')
    regular(INSTALLER)
    for name in ('repository.subr', 'verify-image', 'pkgbase'):
        regular(INSTALLER_SCRIPTS / name)
    # A mixed old/new installer must not silently ignore explicit trust.
    auto = regular(INSTALLER_SCRIPTS / 'auto').read_text()
    if 'BSDINSTALL_CODE_PUBLIC_KEY' not in auto or 'bsdinstall_repository' not in auto:
        raise ValueError('installed bsdinstall lacks explicit repository/signature support')
    if 'BSDINSTALL_KERNEL' not in (INSTALLER_SCRIPTS / 'pkgbase').read_text():
        raise ValueError('installed bsdinstall lacks explicit kernel selection')
    subprocess.run([str(capsign), 'key-id', '-p', str(codepub)], check=True,
                   text=True, capture_output=True)
    hw = load_hardware()
    info = hw.verify(repository)
    host_abi = subprocess.run([str(PKG), 'config', 'ABI'], check=True,
                             text=True, capture_output=True).stdout.strip()
    if info['abi'].split(':')[-1] != host_abi.split(':')[-1]:
        raise ValueError('installer launch requires the native architecture; build media for other targets')
    if not str(info.get('osversion')).isdigit():
        raise ValueError('repository lacks target OS version')
    scratch = Path(tempfile.mkdtemp(prefix='installer-', dir=RUN_ROOT))
    print('Installer preparation and recovery files: ' + str(scratch), flush=True)
    status = scratch / 'status'
    status.write_text('verifying repository\n')
    try:
        keys = scratch / 'keys'
        keys.mkdir()
        shutil.copyfile(pub, keys / 'repository.pub')
        shutil.copyfile(codepub, keys / 'code.pub')
        snapshot = hw.copy_signed_repository(repository, scratch / 'repository',
            keys / 'repository.pub', str(PKG), info['abi'], info['osversion'])
        hw.verify(snapshot)
        names = set(hw.inventory(snapshot))
        required = {'pkg', '5BSD-set-base',
                    '5BSD-kernel-' + args.kernel.lower().replace('_', '-')}
        if not required <= names:
            raise ValueError('installer repository lacks: ' + ', '.join(sorted(required - names)))
        repos = scratch / 'repos'
        repos.mkdir()
        (repos / '5BSD-base.conf').write_text(json.dumps({'5BSD-base': {
            'url': snapshot.as_uri(), 'enabled': True, 'mirror_type': 'none',
            'signature_type': 'pubkey', 'pubkey': str(keys / 'repository.pub')}}) + '\n')
        for name in ('tmp', 'etc', 'boot'):
            (scratch / name).mkdir()
        # Do not inherit unattended-install hooks, alternate repositories or
        # skip flags from a prior installer session.
        environment = {name: os.environ[name] for name in ('TERM', 'LANG', 'LC_ALL')
                       if name in os.environ}
        environment.update({
            'PATH': '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            'TMPDIR': str(scratch / 'tmp'), 'BSDINSTALL_TMPETC': str(scratch / 'etc'),
            'BSDINSTALL_TMPBOOT': str(scratch / 'boot'),
            'BSDINSTALL_PKG_REPOS_DIR': str(repos),
            'BSDINSTALL_CODE_PUBLIC_KEY': str(keys / 'code.pub'),
            'BSDINSTALL_KERNEL': args.kernel,
            'CAPSIGN': str(capsign), 'ELFCACHE': str(elfcache),
            'BSDINSTALL_LOG': str(scratch / 'bsdinstall.log')})
        status.write_text('running interactive installer\n')
        subprocess.run([str(INSTALLER), 'auto'], check=True, env=environment)
        status.write_text('installer completed\n')
    except BaseException:
        status.write_text('failed; preparation and recovery files retained\n')
        raise


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
