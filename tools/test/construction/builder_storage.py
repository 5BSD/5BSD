#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Prepare a private disk-backed directory in an explicitly disposable builder VM.

The host must separately retain its private guest disk. This is trusted fixture
setup, not a runtime updater grant or generation authentication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ENVIRONMENT = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin', 'LC_ALL': 'C'}


def regular_program(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('explicit regular executable required: ' + str(path))
    return path.resolve(strict=True)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(*args):
    return subprocess.run(list(map(str, args)), env=ENVIRONMENT,
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=30, check=True).stdout


def validate_work(work):
    work = Path(work)
    if (not work.is_absolute() or '..' in work.parts or work == Path('/') or
            work.exists() or work.is_symlink()):
        raise ValueError('builder work must be a new absolute directory')
    parent = work.parent
    if parent.resolve(strict=True) != parent or not parent.is_dir():
        raise ValueError('builder work parent must be a canonical directory without symlinks')
    if parent.stat().st_dev != Path('/').stat().st_dev:
        raise ValueError('builder work must reside on the retained root disk, not tmpfs or another mount')
    return work


def prepare(work, mount, sysctl):
    if os.geteuid() != 0:
        raise PermissionError('builder storage preparation requires root inside a disposable VM')
    mount, sysctl = regular_program(mount), regular_program(sysctl)
    hashes = {str(p): digest(p) for p in (mount, sysctl)}
    guest = command(sysctl, '-n', 'kern.vm_guest').strip()
    if guest in ('', 'none'):
        raise ValueError('requires an explicitly disposable VM')
    work = validate_work(work)
    roots = [line.split() for line in command(mount, '-p').splitlines()
             if len(line.split()) == 6 and line.split()[1] == '/']
    if len(roots) != 1 or roots[0][2] != 'ufs':
        raise ValueError('requires the private UFS fixture root')
    if os.statvfs('/').f_flag & os.ST_RDONLY:
        command(mount, '-u', '-w', '/')
    if os.statvfs('/').f_flag & os.ST_RDONLY:
        raise ValueError('builder fixture root remains read-only')
    # Recheck boundaries after remount and immediately before creation.
    work = validate_work(work)
    for name, expected in hashes.items():
        if digest(Path(name)) != expected:
            raise ValueError('storage preparation tool changed: ' + name)
    work.mkdir(mode=0o700)
    work.chmod(0o700)
    info = work.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('private builder work ownership or mode differs')
    return {'format': 1, 'scope': 'disposable-builder-storage', 'result': 'PASS',
            'work': str(work), 'root_source': roots[0][0], 'filesystem': 'ufs',
            'files_sha256': hashes, 'generation_authenticated': False,
            'disk_retention_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--mount', type=Path, required=True)
    parser.add_argument('--sysctl', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.work, args.mount, args.sysctl), indent=2))


if __name__ == '__main__':
    main()
