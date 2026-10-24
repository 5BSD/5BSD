#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Prepare explicit blank VM output disk and run the ordinary install fixture."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def validate_devices(input_device, output_device, mounts):
    for value in (input_device, output_device):
        if not isinstance(value, str) or not re.fullmatch(r'/dev/vtbd[0-9]+', value):
            raise ValueError('explicit whole virtio disk device required')
    if input_device == output_device:
        raise ValueError('input and output devices must differ')
    for row in mounts:
        if any(row[0] == device or row[0].startswith(device + 'p') or
               row[0].startswith(device + 's') for device in (input_device, output_device)):
            raise ValueError('fixture device is already mounted, possibly as root')


def mountpoint_metadata(info):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) not in (0o700, 0o755)):
        raise ValueError('existing mountpoint must be a root-owned mode-0700/0755 directory')


def validate_mountpoint(path, mounts):
    path = Path(path)
    if (not path.is_absolute() or path == Path('/') or '..' in path.parts or
            path.is_symlink() or path.parent.resolve(strict=True) != path.parent):
        raise ValueError('mountpoint must be a canonical absolute directory')
    if any(Path(row[1]) == path for row in mounts):
        raise ValueError('configured mountpoint is already mounted')
    if path.exists():
        mountpoint_metadata(path.stat())
        if any(path.iterdir()):
            raise ValueError('existing mountpoint must be empty')
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or subprocess.check_output(
            ['/sbin/sysctl','-n','kern.vm_guest'],text=True).strip() in ('','none'):
        raise ValueError('requires root inside disposable VM')
    config = json.loads(args.config.read_text())
    required = {'input_device','output_device','input_mount','output_mount','python',
                'installer','backend','java','bash','nullfs_module','timeout'}
    if set(config) != required:
        raise ValueError('settings must specify exactly: ' + ', '.join(sorted(required)))
    if type(config['timeout']) is not int or not 1 <= config['timeout'] <= 86400:
        raise ValueError('bounded timeout required')
    mounts = [line.split() for line in subprocess.check_output(['/sbin/mount','-p'],text=True).splitlines()]
    validate_devices(config['input_device'], config['output_device'], mounts)
    for key in ('input_device','output_device'):
        path = Path(config[key])
        if path.is_symlink() or not stat.S_ISCHR(path.stat().st_mode):
            raise ValueError('fixture disk must be a character device')
    source, destination = Path(config['input_mount']), Path(config['output_mount'])
    needs_creation = {str(path): validate_mountpoint(path, mounts) for path in (source, destination)}
    if source.is_relative_to(destination) or destination.is_relative_to(source):
        raise ValueError('mountpoints overlap')
    with open(config['output_device'],'rb',buffering=0) as stream:
        header = stream.read(1024 * 1024)
    if len(header) != 1024 * 1024 or any(header):
        raise ValueError('output disk has existing metadata; require a new runner-created blank disk')
    # Check/load the actual matching module; failure is not a passing skip.
    if subprocess.run(['/sbin/kldstat','-q','-m','nullfs']).returncode:
        subprocess.run(['/sbin/kldload',config['nullfs_module']],check=True)
    subprocess.run(['/sbin/kldstat','-q','-m','nullfs'],check=True)
    created = []
    input_mounted = output_mounted = False
    result = {'scope':'disposable-offline-builder-disk-setup','result':'RUNNING','settings':config,
              'created_mountpoints':created,
              'reused_mountpoints':[name for name, new in needs_creation.items() if not new]}
    report = None
    try:
        for path in (source, destination):
            if needs_creation[str(path)]:
                path.mkdir(mode=0o700)
                created.append(str(path))
            validate_mountpoint(path, mounts)
        subprocess.run(['/sbin/mount','-t','ufs','-o','ro',config['input_device'],source],check=True)
        input_mounted = True
        subprocess.run(['/sbin/newfs','-U',config['output_device']],check=True)
        subprocess.run(['/sbin/mount','-t','ufs',config['output_device'],destination],check=True)
        output_mounted = True
        private = destination/'private'; private.mkdir(mode=0o700)
        target = private/'root'; target.mkdir(mode=0o700)
        report = destination/'report'; report.mkdir(mode=0o700)
        command = [config['python'],config['installer'],'--disposable-vm',
                   '--input',str(source),'--target',str(target),'--output',str(report),
                   '--inventory',str(source/'inventory.json'),'--layout',str(source/'root-layout.json'),
                   '--backend',config['backend'],'--java',config['java'],'--bash',config['bash'],
                   '--timeout',str(config['timeout'])]
        result['command'] = command
        completed = subprocess.run(command)
        result['exit_status'] = completed.returncode
        completed.check_returncode()
        receipt = json.loads((report/'result.json').read_text())
        if receipt.get('result') != 'PASS':
            raise ValueError('installation did not produce passing receipt')
        result['result'] = 'PASS'
    except Exception as error:
        result.update(result='FAIL',error=str(error))
        raise
    finally:
        if report is not None:
            (destination/'setup-result.json').write_text(json.dumps(dict(result, cleanup_complete=False),indent=2)+'\n')
        # Preserve disks. Unmount failures must fail the enclosing ATF case.
        cleanup_failed = False
        for mounted, point in ((output_mounted,destination),(input_mounted,source)):
            if mounted and subprocess.run(['/sbin/umount',point]).returncode:
                cleanup_failed = True
                continue
            # Preserve caller-provided directories, including those on a RO root.
            if str(point) in created:
                try:
                    point.rmdir()
                except OSError as error:
                    result.setdefault('mountpoint_cleanup_errors', []).append(str(error))
                    cleanup_failed = True
        result['cleanup_complete'] = not cleanup_failed
        if cleanup_failed:
            result['result'] = 'FAIL'
        print(json.dumps(result),flush=True)
        if cleanup_failed:
            raise RuntimeError('fixture disk cleanup failed')


if __name__ == '__main__':
    main()
