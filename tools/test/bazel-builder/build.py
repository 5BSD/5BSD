#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build a selected port in an initialized disposable builder, on separate disks."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import setup


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(value):
    if (not isinstance(value, str) or not value or value.startswith('/') or
            any(ord(c) < 32 for c in value) or
            any(part in ('', '.', '..') for part in value.split('/'))):
        raise ValueError('canonical relative input path required')
    return value


def inside(root, value):
    path = root / relative(value)
    if path.resolve(strict=True) != path or not path.is_relative_to(root):
        raise ValueError('input path traverses a symlink')
    return path


def validate_devices(config, mounts):
    devices = [config[k] for k in ('input_device', 'root_device', 'workspace_device')]
    if len(set(devices)) != 3:
        raise ValueError('input, initialized root and blank workspace must be distinct')
    for device in devices:
        setup.validate_devices(device, next(d for d in devices if d != device), mounts)


def validate_archive(path):
    """Validate the complete member graph before any extraction occurs."""
    entries = {}
    with tarfile.open(path, 'r:*') as archive:
        for member in archive:
            name = relative(member.name.removesuffix('/'))
            if name in entries:
                raise ValueError('duplicate ports snapshot path: ' + name)
            if member.isfile(): kind = 'file'
            elif member.isdir(): kind = 'directory'
            elif member.issym(): kind = 'symlink'
            elif member.islnk(): kind = 'hardlink'
            else: raise ValueError('unsupported ports snapshot member: ' + name)
            entries[name] = (kind, member.linkname)
    for name, (kind, target) in entries.items():
        for parent in PurePosixPath(name).parents:
            entry = entries.get(str(parent))
            if entry and entry[0] != 'directory':
                raise ValueError('nondirectory ports snapshot ancestor: ' + str(parent))
        if kind == 'symlink':
            if not target or target.startswith('/'):
                raise ValueError('absolute or empty ports snapshot link')
            parts = list(PurePosixPath(name).parent.parts)
            for part in PurePosixPath(target).parts:
                if part == '..':
                    if not parts: raise ValueError('ports snapshot link escapes workspace')
                    parts.pop()
                elif part != '.': parts.append(part)
                entry = entries.get('/'.join(parts))
                if entry and entry[0] in ('symlink', 'hardlink'):
                    raise ValueError('ports snapshot symlink target traverses another link')
        if kind == 'hardlink':
            seen = {name}
            while True:
                target = relative(target)
                if target in seen: raise ValueError('cyclic ports snapshot hardlink')
                seen.add(target)
                entry = entries.get(target)
                if entry is None or entry[0] not in ('file', 'hardlink'):
                    raise ValueError('ports snapshot hardlink must target an archived regular file')
                # The global ancestor check also validates each target member.
                if entry[0] == 'file': break
                target = entry[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    required = {'input_device', 'root_device', 'workspace_device', 'input_mount', 'root_mount',
                'root_relative', 'installation_receipt', 'installation_receipt_sha256',
                'sources_manifest', 'sources_manifest_sha256', 'nullfs_module',
                'python', 'resources', 'budget', 'javac_options', 'bootstrap_args', 'package_tool'}
    if set(config) != required:
        raise ValueError('explicit complete initialized-builder config required')
    if os.geteuid() != 0 or subprocess.check_output(
            ['/sbin/sysctl', '-n', 'kern.vm_guest'], text=True).strip() in ('', 'none'):
        raise ValueError('requires root inside disposable VM')
    mounts = [line.split() for line in subprocess.check_output(['/sbin/mount', '-p'], text=True).splitlines()]
    validate_devices(config, mounts)
    for key in ('input_device', 'root_device', 'workspace_device'):
        p = Path(config[key])
        if p.is_symlink() or not stat.S_ISCHR(p.stat().st_mode):
            raise ValueError('explicit whole virtio character device required')
    source, destination = Path(config['input_mount']), Path(config['root_mount'])
    if source.is_relative_to(destination) or destination.is_relative_to(source):
        raise ValueError('input and initialized root mountpoints overlap')
    # Reuse only precreated safe mountpoints, including on the read-only boot root.
    for path in (source, destination):
        if setup.validate_mountpoint(path, mounts):
            raise ValueError('precreated root-owned mountpoint required: ' + str(path))
    with open(config['workspace_device'], 'rb', buffering=0) as stream:
        header = stream.read(1024 * 1024)
    if len(header) != 1024 * 1024 or any(header):
        raise ValueError('workspace must be a new runner-created blank disk')
    if subprocess.run(['/sbin/kldstat', '-q', '-m', 'nullfs']).returncode:
        subprocess.run(['/sbin/kldload', config['nullfs_module']], check=True)
    mounted = []
    result = {'scope': 'initialized-disposable-ports-build', 'result': 'FAIL', 'config': config}
    evidence = None
    def run(argv, timeout=3600):
        subprocess.run(argv, check=True, timeout=timeout)
    def mount(argv, point):
        run(argv); mounted.append(point)
    try:
        mount(['/sbin/mount', '-t', 'ufs', '-o', 'ro', config['input_device'], source], source)
        mount(['/sbin/mount', '-t', 'ufs', config['root_device'], destination], destination)
        receipt_path = inside(destination, config['installation_receipt'])
        if sha256(receipt_path) != config['installation_receipt_sha256']:
            raise ValueError('initialized installation receipt hash differs')
        receipt = json.loads(receipt_path.read_text())
        if receipt.get('scope') != 'ordinary-offline-builder-installation' or receipt.get('result') != 'PASS':
            raise ValueError('initialized root lacks successful ordinary installation')
        root = inside(destination, config['root_relative'])
        if not root.is_dir() or root.stat().st_uid != 0:
            raise ValueError('initialized root must be a root-owned directory')
        source_manifest = inside(source, config['sources_manifest'])
        if sha256(source_manifest) != config['sources_manifest_sha256']:
            raise ValueError('build source manifest hash differs')
        inputs = json.loads(source_manifest.read_text())
        if (set(inputs) != {'format', 'ports_archive', 'ports_directory', 'distfiles', 'origin', 'package'} or
                type(inputs['format']) is not int or inputs['format'] != 1 or not isinstance(inputs['distfiles'], list) or not inputs['distfiles'] or
                not re.fullmatch(r'[A-Za-z0-9_+.-]+/[A-Za-z0-9_+.-]+', inputs['origin'])):
            raise ValueError('invalid explicit build source manifest')
        for entry in [inputs['ports_archive'], *inputs['distfiles']]:
            if set(entry) != {'file', 'sha256'} or not re.fullmatch('[0-9a-f]{64}', entry['sha256']):
                raise ValueError('invalid source binding')
            if sha256(inside(source, entry['file'])) != entry['sha256']:
                raise ValueError('build source hash differs: ' + entry['file'])
        workspace = root / 'usr/obj'
        if not workspace.exists():
            workspace.mkdir(mode=0o755)
        setup.validate_mountpoint(workspace, mounts)
        # Never format the initialized root; only the distinct checked blank disk.
        run(['/sbin/newfs', '-U', config['workspace_device']])
        mount(['/sbin/mount', '-t', 'ufs', config['workspace_device'], workspace], workspace)
        evidence = workspace / 'build-result.json'
        archive = inside(source, inputs['ports_archive']['file'])
        validate_archive(archive)
        run(['/usr/bin/tar', '-xpf', archive, '-C', workspace])
        ports = inside(workspace, inputs['ports_directory'])
        if not (ports / 'Mk/bsd.port.mk').is_file():
            raise ValueError('full maintained ports framework missing')
        inputs_guest = root / 'inputs'
        if not inputs_guest.exists(): inputs_guest.mkdir(mode=0o755)
        setup.validate_mountpoint(inputs_guest, mounts)
        mount(['/sbin/mount', '-t', 'nullfs', '-o', 'ro', source, inputs_guest], inputs_guest)
        dev = root / 'dev'
        setup.validate_mountpoint(dev, mounts)
        mount(['/sbin/mount', '-t', 'devfs', 'devfs', dev], dev)
        run(['/sbin/devfs', '-m', dev, 'rule', 'apply', 'hide'])
        for name in ('null', 'zero', 'random', 'urandom'):
            run(['/sbin/devfs', '-m', dev, 'rule', 'apply', 'path', name, 'unhide'])
        if list(dev.glob('vtbd*')):
            raise ValueError('build chroot must not expose fixture disks')
        cpus = int(subprocess.check_output(['/sbin/sysctl', '-n', 'hw.ncpu'], text=True))
        if cpus < 1: raise ValueError('invalid guest CPU count')
        ports_guest = '/usr/obj/' + relative(inputs['ports_directory'])
        distdirs = {str(PurePosixPath(relative(d['file'])).parent) for d in inputs['distfiles']}
        if len(distdirs) != 1: raise ValueError('distfiles require one explicit input directory')
        command = ['/usr/sbin/chroot', str(root), '/usr/bin/env', '-i',
                   'PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
                   'HOME=/root', 'LC_ALL=C', 'DIST_BOOTSTRAP_ARGS=' + config['bootstrap_args'],
                   '/usr/bin/make', '-C', ports_guest + '/' + inputs['origin'],
                   'BATCH=yes', '__MAKE_CONF=/dev/null', 'PORTSDIR=' + ports_guest,
                   'DISTDIR=/inputs/' + next(iter(distdirs)), 'WRKDIRPREFIX=/usr/obj/ports-work',
                   'PACKAGES=/usr/obj/packages', 'PORT_DBDIR=/usr/obj/ports-options',
                   'USE_PACKAGE_DEPENDS_ONLY=yes', 'MAKE_JOBS_NUMBER=' + str(cpus),
                   'BAZEL_JAVAC_OPTS=' + config['javac_options']]
        actual = subprocess.check_output(command + ['-V', 'PKGNAME'], text=True, timeout=60).strip()
        if actual != inputs['package']: raise ValueError('selected port package identity differs')
        (workspace / 'packages/All').mkdir(parents=True)
        result.update(command=command + ['package'], guest_cpus=cpus, expected_package=actual)
        run([config['python'], config['resources'], '--disposable-vm', '--budget', config['budget'],
             '--output', str(workspace / 'resources'), '--filesystem', str(destination),
             '--filesystem', str(workspace), '--device', Path(config['root_device']).name,
             '--device', Path(config['workspace_device']).name, '--', *command, 'package'], timeout=86500)
        packages = list((workspace / 'packages/All').glob(actual + '.pkg'))
        if len(packages) != 1: raise ValueError('build did not produce exact selected package')
        identity = subprocess.check_output(['/usr/sbin/chroot', str(root), '/usr/bin/env', '-i',
            'PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
            config['package_tool'], 'query', '-F', '/usr/obj/packages/All/' + packages[0].name,
            '%n-%v'], text=True, timeout=60).strip()
        if identity != actual: raise ValueError('built archive package identity differs')
        result.update(result='PASS', package_sha256=sha256(packages[0]), package=str(packages[0]),
                      runtime_qualified=False, production_backend='bsd-make')
    except Exception as error:
        result['error'] = str(error)
        raise
    finally:
        failures = []
        if evidence is not None:
            try:
                evidence.write_text(json.dumps(dict(result, cleanup_complete=False), indent=2) + '\n')
            except OSError as error:
                failures.append('evidence write: ' + str(error))
        for point in reversed(mounted):
            if subprocess.run(['/sbin/umount', point]).returncode:
                failures.append(str(point))
        result['cleanup_complete'] = not failures
        if failures: result.update(result='FAIL', unmount_failures=failures)
        print(json.dumps(result), flush=True)
        if failures: raise RuntimeError('initialized build cleanup failed')


if __name__ == '__main__':
    main()
