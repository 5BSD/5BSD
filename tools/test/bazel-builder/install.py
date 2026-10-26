#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Offline full-package installation fixture, only inside a disposable VM."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path.resolve(strict=True) != path:
        raise ValueError('requires an existing canonical absolute path without symlinks')
    return path


def boundaries(source, target, output):
    source, target, output = map(canonical, (source, target, output))
    if any(path == Path('/') for path in (source, target, output)):
        raise ValueError('root filesystem is not a fixture directory')
    for left, right in ((source, target), (source, output), (target, output)):
        if left.is_relative_to(right) or right.is_relative_to(left):
            raise ValueError('input, target and report paths must be disjoint')
    if any(target.iterdir()) or any(output.iterdir()):
        raise ValueError('target and report directories must be empty')
    return source, target, output


def package_rows(record):
    if record.get('format') != 1 or record.get('scope') != 'offline-builder-package-transport':
        raise ValueError('unsupported package transport')
    rows = record.get('packages')
    if not isinstance(rows, list) or not rows:
        raise ValueError('empty package selection')
    names, files = set(), set()
    for row in rows:
        name = row.get('name'); relative = row.get('file'); sha = row.get('sha256')
        if not isinstance(name, str) or not name or name in names:
            raise ValueError('invalid or duplicate package name')
        if not isinstance(row.get('version'), str) or not row['version']:
            raise ValueError('missing package version')
        if (not isinstance(relative, str) or PurePosixPath(relative).is_absolute() or
                len(PurePosixPath(relative).parts) != 2 or
                PurePosixPath(relative).parts[0] != 'archives' or
                not re.fullmatch(r'archives/[A-Za-z0-9_.+-]+\.pkg', relative) or
                relative in files):
            raise ValueError('unsafe or duplicate archive path')
        if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
            raise ValueError('invalid archive hash')
        names.add(name); files.add(relative)
    return rows


def mounted_filesystem(path, mounts):
    matches = [row for row in mounts if path.is_relative_to(row[1])]
    if not matches:
        raise ValueError('path has no mount record')
    return max(matches, key=lambda row: len(Path(row[1]).parts))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    for name in ('input', 'target', 'output', 'inventory', 'layout', 'backend'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--java', required=True, help='absolute installed Java program, from selected package layout')
    parser.add_argument('--bash', required=True, help='absolute installed Bash program')
    parser.add_argument('--timeout', type=int, default=3600)
    args = parser.parse_args()
    if os.geteuid() != 0 or not 1 <= args.timeout <= 86400:
        parser.error('requires root in disposable VM and bounded timeout')
    guest = subprocess.check_output(['/sbin/sysctl', '-n', 'kern.vm_guest'], text=True).strip()
    if guest in ('', 'none'):
        parser.error('not running in a VM')
    source, target, output = boundaries(args.input, args.target, args.output)
    mounts = [line.split() for line in subprocess.check_output(['/sbin/mount', '-p'], text=True).splitlines()]
    srcmount, dstmount = mounted_filesystem(source, mounts), mounted_filesystem(target, mounts)
    if srcmount[1] != str(source) or 'ro' not in srcmount[3].split(','):
        raise ValueError('input must be an explicit read-only mountpoint')
    if dstmount[2] != 'ufs' or not dstmount[0].startswith('/dev/vtbd') or 'rw' not in dstmount[3].split(','):
        raise ValueError('target must reside on writable disk-backed virtio UFS')
    if os.stat(target).st_dev == os.stat('/').st_dev:
        raise ValueError('target must be on a separate disk from the fixture root')
    if mounted_filesystem(output, mounts)[2] == 'tmpfs':
        raise ValueError('report must remain on retained disk')
    manifest_path = canonical(source / 'transport.json')
    record = json.loads(manifest_path.read_text()); rows = package_rows(record)
    inventory_path, layout_path = canonical(args.inventory), canonical(args.layout)
    if digest(layout_path) != record['layout_sha256']:
        raise ValueError('layout does not match transport binding')
    if digest(inventory_path) != record['inventory_sha256']:
        raise ValueError('inventory does not match transport binding')
    inventory = json.loads(inventory_path.read_text()); initial = json.loads(layout_path.read_text())
    byname = {p['name']: p for p in inventory['packages']}
    if len(byname) != len(inventory['packages']) or set(byname) != {r['name'] for r in rows}:
        raise ValueError('transport and inventory package sets differ')
    hashes = {str(Path(__file__).resolve()): digest(Path(__file__)), str(manifest_path): digest(manifest_path), str(inventory_path): digest(inventory_path),
              str(layout_path): digest(layout_path), str(source / 'pkg-static'): record['pkg_static_sha256']}
    inventory = copy.deepcopy(inventory)
    byname = {p['name']: p for p in inventory['packages']}
    for row in rows:
        archive = canonical(source / row['file'])
        if not archive.is_relative_to(source) or not archive.is_file():
            raise ValueError('archive escapes input mount')
        package = byname[row['name']]
        if package['version'] != row['version'] or package['archive_sha256'] != row['sha256']:
            raise ValueError('archive identity/hash differs from inventory')
        package['archive'] = str(archive); hashes[str(archive)] = row['sha256']
    for program in (args.java, args.bash):
        if not program.startswith('/') or '..' in PurePosixPath(program).parts:
            raise ValueError('installed programs must have absolute package-owned paths')
        if not any(program in package['entries'] for package in inventory['packages']):
            raise ValueError('program is absent from selected package payloads')
    backend = canonical(args.backend)
    for path in backend.glob('*.py'):
        hashes[str(path)] = digest(path)
    spec = importlib.util.spec_from_file_location('payload_extract', backend / 'payload_extract.py')
    extractor = importlib.util.module_from_spec(spec); spec.loader.exec_module(extractor)
    report = dict(scope='ordinary-offline-builder-installation', result='RUNNING',
                  package_count=len(rows), hashes=hashes, commands=[], runtime_build_qualified=False,
                  inputs_authenticated=False, input_mount=srcmount, target_mount=dstmount)
    mounted = False
    devfs_mounted = False
    control = target / '.bazel-builder-control'
    input_mount = target / '.bazel-builder-input'

    def unchanged():
        for path, expected in hashes.items():
            if digest(path) != expected:
                raise ValueError('input changed: ' + path)

    def run(command, timeout=None, read_stdout=True):
        number = len(report['commands'])
        stdout, stderr = output / f'{number:03d}.stdout', output / f'{number:03d}.stderr'
        entry = dict(argv=list(map(str, command)), stdout=str(stdout), stderr=str(stderr))
        report['commands'].append(entry)
        with stdout.open('wb') as out, stderr.open('wb') as err:
            process = subprocess.Popen(entry['argv'], stdout=out, stderr=err,
                stdin=subprocess.DEVNULL, env={'PATH':'/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin',
                'HOME':'/root','LC_ALL':'C'}, start_new_session=True)
            try:
                status = process.wait(timeout=timeout or args.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                entry.update(timed_out=True, exit_status=process.returncode)
                raise
        entry['exit_status'] = status
        if status:
            raise RuntimeError('command failed; see ' + str(stderr))
        if read_stdout and stdout.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('unexpectedly large command output; retained on disk')
        return stdout.read_text() if read_stdout else ''

    try:
        unchanged()
        if 'statically linked' not in run(['/usr/bin/file', source / 'pkg-static'], 30):
            raise ValueError('explicit static package engine required')
        # Complete selected payload seed supplies shell/interpreter prerequisites.
        # The subsequent operation is a real install with scripts, not registration.
        report['extraction'] = extractor.extract(target, inventory, initial, '/usr/bin/tar', args.timeout)
        if control.exists() or input_mount.exists():
            raise ValueError('fixture paths conflict with selected payload')
        control.mkdir(mode=0o700); (control / 'repos').mkdir(); (control / 'empty.conf').write_text('')
        input_mount.mkdir(mode=0o700)
        run(['/sbin/mount', '-t', 'nullfs', '-o', 'ro', source, input_mount], 30); mounted = True
        if not (target / 'dev').is_dir() or (target / 'dev').is_symlink():
            raise ValueError('package-derived dev directory required')
        run(['/sbin/mount', '-t', 'devfs', 'devfs', target / 'dev'], 30); devfs_mounted = True
        run(['/sbin/devfs', '-m', target / 'dev', 'rule', 'apply', 'hide'], 30)
        for name in ('null', 'zero', 'random', 'urandom'):
            run(['/sbin/devfs', '-m', target / 'dev', 'rule', 'apply', 'path', name, 'unhide'], 30)
        if any((target / 'dev').glob('vtbd*')):
            raise ValueError('builder device namespace exposes backing disks')
        prefix = [str(source / 'pkg-static'), '-c', str(target), '-C', '/.bazel-builder-control/empty.conf',
                  '-R', '/.bazel-builder-control/repos']
        for option in ('REPO_AUTOUPDATE=no', 'PKG_ENABLE_PLUGINS=no', 'RUN_SCRIPTS=yes',
                       'PKG_TRIGGERS_ENABLE=yes', 'SYSLOG=no', 'DEBUG_SCRIPTS=yes'):
            prefix += ['-o', option]
        run(prefix + ['install', '--local-only', '--yes'] +
            ['/.bazel-builder-input/' + row['file'] for row in rows], read_stdout=False)
        for kind in ('stdout', 'stderr'):
            with Path(report['commands'][-1][kind]).open(errors='replace') as stream:
                for line in stream:
                    if re.search(r'\bscript failed\b|Failed to execute lua script', line):
                        raise RuntimeError('package engine reported hook failure despite transaction status')
        actual = run(prefix + ['query', '%n\t%v']).splitlines()
        expected = sorted(row['name'] + '\t' + row['version'] for row in rows)
        if sorted(actual) != expected:
            raise ValueError('installed database differs from complete selected package set')
        run(prefix + ['check', '-s', '-a'], read_stdout=False)
        bash_version = run(['/usr/sbin/chroot', target, args.bash, '-c',
                            'printf "%s\\n" "${BASH_VERSION%%(*}"']).strip()
        bash_owner = next(p for p in inventory['packages'] if args.bash in p['entries'])
        if bash_version != bash_owner['version'].split('_')[0].split(',')[0]:
            raise ValueError('Bash runtime version differs from selected package')
        run(['/usr/sbin/chroot', target, args.java, '-version'])
        java_text = ''.join(Path(report['commands'][-1][kind]).read_text(errors='replace')
                            for kind in ('stdout', 'stderr'))
        java_owner = next(p for p in inventory['packages'] if args.java in p['entries'])
        expected_java = java_owner['version'].split('+')[0].split('_')[0]
        if not re.search(r'openjdk version "' + re.escape(expected_java) + r'"', java_text):
            raise ValueError('selected Java did not identify an OpenJDK runtime')
        for path in ('etc/passwd', 'etc/pwd.db', 'etc/spwd.db', 'var/db/pkg/local.sqlite'):
            if not (target / path).is_file() or (target / path).stat().st_size == 0:
                raise ValueError('required installed database missing: ' + path)
        unchanged(); report['result'] = 'PASS'
    except Exception as error:
        report.update(result='FAIL', error=str(error))
        raise
    finally:
        if devfs_mounted:
            try:
                run(['/sbin/umount', target / 'dev'], 30)
            except Exception as error:
                report.update(result='FAIL', devfs_cleanup_error=str(error))
        if mounted:
            try:
                run(['/sbin/umount', input_mount], 30)
            except Exception as error:
                report.update(result='FAIL', cleanup_error=str(error))
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if report['result'] != 'PASS':
        raise RuntimeError('fixture cleanup failed')


if __name__ == '__main__':
    main()
