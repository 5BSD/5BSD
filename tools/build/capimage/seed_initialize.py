#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Initialize an empty state tree in a trusted offline builder.

This primitive does not allocate datasets, authenticate inputs, mount storage or
activate a generation. Existing state is never merged or replaced. The caller
must supply an exclusively owned destination and independently trusted inputs.
"""
import importlib.util
import os
import json
import ctypes as C
from pathlib import Path
import subprocess

spec = importlib.util.spec_from_file_location('generation_image', Path(__file__).with_name('generation_image.py'))
image = importlib.util.module_from_spec(spec); spec.loader.exec_module(image)


def initialize(source, target, expected, tar, work, timeout=600):
    source, target, tar, work = map(Path, (source, target, tar, work))
    for directory in (source, target):
        if directory.is_symlink() or not directory.is_dir() or directory.resolve() == Path('/'):
            raise ValueError('seed directories must be alternate physical directories')
    source, target = source.resolve(strict=True), target.resolve(strict=True)
    if source.is_relative_to(target) or target.is_relative_to(source):
        raise ValueError('seed source and destination must be disjoint')
    if any(target.iterdir()):
        raise ValueError('seed destination contains existing state')
    if (work.exists() or work.is_symlink() or work.resolve().is_relative_to(source) or
            work.resolve().is_relative_to(target)):
        raise ValueError('seed work directory must be new and outside source/destination')
    if tar.is_symlink() or not tar.is_file():
        raise ValueError('explicit regular archive tool required')
    tar = tar.resolve(strict=True)
    if tar.is_relative_to(source) or tar.is_relative_to(target):
        raise ValueError('archive tool must be external to source/destination')
    if image.construction.generation.scan(source) != expected:
        raise ValueError('seed source does not match selected observations')
    tool_hash = image.file_hash(tar)
    identity = (target.stat().st_dev, target.stat().st_ino)
    work.mkdir(mode=0o700); work = work.resolve(strict=True)
    archive = work / 'seed.tar'
    report = dict(format=1, scope='offline-empty-state-initialization', result='RUNNING',
        source_observation_sha256=image.construction.digest(expected),
        archive_tool_sha256=tool_hash, destination=str(target),
        generation_authenticated=False, activation_authorized=False, dataset_identity_verified=False)
    def run(*args):
        result = subprocess.run([str(tar), *map(str, args)],
            env=image.construction.ENVIRONMENT, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout, close_fds=True)
        with (work / 'commands.log').open('a') as log:
            log.write(result.stdout + result.stderr)
        result.check_returncode()
    image.construction.write_record(work / 'construction.json', report)
    try:
        run('--format=pax', '-cpf', archive, '-C', source, '.')
        if image.construction.generation.scan(source) != expected:
            raise ValueError('seed source changed during archive creation')
        if ((target.stat().st_dev, target.stat().st_ino) != identity or
                target.is_symlink() or any(target.iterdir())):
            raise ValueError('seed destination changed before initialization')
        # The archive root '.' already exists (eventually a dataset mountpoint).
        # libarchive defers timestamps only for directories it creates. Exclude
        # that root header, restore children, then apply root metadata last.
        # This also prevents restrictive root flags/mode blocking child creation.
        run('--numeric-owner', '--strip-components', '1', '-xpf', archive, '-C', target)
        # An archive may omit a zero-valued flags field. ZFS sets UF_ARCHIVE
        # on newly created objects, so absence is not equivalent to restoring
        # the selected flags. Apply exact flags, children before their parents.
        restored = set()
        for name in sorted((name for name in expected if name != '/'),
                           key=lambda name: (-name.count('/'), name)):
            path = target / name.lstrip('/')
            info = path.lstat()
            inode = (info.st_dev, info.st_ino)
            if inode in restored:
                continue
            restored.add(inode)
            # Apply metadata once per inode. A redundant chflags through a
            # hardlink can update ZFS ctime and set UF_ARCHIVE again.
            if info.st_flags != expected[name]['flags_set']:
                os.chflags(path, expected[name]['flags_set'], follow_symlinks=False)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != identity:
                raise ValueError('seed destination identity changed during initialization')
            root = expected['/']
            os.fchown(fd, root['uid'], root['gid'])
            os.fchmod(fd, root['mode'])
            stamp = root['mtime'] * 1000000000 + root['mtime_nsec']
            os.utime(fd, ns=(info.st_atime_ns, stamp))
            libc = C.CDLL(None, use_errno=True)
            libc.fchflags.argtypes, libc.fchflags.restype = [C.c_int, C.c_ulong], C.c_int
            if libc.fchflags(fd, root['flags_set']) != 0:
                error = C.get_errno()
                raise OSError(error, os.strerror(error))
        finally:
            os.close(fd)
        actual = image.construction.generation.scan(target)
        if actual != expected:
            differences = {name: dict(expected=expected.get(name), actual=actual.get(name))
                for name in set(expected) | set(actual) if expected.get(name) != actual.get(name)}
            image.construction.write_record(work / 'differences.json', differences)
            raise ValueError('initialized state differs from selected seed observations: ' + json.dumps(differences, sort_keys=True))
        if image.file_hash(tar) != tool_hash or image.construction.generation.scan(source) != expected:
            raise ValueError('seed tool or source changed during initialization')
        report.update(result='PASS', archive_sha256=image.file_hash(archive),
                      initialized_observation_sha256=image.construction.digest(actual))
        image.construction.write_record(work / 'receipt.json', report)
        image.construction.write_record(work / 'construction.json', report)
        return report
    except BaseException as error:
        (work / 'receipt.json').unlink(missing_ok=True)
        report.update(result='FAIL', error=str(error))
        image.construction.write_record(work / 'construction.json', report)
        # Preserve incomplete state and diagnostics. Never delete user data or
        # retry by treating a partially initialized tree as a fresh destination.
        raise
