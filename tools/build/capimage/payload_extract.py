#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Materialize verified package payloads in a private trusted-builder root.

This does not authenticate archives or authorize installation/activation. The
builder and its kernel are trusted; hostile concurrent host mutation is excluded.
"""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess

spec = importlib.util.spec_from_file_location('construction', Path(__file__).with_name('construction.py'))
construction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(construction)
generation = construction.generation


def prepare(root, inventory, initial):
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or root.resolve() == Path('/'):
        raise ValueError('extraction requires an empty alternate root directory')
    root = root.resolve(strict=True)
    if any(root.iterdir()):
        raise ValueError('extraction root must be empty')
    # Validate provenance and metadata with the same schema as reconciliation.
    # Extraction can create unowned directories, but cannot approve replacement
    # payloads before the generators responsible for those replacements run.
    expected = generation.expected_objects(inventory, initial)
    if '/' not in initial['entries']:
        raise ValueError('payload extraction requires explicit root layout metadata')
    packaged = generation.expected_objects(inventory, dict(format=1, entries={}))
    for name, item in initial['entries'].items():
        if item['type'] != 'directory':
            raise ValueError('extraction layout may declare only directories: ' + name)
        if name in packaged or item['replaces']:
            raise ValueError('extraction layout cannot replace package objects: ' + name)
    if expected['/']['type'] != 'directory':
        raise ValueError('root layout must declare a directory')
    for name in expected:
        for parent in Path(name).parents:
            if expected.get(str(parent), {}).get('type') != 'directory':
                raise ValueError('missing declared parent directory: ' + str(parent))
    for name in ('/etc/master.passwd', '/etc/group'):
        if expected.get(name, {}).get('type') != 'file':
            raise ValueError('package-derived account inputs required: ' + name)
    for package in inventory['packages']:
        archive = Path(package['archive'])
        if archive.resolve().is_relative_to(root):
            raise ValueError('archive input must be outside extraction root')
    return root, expected


def planning_objects(inventory, expected):
    """Resolve archive account names without extracting or consulting host NSS."""
    maps = []
    for name, fields in (('/etc/master.passwd', 10), ('/etc/group', 4)):
        wanted = expected[name]
        owners = [p for p in inventory['packages'] if name in p['entries']]
        if len(owners) != 1 or wanted.get('type') != 'file':
            raise ValueError('account payload requires one regular-file owner: ' + name)
        owner = owners[0]
        checked = generation.pkg.inventory_archive(owner['archive'], capture={name: 64 * 1024 * 1024})
        data = checked.pop('captured_payloads')[name]
        if checked['archive_sha256'] != owner['archive_sha256'] or checked['entries'] != owner['entries']:
            raise ValueError('account package changed during planning: ' + name)
        if len(data) != wanted['size'] or hashlib.sha256(data).hexdigest() != wanted['sha256']:
            raise ValueError('account payload differs from planned input: ' + name)
        maps.append(generation.parse_account_data(name, fields, data))
    result = copy.deepcopy(expected)
    for item in result.values():
        for symbolic, numeric, mapping in (('uname', 'uid', maps[0]), ('gname', 'gid', maps[1])):
            if item.get(symbolic):
                if item[symbolic] not in mapping:
                    raise ValueError('unknown generation account: ' + item[symbolic])
                item[numeric] = mapping[item[symbolic]]
    return result


def extract(root, inventory, initial, tar, timeout=300, progress=None):
    root, expected = prepare(root, inventory, initial)
    if os.geteuid() != 0:
        raise PermissionError('payload extraction requires root in a trusted builder')
    parent = root.parent.stat()
    if parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError('extraction root needs a root-owned mode-0700 parent')
    tar = Path(tar).resolve(strict=True)
    if not tar.is_file() or not os.access(tar, os.X_OK):
        raise ValueError('explicit executable tar input required')
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError('invalid extraction timeout')
    hashes = {str(tar): hashlib.sha256(tar.read_bytes()).hexdigest()}
    for package in inventory['packages']:
        hashes[package['archive']] = package['archive_sha256']

    def unchanged():
        for name, digest in hashes.items():
            with Path(name).open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                    raise ValueError('extraction input changed: ' + name)

    if progress: progress('verify-inputs')
    unchanged()
    root.chmod(0o700)
    # Precreate every declared directory; tar must never invent layout policy.
    for name in sorted(expected, key=lambda name: (name.count('/'), name)):
        if name != '/' and expected[name]['type'] == 'directory':
            (root / name.lstrip('/')).mkdir(mode=0o700)
    commands = []
    for index, package in enumerate(inventory['packages']):
        if progress: progress('archive-' + str(index + 1) + '-of-' + str(len(inventory['packages'])))
        argv = [str(tar), '-xpf', package['archive'], '--numeric-owner',
                '--no-acls', '--no-xattrs', '--no-fflags',
                '--exclude=+MANIFEST', '--exclude=+COMPACT_MANIFEST', '-C', str(root)]
        result = subprocess.run(argv, env=construction.ENVIRONMENT,
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            close_fds=True, timeout=timeout)
        commands.append(dict(argv=argv, exit=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode:
            raise ValueError('archive extraction failed: ' + result.stderr)
    unchanged()
    if progress: progress('scan-extracted-tree')
    observed = generation.scan(root)
    if set(observed) != set(expected):
        raise ValueError('extracted paths differ from declared payload and layout')
    if progress: progress('resolve-accounts')
    users, groups = generation.account_maps(root, expected, observed)
    for name, item in expected.items():
        for symbolic, numeric, mapping in (('uname', 'uid', users), ('gname', 'gid', groups)):
            if item.get(symbolic):
                if item[symbolic] not in mapping:
                    raise ValueError('unknown generation account: ' + item[symbolic])
                item[numeric] = mapping[item[symbolic]]
        if item['type'] == 'hardlink':
            # Check the target's metadata before touching a shared inode.
            target = item['target']; seen = {name}
            while expected[target]['type'] == 'hardlink':
                if target in seen:
                    raise ValueError('cyclic hardlink')
                seen.add(target); target = expected[target]['target']
            if expected[target]['type'] != 'file':
                raise ValueError('hardlink target is not a regular file')
    # Names resolve only through the verified candidate account files. Apply
    # flags last so immutable payloads cannot interrupt link/metadata creation.
    for name in sorted(expected, key=lambda name: (-name.count('/'), name)):
        item = expected[name]
        if item['type'] == 'hardlink':
            continue
        target = root / name.lstrip('/')
        os.chown(target, item['uid'], item['gid'], follow_symlinks=False)
        os.chmod(target, item['mode'], follow_symlinks=False)
        if 'mtime' in item and item['type'] != 'directory':
            timestamp = item['mtime'] * 1000000000 + item.get('mtime_nsec', 0)
            os.utime(target, ns=(timestamp, timestamp), follow_symlinks=False)
    for name in sorted(expected, key=lambda name: (-name.count('/'), name)):
        if expected[name]['type'] != 'hardlink':
            os.chflags(root / name.lstrip('/'), expected[name].get('flags_set', 0), follow_symlinks=False)
    unchanged()
    if progress: progress('reconcile-metadata')
    verified = construction.require_match(root, inventory, initial)
    return dict(format=1, scope='trusted-builder-payload-extraction', result='PASS',
        inputs_authenticated=False, generation_authenticated=False,
        inventory_sha256=construction.digest(inventory), initial_generated_sha256=construction.digest(initial),
        files_sha256=hashes, commands=commands, object_count=len(verified),
        filesystem_sha256=construction.digest(verified))
