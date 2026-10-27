# SPDX-License-Identifier: BSD-2-Clause
"""Compile explicit library search inputs for an isolated, trusted builder.

This is not runtime storage authorization or authentication of policy/packages.
"""
import hashlib
from pathlib import PurePosixPath
import struct


def path(value):
    if (not isinstance(value, str) or not value.startswith('/') or value == '/' or
            len(value.encode()) >= 4096 or ':' in value or
            any(ord(c) < 32 for c in value) or
            any(p in ('', '.', '..') for p in value.split('/')[1:])):
        raise ValueError('invalid library policy path')
    return value


def prepare(inventory, observed, policy, pkg, digest):
    if (not isinstance(policy, dict) or set(policy) != {'format', 'program', 'directories', 'output'} or
            type(policy['format']) is not int or policy['format'] != 1):
        raise ValueError('invalid library policy fields or format')
    program, destination = path(policy['program']), path(policy['output'])
    directories = policy['directories']
    if not isinstance(directories, list) or not 1 <= len(directories) <= 1024:
        raise ValueError('library policy requires explicit directories')
    directories = [path(p) for p in directories]
    if len(set(directories)) != len(directories):
        raise ValueError('duplicate library directory')
    declared, owners = set(), []
    for package in inventory['packages']:
        declared.update(pkg.package_directories(package))
        if program in package['entries']:
            owners.append((package, package['entries'][program]))
    if len(owners) != 1:
        raise ValueError('library generator requires one package owner')
    package, entry = owners[0]
    actual = observed.get(program, {})
    if (entry.get('type') != 'file' or not entry.get('mode', 0) & 0o111 or
            actual.get('type') != 'file' or actual.get('hardlinks') or
            actual.get('sha256') != entry.get('sha256')):
        raise ValueError('library generator differs from unaliased package payload')
    if destination in observed:
        raise ValueError('library hints output must be new')
    checked = {}
    for name in [*directories, str(PurePosixPath(destination).parent)]:
        for parent in [PurePosixPath(name), *PurePosixPath(name).parents]:
            key = str(parent)
            value = observed.get(key, {})
            if (key != '/' and key not in declared) or value.get('type') != 'directory':
                raise ValueError('library directory or ancestor is not package-declared: ' + key)
            if value.get('uid') != 0 or value.get('mode', 0) & 0o022:
                raise ValueError('unsafe library directory ownership or mode: ' + key)
            checked[key] = {k: value[k] for k in ('type', 'uid', 'gid', 'mode', 'flags_set')}
    # ELF hints v1 has a 128-byte header and a NUL-terminated ordered search list.
    strings = ':'.join(directories).encode() + b'\0'
    content = struct.pack('<32I', 0x746e6845, 1, 128, len(strings), 0,
                          len(strings) - 1, *([0] * 26)) + strings
    if len(content) > 16 * 1024:
        raise ValueError('library hints exceed the utility format limit')
    action = dict(name='library-hints', argv=[program, '-elf', '-S', '-f', destination, *directories],
        inputs=[], directory_inputs=checked,
        executable_payload=dict(path=program, package=package['name'],
            archive_sha256=package['archive_sha256'], sha256=entry['sha256'], mode=entry['mode']),
        outputs={destination: dict(type='file', uid=0, gid=0, mode=0o444, flags_set=0, replace=False)},
        planned_hashes={destination: hashlib.sha256(content).hexdigest()},
        source='explicit-library-policy', policy_sha256=digest(policy))
    return dict(policy=policy, policy_sha256=digest(policy), actions=[action],
                inputs_authenticated=False, runtime_storage_authorized=False)
