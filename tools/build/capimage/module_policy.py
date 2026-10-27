# SPDX-License-Identifier: BSD-2-Clause
"""Derive explicit module-hints actions from package payloads and builder policy.

The caller authenticates packages and policy; compilation grants no authority.
"""
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import stat


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def read_policy(path, pkg):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('module policy must be a regular file')
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('module policy exceeds size limit')
    return json.loads(data, object_pairs_hook=pkg.unique_object, parse_constant=pkg.invalid_constant)


def path(value):
    if (not isinstance(value, str) or not value.startswith('/') or value == '/' or
            len(value.encode()) > 4096 or any(ord(c) < 32 for c in value) or
            any(p in ('', '.', '..') for p in value.split('/')[1:])):
        raise ValueError('invalid module policy path')
    return value


def patterns(value):
    if (not isinstance(value, list) or not 1 <= len(value) <= 64 or
            any(not isinstance(p, str) or not p or len(p.encode()) > 256 or
                '/' in p or any(ord(c) < 32 for c in p) for p in value)):
        raise ValueError('invalid module selection patterns')
    return value


def prepare(inventory, observed, policy):
    if (not isinstance(policy, dict) or set(policy) != {'format', 'program', 'groups'} or
            type(policy['format']) is not int or policy['format'] != 1 or
            not isinstance(policy['groups'], list) or not 1 <= len(policy['groups']) <= 64):
        raise ValueError('invalid module policy fields or format')
    program = path(policy['program'])
    payloads = {}
    for package in inventory['packages']:
        for name, entry in package['entries'].items():
            if entry['type'] != 'directory':
                if name in payloads:
                    raise ValueError('ambiguous module payload owner: ' + name)
                payloads[name] = (package, entry)

    def binding(name):
        package, entry = payloads.get(name, (None, {}))
        actual = observed.get(name, {})
        if (entry.get('type') != 'file' or actual.get('type') != 'file' or
                actual.get('hardlinks') or actual.get('sha256') != entry['sha256']):
            raise ValueError('module input differs from unaliased package payload: ' + name)
        return dict(path=name, package=package['name'], archive_sha256=package['archive_sha256'],
                    sha256=entry['sha256'], mode=entry['mode'])

    executable = binding(program)
    if not executable['mode'] & 0o111:
        raise ValueError('module generator is not executable')
    actions, selections, directories = [], [], set()
    total = 0
    for index, group in enumerate(policy['groups']):
        if (not isinstance(group, dict) or set(group) != {'directory', 'packages', 'patterns', 'required', 'output'} or
                type(group['required']) is not bool):
            raise ValueError('invalid module policy group')
        directory = path(group['directory'])
        if directory in directories:
            raise ValueError('duplicate module directory')
        directories.add(directory)
        package_patterns, file_patterns = patterns(group['packages']), patterns(group['patterns'])
        output = group['output']
        if not isinstance(output, dict) or set(output) != {'name', 'uid', 'gid', 'mode', 'flags_set', 'replace'}:
            raise ValueError('invalid module output fields')
        name = output['name']
        if not isinstance(name, str) or '/' in name or name in ('', '.', '..'):
            raise ValueError('invalid module output name')
        destination = path(directory + '/' + name)
        for key, maximum in [('uid', 2**32-2), ('gid', 2**32-2), ('mode', 0o7777), ('flags_set', 2**64-1)]:
            if type(output[key]) is not int or not 0 <= output[key] <= maximum:
                raise ValueError('invalid module output ' + key)
        if type(output['replace']) is not bool:
            raise ValueError('invalid module replacement intent')
        replacement = None
        if output['replace']:
            replacement = binding(destination)
        elif destination in observed:
            raise ValueError('module output must be absent without explicit replacement')
        chosen = []
        for name, (package, entry) in sorted(payloads.items()):
            if (str(Path(name).parent) == directory and
                    any(fnmatch.fnmatchcase(package['name'], p) for p in package_patterns) and
                    any(fnmatch.fnmatchcase(Path(name).name, p) for p in file_patterns)):
                chosen.append(binding(name))
        if destination == program or any(item['path'] == destination for item in chosen):
            raise ValueError('module output overlaps an input or generator')
        if not chosen and (group['required'] or replacement is not None):
            raise ValueError('required module selection is empty: ' + directory)
        total += len(chosen)
        if total > 1024:
            raise ValueError('too many selected module inputs')
        selections.append(dict(directory=directory, output=destination, inputs=chosen))
        if not chosen:
            continue
        if observed.get(directory, {}).get('type') != 'directory':
            raise ValueError('module directory must be verified')
        argv = [program, '-o', destination, *[item['path'] for item in chosen]]
        if len(argv) > 4096 or sum(len(a.encode()) + 1 for a in argv) > 128 * 1024:
            raise ValueError('module command exceeds construction argument limits')
        actions.append(dict(name='module-hints-' + str(index), argv=argv,
            inputs=[item['path'] for item in chosen], input_payloads={item['path']:item['sha256'] for item in chosen},
            outputs={destination: dict(type='file', replace=output['replace'],
                **{key: output[key] for key in ('uid', 'gid', 'mode', 'flags_set')})},
            executable_payload=executable, source='explicit-module-policy', policy_sha256=digest(policy)))
        if replacement is not None:
            actions[-1]['package_sha256'] = replacement['archive_sha256']
            actions[-1]['replacement_payload'] = replacement
    return dict(policy=policy, policy_sha256=digest(policy), selections=selections,
                selection_sha256=digest(selections), actions=actions, inputs_authenticated=False)
