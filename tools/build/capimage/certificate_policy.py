# SPDX-License-Identifier: BSD-2-Clause
"""Compile explicit certificate policy in a reconciled, private builder root.

The caller authenticates policy and packages before a protected release. This
module supplies neither authentication nor a live-system writer grant.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_POLICY = 1024 * 1024
MAX_PLAN = 2 * 1024 * 1024


def canonical(value):
    if (not isinstance(value, str) or not value.startswith('/') or value == '/' or
            len(value.encode()) > 4096 or any(ord(c) < 32 for c in value) or
            any(p in ('', '.', '..') for p in value.split('/')[1:])):
        raise ValueError('invalid certificate policy path')
    return value


def read_policy(path, pkg):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('certificate policy must be a regular file')
        data = stream.read(MAX_POLICY + 1)
    if len(data) > MAX_POLICY:
        raise ValueError('certificate policy is too large')
    return json.loads(data, object_pairs_hook=pkg.unique_object, parse_constant=pkg.invalid_constant)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prepare(inventory, observed, policy):
    if (not isinstance(policy, dict) or set(policy) !=
            {'format', 'name', 'program', 'selections', 'files', 'overrides', 'outputs'} or
            type(policy['format']) is not int or policy['format'] != 1):
        raise ValueError('invalid certificate policy fields or format')
    if not isinstance(policy['name'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', policy['name']):
        raise ValueError('invalid certificate policy name')
    program = canonical(policy['program'])
    packages = {p['name']: p for p in inventory['packages']}
    payloads = {path: (p, entry) for p in packages.values() for path, entry in p['entries'].items()
                if entry['type'] != 'directory'}
    package, entry = payloads.get(program, (None, {}))
    if entry.get('type') != 'file' or not entry.get('mode', 0) & 0o111:
        raise ValueError('certificate generator must be an executable package payload')
    actual = observed.get(program, {})
    if actual.get('type') != 'file' or actual.get('sha256') != entry['sha256']:
        raise ValueError('certificate generator differs from package payload')
    binding = {'path': program, 'sha256': entry['sha256'], 'mode': entry['mode'],
               'archive_sha256': package['archive_sha256']}
    for key, limit in [('selections', 64), ('files', 1024), ('overrides', 1024)]:
        if not isinstance(policy[key], list) or len(policy[key]) > limit:
            raise ValueError('invalid certificate policy ' + key)
    selected = {}

    def add(path, role):
        canonical(path)
        if role not in ('trusted', 'untrusted') or path in selected:
            raise ValueError('invalid or duplicate certificate selection: ' + path)
        item = observed.get(path, {})
        if item.get('type') != 'file' or item.get('hardlinks'):
            raise ValueError('certificate input must be a verified unaliased regular file: ' + path)
        selected[path] = {'path': path, 'role': role, 'sha256': item['sha256']}

    for rule in policy['selections']:
        if not isinstance(rule, dict) or set(rule) != {'package', 'prefix', 'role'}:
            raise ValueError('invalid certificate package selector')
        if not isinstance(rule['package'], str) or rule['package'] not in packages:
            raise ValueError('certificate selector names an absent package')
        prefix = canonical(rule['prefix'])
        matched = 0
        for path, item in sorted(packages[rule['package']]['entries'].items()):
            if not path.startswith(prefix + '/') or item['type'] == 'directory':
                continue
            if item['type'] != 'file':
                raise ValueError('certificate selector includes a non-regular package payload')
            add(path, rule['role'])
            matched += 1
        if matched == 0:
            raise ValueError('certificate package selector is empty')
    for item in policy['files']:
        if not isinstance(item, dict) or set(item) != {'path', 'role'}:
            raise ValueError('invalid explicit certificate file')
        add(item['path'], item['role'])
    overridden = set()
    for item in policy['overrides']:
        if (not isinstance(item, dict) or set(item) != {'path', 'role'} or
                not isinstance(item['path'], str) or item['path'] not in selected or
                item['path'] in overridden or item['role'] not in ('trusted', 'untrusted')):
            raise ValueError('invalid certificate role override')
        selected[item['path']]['role'] = item['role']
        overridden.add(item['path'])
    if len(selected) > 1024:
        raise ValueError('too many selected certificate files')
    output = policy['outputs']
    if not isinstance(output, dict) or set(output) != {
            'trusted_directory', 'untrusted_directory', 'bundle', 'uid', 'gid', 'mode', 'flags_set'}:
        raise ValueError('invalid certificate output policy')
    for key, maximum in [('uid', 2**32 - 2), ('gid', 2**32 - 2), ('mode', 0o7777), ('flags_set', 2**64 - 1)]:
        if type(output[key]) is not int or not 0 <= output[key] <= maximum:
            raise ValueError('invalid certificate output ' + key)
    for key in ('trusted_directory', 'untrusted_directory', 'bundle'):
        canonical(output[key])
        if any(c.isspace() or c == '\\' for c in output[key]):
            raise ValueError('certificate output path cannot be represented literally in a metalog')
    trusted, untrusted, bundle = (output[k] for k in ('trusted_directory', 'untrusted_directory', 'bundle'))
    if (trusted == untrusted or trusted.startswith(untrusted + '/') or untrusted.startswith(trusted + '/') or
            bundle in (trusted, untrusted) or bundle.startswith((trusted + '/', untrusted + '/')) or
            trusted.startswith(bundle + '/') or untrusted.startswith(bundle + '/')):
        raise ValueError('certificate output locations overlap')
    for directory in (trusted, untrusted, str(Path(bundle).parent)):
        if observed.get(directory, {}).get('type') != 'directory':
            raise ValueError('certificate output parent must be a verified directory: ' + directory)
    if bundle in observed or any(p.startswith((trusted + '/', untrusted + '/')) for p in observed):
        raise ValueError('certificate construction requires empty output locations')
    selection = [selected[p] for p in sorted(selected)]
    argv = [program, '-E', '-C', trusted, '-R', untrusted, '-b', bundle]
    for item in selection:
        argv.extend(['-T' if item['role'] == 'trusted' else '-X', item['path']])
    argv.append('rehash')
    # Leave room for planning options and the executor's command prefix.
    if len(argv) + 5 > 4096 or sum(len(a.encode()) + 1 for a in argv) + 64 > 128 * 1024:
        raise ValueError('certificate command exceeds construction argument limits')
    return {'policy': policy, 'policy_sha256': digest(policy), 'selection': selection,
            'selection_sha256': digest(selection), 'argv': argv, 'executable_payload': binding}


def parse_plan(data, prepared):
    if len(data) > MAX_PLAN:
        raise ValueError('certificate output plan is too large')
    output = prepared['policy']['outputs']
    directories = (output['trusted_directory'], output['untrusted_directory'])
    paths, sizes = {}, {}
    for line in data.decode('utf-8', errors='strict').splitlines():
        fields = line.split(' ')
        if (len(fields) != 6 or not fields[0].startswith('./') or
                fields[1:5] != ['type=file', 'uname=root', 'gname=wheel', 'mode=0444'] or
                not re.fullmatch(r'size=[0-9]{1,19}', fields[5])):
            raise ValueError('invalid certificate output plan record')
        path = canonical(fields[0][1:])
        size = int(fields[5][5:])
        if size > 2**63 - 1 or path in paths:
            raise ValueError('duplicate or oversized certificate output')
        if path != output['bundle']:
            if (str(Path(path).parent) not in directories or
                    not re.fullmatch(r'[0-9a-f]{8}\.(0|[1-9][0-9]{0,9})', Path(path).name)):
                raise ValueError('certificate output escapes declared store locations')
        paths[path] = dict(type='file', replace=False,
                           **{k: output[k] for k in ('uid', 'gid', 'mode', 'flags_set')})
        sizes[path] = size
    if output['bundle'] not in paths or len(paths) > 1024:
        raise ValueError('certificate plan lacks its bundle or has too many outputs')
    return paths, sizes


def compile_recipe(root, inventory, observed, policy, log, timeout, execute, scan):
    prepared = prepare(inventory, observed, policy)
    argv = prepared['argv'][:-1] + ['-n', '-U', '-M', '-', 'rehash']
    execute(root, argv, log, timeout)
    if scan(root) != observed:
        raise ValueError('certificate planning modified the candidate')
    with log.open('rb') as stream:
        plan = stream.read(MAX_PLAN + 1)
    outputs, sizes = parse_plan(plan, prepared)
    for path in outputs:
        if path in observed:
            raise ValueError('certificate output would replace an existing object')
    action = {'name': policy['name'], 'argv': prepared['argv'],
              'inputs': [item['path'] for item in prepared['selection']], 'outputs': outputs,
              'planned_sizes': sizes, 'executable_payload': prepared['executable_payload'],
              'source': 'explicit-certificate-policy', 'policy_sha256': prepared['policy_sha256']}
    record = dict(prepared, plan_sha256=hashlib.sha256(plan).hexdigest(),
                  outputs=outputs, planned_sizes=sizes, inputs_authenticated=False)
    return action, record
