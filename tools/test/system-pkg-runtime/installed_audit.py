# SPDX-License-Identifier: BSD-2-Clause
"""Build a read-only mtree audit from the complete captured image contract."""
import hashlib
import re


def specification(metalog, report):
    """Check every declared object; bind each regular file to its image digest.

    Timestamps are construction policy, not a runtime content/permission check.
    Extra runtime files are outside this baseline audit. No declared object is
    omitted or relaxed, including configuration and generated database files.
    """
    if hashlib.sha256(metalog).hexdigest() != report['metalog_sha256']:
        raise ValueError('METALOG does not match captured construction report')
    hashes = report['payload_sha256']
    seen, regular, directories, lines = set(), set(), 0, []
    kinds = {}
    for line in metalog.decode('utf-8').splitlines():
        fields = line.split()
        if not fields:
            raise ValueError('empty METALOG record')
        name = fields[0]
        path = '/' if name == '.' else name[1:]
        if (name != '.' and (not name.startswith('./') or
                any(part in ('', '.', '..') for part in name[2:].split('/')))):
            raise ValueError('noncanonical METALOG path')
        if path in seen:
            raise ValueError('duplicate METALOG path')
        seen.add(path)
        attrs = {}
        for field in fields[1:]:
            key, separator, value = field.partition('=')
            if not separator or key in attrs:
                raise ValueError('invalid METALOG attributes')
            attrs[key] = value
        required = {'type', 'uid', 'gid', 'mode', 'flags', 'time'}
        kind = attrs.get('type')
        if kind == 'link':
            required.add('link')
        if set(attrs) != required or kind not in ('dir', 'file', 'link'):
            raise ValueError('unsupported METALOG record')
        if not all(re.fullmatch(r'[0-9]+', attrs[key]) for key in ('uid', 'gid')):
            raise ValueError('numeric ownership required')
        if not re.fullmatch(r'0*[0-7]{1,4}', attrs['mode']):
            raise ValueError('octal mode required')
        del attrs['time']
        kinds[path] = kind
        if kind == 'file':
            value = hashes.get(path)
            if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value):
                raise ValueError('every regular file requires an image digest')
            regular.add(path)
            attrs['sha256digest'] = value
        elif kind == 'dir':
            directories += 1
        lines.append(name + ' ' + ' '.join(key+'='+value for key,value in attrs.items()))
    if (set(hashes) != regular or directories != report['directories'] or
            len(seen) - directories != report['files'] or '/' not in seen):
        raise ValueError('complete image record coverage required')
    parents = set()
    for path in seen - {'/'}:
        parent = path.rsplit('/', 1)[0] or '/'
        if kinds.get(parent) != 'dir':
            raise ValueError('every object requires its declared directory parent')
        parents.add(parent)
    # mtree otherwise visits extra children of a declared empty directory and
    # can report access errors for unrelated runtime devices. Check the directory
    # itself, but prune contents only when the baseline declares no children.
    for index, line in enumerate(lines):
        name = line.split()[0]
        path = '/' if name == '.' else name[1:]
        if kinds[path] == 'dir' and path not in parents:
            lines[index] += ' ignore'
    return ('\n'.join(lines)+'\n').encode()
