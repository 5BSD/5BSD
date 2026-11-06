# SPDX-License-Identifier: BSD-2-Clause
"""Resolve inspection dependencies from installation metadata, never host paths."""


def inspection_paths(path, records):
    """Return traversed aliases and the terminal path, rooted at the target /."""
    pending = path.split('/')
    aliases = set()
    # Match the package tool's bounded symlink traversal. A cycle is an error,
    # while a missing target remains a legitimate dangling installation alias.
    for expansion in range(41):
        resolved = []
        for index, component in enumerate(pending):
            if component in ('', '.'):
                continue
            if component == '..':
                if resolved:
                    resolved.pop()
                continue
            candidate = '/' + '/'.join(resolved + [component])
            record = records.get(candidate)
            if record is not None and record['type'] == 'symlink':
                if expansion == 40:
                    raise ValueError('package inspection exceeds 40 symlinks: ' + path)
                aliases.add(candidate)
                link = record['link']
                pending = ([] if link.startswith('/') else resolved) + link.split('/') + pending[index + 1:]
                break
            resolved.append(component)
        else:
            return aliases | {'/' + '/'.join(resolved)}
    raise AssertionError('unreachable symlink traversal')
