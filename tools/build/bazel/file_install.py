# SPDX-License-Identifier: BSD-2-Clause
"""Export effective bsd.files.mk per-file installation metadata."""
import shlex
from pathlib import PurePosixPath


def export(metadata, query, add, source_identity):
    if query(['DESTDIR'])['DESTDIR']:
        raise ValueError('file policy must be queried without DESTDIR')
    observed = {}
    for group in shlex.split(metadata['FILESGROUPS']):
        values = query([group, group + 'TAG_ARGS'])
        files = shlex.split(values[group])
        if len(files) != len(set(files)):
            raise ValueError('duplicate configured group file')
        entries = {}
        keys = [group + kind + '_' + name for name in files
                for kind in ('OWN', 'GRP', 'MODE', 'NAME', 'PREFIX')]
        selected = query(keys) if keys else {}
        for name in files:
            fields = {kind: selected[group + kind + '_' + name]
                      for kind in ('OWN', 'GRP', 'MODE', 'NAME', 'PREFIX')}
            installed = fields['NAME']
            if (not installed or PurePosixPath(installed).name != installed or
                    installed in ('.', '..') or not fields['PREFIX'].startswith('/')):
                raise ValueError('file group requires absolute destination and installed basename')
            add(fields['PREFIX'].rstrip('/') + '/' + installed, 'file',
                fields['OWN'], fields['GRP'], fields['MODE'], values[group + 'TAG_ARGS'],
                role='file', **source_identity(name))
            entries[name] = fields
        observed[group] = dict(metadata=values, files=entries)
    return observed
