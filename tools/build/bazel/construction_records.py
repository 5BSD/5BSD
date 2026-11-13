# SPDX-License-Identifier: BSD-2-Clause
"""Expand explicitly selected construction metadata, never observed host state."""
import json
from pathlib import Path, PurePosixPath


def destination(value):
    if (not isinstance(value, str) or not value.startswith('/') or value.startswith('//')
            or str(PurePosixPath(value)) != value or '..' in PurePosixPath(value).parts
            or any(c.isspace() or c == '\\' for c in value)):
        raise ValueError('canonical construction destination required')
    return value


def construction_records(records, trees):
    result = []
    paths = set()

    def add(record):
        path = destination(record['destination'])
        if record['type'] != 'file' or record['tags'] != [] or path in paths:
            raise ValueError('construction requires distinct untagged regular files: ' + path)
        if not isinstance(record.get('source'), str) or not record['source']:
            raise ValueError('construction file requires a declared source: ' + path)
        paths.add(path)
        result.append(record)

    for record in records:
        add(record)
    for tree in trees:
        prefix = destination(tree['prefix'])
        if prefix == '/':
            raise ValueError('construction tree requires a bounded prefix')
        metadata = json.loads(Path(tree['metadata']).read_text())
        # bsd_install_tree_archive exposes its installation request, including
        # records; it does not currently emit a separate versioned envelope.
        if not isinstance(metadata, dict) or not isinstance(metadata.get('records'), list):
            raise ValueError('construction tree installation records required')
        for record in metadata['records']:
            path = destination(record['destination'])
            if path != prefix and not path.startswith(prefix + '/'):
                raise ValueError('construction tree record outside declared prefix: ' + path)
            if record['tags'] != []:
                raise ValueError('construction tree must not claim package ownership: ' + path)
            if record['type'] == 'dir':
                # Directory policy is reconciled through the selected installation
                # archive, rather than granting new directories from this declaration.
                continue
            if path == prefix:
                raise ValueError('construction tree prefix must be a directory')
            add(record)
    return result
