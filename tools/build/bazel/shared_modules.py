# SPDX-License-Identifier: BSD-2-Clause
"""Map configured shared-only modules to ordered PIC compilation inputs."""
import shlex
from pathlib import PurePosixPath


def inventory(component, records, labels, flags):
    metadata = component['metadata']
    if metadata['LIB'] or metadata['PROG']:
        raise ValueError('shared-only module must not declare LIB or PROG')
    name = metadata['SHLIB_NAME']
    for value in (name, metadata['SHLIB_NAME_FULL'], metadata['SONAME']):
        if not value or PurePosixPath(value).name != value or value in ('.', '..'):
            raise ValueError('shared module output and SONAME must be basenames')
    if shlex.split(metadata['_LIBS']) != [name]:
        raise ValueError('shared module output inventory differs')
    objects = shlex.split(metadata['SOBJS'])
    if not objects or len(set(objects)) != len(objects):
        raise ValueError('nonempty unique shared module object inventory required')
    selected, source_flags = {}, {}
    for record, label in zip(records, labels, strict=True):
        contexts = record.get('compile_contexts', {})
        if set(contexts) != {'pic'}:
            raise ValueError('shared-only source requires exactly its PIC context')
        target = contexts['pic']['target']
        if target in selected or label in source_flags:
            raise ValueError('duplicate shared module object or source')
        selected[target] = label
        source_flags[label] = flags[label + '|pic']
    if set(selected) != set(objects):
        raise ValueError('shared module object inventory differs from compilation outputs')
    return [selected[obj] for obj in objects], source_flags
