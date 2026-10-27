# SPDX-License-Identifier: BSD-2-Clause
"""Map configured program objects to native per-translation-unit actions."""
import shlex


def inventory(component, records, labels, flags):
    objects = shlex.split(component['metadata']['OBJS'])
    if not objects or len(objects) != len(set(objects)):
        raise ValueError('nonempty unique program object inventory required')
    selected = {}
    source_flags = {}
    for record, label in zip(records, labels, strict=True):
        contexts = record.get('compile_contexts', {})
        if len(contexts) != 1:
            raise ValueError('program source requires one configured object context: '+record['name'])
        variant, context = next(iter(contexts.items()))
        if variant not in ('regular', 'pie'):
            raise ValueError('unsupported configured program object variant')
        target = context['target']
        if target in selected or label in source_flags:
            raise ValueError('duplicate configured program object or source')
        selected[target] = label
        source_flags[label] = flags[label+'|'+variant]
    if set(selected) != set(objects):
        raise ValueError('program object inventory differs from declared compilation outputs')
    return [selected[name] for name in objects], source_flags


def link_driver(metadata):
    if metadata.get('PROG_CXX'):
        if metadata['PROG_CXX'] != metadata['PROG']:
            raise ValueError('C++ program selector differs from configured program')
        return 'g++', 'CXXFLAGS'
    return 'gcc', 'CFLAGS'
