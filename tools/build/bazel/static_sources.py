# SPDX-License-Identifier: BSD-2-Clause
"""Emit declared regular-archive source aliases and effective compile flags."""
from pathlib import Path
import shlex
from libmd_environment import digest
from libmd_paths import rewrite_includes


def emit(component, src, objtop, copy, rule, generated_directories):
    records = component.get('static_objects', [])
    if [r['object'] for r in records] != shlex.split(component['metadata']['STATICOBJS']):
        raise ValueError('static object inventory differs from Make')
    labels, headers = [], set()
    for index, record in enumerate(records):
        source = record['source']
        context = record['compile_context']
        if (record['variant'] != 'regular' or context['source'] != source or
                context['target'] != record['object'] or
                context['language'] != ('c' if source.endswith('.c') else 'c++')):
            raise ValueError('static source compile context differs from mapping')
        origin = (src / record['origin']).resolve(strict=True)
        if not origin.is_relative_to(src) or digest(origin) != record['sha256']:
            raise ValueError('static source changed or escaped source tree')
        flags, directories = rewrite_includes(context['static_flags'] + context['flags'],
            src, objtop, generated_directories=generated_directories)
        headers.update(directories)
        headers.add(origin.parent)
        label = component['metadata']['LIB'] + '_static_source_' + str(index)
        copied = copy(origin)
        # Make compiles the resolved source in its original directory. A generated
        # alias has a different dirname, so restore quoted-header lookup without
        # adding that directory to angle-bracket/system header search.
        flags = ['-iquote', str(Path('sources') / origin.relative_to(src).parent)] + flags
        rule('bsd_static_source', name=label, source=copied,
             output='generated/' + component['metadata']['LIB'] + '/static/' + source, copts=flags)
        labels.append(':' + label)
    return labels, headers
