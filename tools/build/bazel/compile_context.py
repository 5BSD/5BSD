# SPDX-License-Identifier: BSD-2-Clause
"""Query effective Make compiler flags in an explicit automatic-variable context.

The short automatic names '<' and '@' are the bmake command-line bindings for
.IMPSRC and .TARGET. Long-name assignments do not supply that context to -v.
This exports configuration only, without parsing or executing compiler recipes.
"""
import shlex


def capture(environment, component, source, target, language, extra=(), obj=None):
    if language not in ('c', 'c++', 'assembler-with-cpp'):
        raise ValueError('unsupported compile-context language')
    if not source or not target or any(c in source + target for c in '\n\r'):
        raise ValueError('explicit single-line source and target required')
    flag = 'CXXFLAGS' if language == 'c++' else 'CFLAGS'
    static = 'STATIC_CXXFLAGS' if language == 'c++' else 'STATIC_CFLAGS'
    shared = 'SHARED_CXXFLAGS' if language == 'c++' else 'SHARED_CFLAGS'
    keys = ['.IMPSRC', '.TARGET', flag, static, 'DEPEND_CFLAGS', shared, 'PICFLAG', 'PIEFLAG']
    if language == 'assembler-with-cpp':
        keys.append('ACFLAGS')
    nossp = target.endswith('.nossppico')
    if nossp:
        suffix = 'ASFLAGS' if language == 'assembler-with-cpp' else 'CXXFLAGS' if language == 'c++' else 'CFLAGS'
        keys.extend(['_NOSSP_' + suffix, '_NOSSP_SHARED_' + suffix])
    argv = [arg for key in keys for arg in ('-v', key)]
    bindings = [*extra, '<=' + source, '@=' + target]
    raw = environment.query(argv, component=component, extra=bindings, obj=obj)
    rows = raw.splitlines()
    if len(rows) != len(keys) or rows[:2] != [source, target]:
        raise ValueError('Make automatic-variable context did not bind')
    if environment.query(argv, component=component, extra=bindings, obj=obj) != raw:
        raise ValueError('compile context changed during export')
    result = dict(source=source, target=target, language=language,
                flags=shlex.split(rows[2]), static_flags=shlex.split(rows[3]),
                dependency_flags=shlex.split(rows[4]), shared_flags=shlex.split(rows[5]),
                pic_flags=shlex.split(rows[6]), pie_flags=shlex.split(rows[7]))
    if language == 'assembler-with-cpp':
        result['assembly_flags'] = shlex.split(rows[8])
    if nossp:
        result['nossp_flags'] = shlex.split(rows[-2])
        result['nossp_shared_flags'] = shlex.split(rows[-1])
    return result


def compile_flags(context, variant):
    """Match maintained C/C++/preprocessed-assembly suffix-rule flag order; depfiles belong to Bazel."""
    if variant == 'nossp_pic':
        if not context['target'].endswith('.nossppico') or 'nossp_flags' not in context or 'nossp_shared_flags' not in context:
            raise ValueError('NOSSP requires an exported effective Make context')
        return context['pic_flags'] + ['-DPIC'] + context['nossp_shared_flags'] + context['nossp_flags'] + (context['assembly_flags'] if context['language'] == 'assembler-with-cpp' else [])
    if variant == 'regular':
        prefix = [] if context['language'] == 'assembler-with-cpp' else context['static_flags']
    elif variant in ('pic', 'pie'):
        prefix = context['pic_flags' if variant == 'pic' else 'pie_flags']
        prefix = prefix + (['-DPIC'] if variant == 'pic' or context['language'] in ('c', 'assembler-with-cpp') else []) + context['shared_flags']
    else:
        raise ValueError('unsupported compiler variant')
    return prefix + context['flags'] + (context['assembly_flags'] if context['language'] == 'assembler-with-cpp' else [])
