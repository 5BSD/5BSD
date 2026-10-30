# SPDX-License-Identifier: BSD-2-Clause
"""Map exported effective source/variant contexts to native compilation inputs."""
from pathlib import Path
from compile_context import compile_flags
from libmd_paths import rewrite_includes


def emit(records, labels, src, objtop, generated_directories):
    flags, directories = {}, {}
    for record, label in zip(records, labels, strict=True):
        contexts = record.get('compile_contexts')
        if not contexts:
            raise ValueError('library source lacks effective compile contexts: ' + record['name'])
        for variant, context in contexts.items():
            suffix = {'regular': '.o', 'pic': '.pico', 'pie': '.pieo', 'nossp_pic': '.nossppico'}.get(variant)
            if (suffix is None or context['source'] != (str(src / record['path']) if record['resolution']=='source' else record['name']) or
                    context['target'] != str(Path(record['name']).with_suffix(suffix)) or
                    context['language'] != ('assembler-with-cpp' if record['name'].endswith('.S') else 'c' if record['name'].endswith('.c') else 'c++')):
                raise ValueError('source compile context differs from inventory')
            mapped, includes = rewrite_includes(compile_flags(context, variant), src, objtop,
                generated_directories=generated_directories)
            flags[label + '|' + variant] = mapped
            directories.setdefault(label, set()).update(includes)
    return flags, directories
